import { Finding, RiskLevel, ScanResult, RepositoryInfo } from '../shared/types';

/**
 * Determine overall risk level from a list of findings
 * Takes the highest severity found
 */
export function determineOverallRisk(findings: Finding[]): RiskLevel {
  if (findings.length === 0) {
    return RiskLevel.GREEN;
  }

  // Check for RED findings first
  if (findings.some(f => f.riskLevel === RiskLevel.RED)) {
    return RiskLevel.RED;
  }

  // Check for YELLOW findings
  if (findings.some(f => f.riskLevel === RiskLevel.YELLOW)) {
    return RiskLevel.YELLOW;
  }

  return RiskLevel.GREEN;
}

/**
 * Aggregate findings from multiple scans
 */
export function aggregateFindings(
  findingsArrays: Finding[][]
): Finding[] {
  const allFindings: Finding[] = [];

  for (const findings of findingsArrays) {
    allFindings.push(...findings);
  }

  // Deduplicate similar findings
  return deduplicateFindings(allFindings);
}

/**
 * Remove duplicate or very similar findings
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];

  for (const finding of findings) {
    // Create a key based on risk, file, and description
    const key = `${finding.riskLevel}:${finding.filePath}:${finding.description}`;

    if (!seen.has(key)) {
      seen.add(key);
      unique.push(finding);
    }
  }

  return unique;
}

/**
 * Sort findings by severity (RED first, then YELLOW)
 */
export function sortFindingsBySeverity(findings: Finding[]): Finding[] {
  const severityOrder: Record<RiskLevel, number> = {
    [RiskLevel.RED]: 0,
    [RiskLevel.YELLOW]: 1,
    [RiskLevel.GREEN]: 2,
  };

  return [...findings].sort((a, b) => {
    return severityOrder[a.riskLevel] - severityOrder[b.riskLevel];
  });
}

/**
 * Create a scan result from findings
 */
export function createScanResult(
  findings: Finding[],
  scannedFiles: string[],
  skippedFiles: string[],
  repository: RepositoryInfo
): ScanResult {
  return {
    overallRisk: determineOverallRisk(findings),
    findings: sortFindingsBySeverity(findings),
    scannedFiles,
    skippedFiles,
    timestamp: Date.now(),
    repository,
  };
}

/**
 * Get a summary of findings by category
 */
export function getFindingsSummary(findings: Finding[]): Record<string, number> {
  const summary: Record<string, number> = {};

  for (const finding of findings) {
    const category = finding.category;
    summary[category] = (summary[category] || 0) + 1;
  }

  return summary;
}

/**
 * Get risk level description for display
 */
export function getRiskDescription(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case RiskLevel.RED:
      return 'Dangerous - Immediate RCE or data exfiltration detected';
    case RiskLevel.YELLOW:
      return 'Potential Risk - Suspicious patterns detected';
    case RiskLevel.GREEN:
      return 'Safe - No common attack vectors found';
    default:
      return 'Unknown risk level';
  }
}

/**
 * Get risk level color for UI
 */
export function getRiskColor(riskLevel: RiskLevel): string {
  switch (riskLevel) {
    case RiskLevel.RED:
      return '#dc3545'; // Red
    case RiskLevel.YELLOW:
      return '#ffc107'; // Yellow
    case RiskLevel.GREEN:
      return '#28a745'; // Green
    default:
      return '#6c757d'; // Gray
  }
}

/**
 * Format findings for display
 */
export function formatFindingsForDisplay(findings: Finding[]): string[] {
  return findings.map(finding => {
    const prefix = finding.riskLevel === RiskLevel.RED ? '🔴' : '🟡';
    const location = finding.lineNumber
      ? `${finding.filePath}:${finding.lineNumber}`
      : finding.filePath;
    return `${prefix} ${location}: ${finding.description}`;
  });
}
