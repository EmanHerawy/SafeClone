import { Finding, PatternResult, FileContent, RepositoryInfo, ScanResult, RiskLevel, FindingCategory } from '../shared/types';
import { scanVSCodeTasks } from './patterns/vscode';
import { scanNPMPackage } from './patterns/npm';
import { scanPython } from './patterns/python';
import { scanRust } from './patterns/rust';
import { scanGitHubActions } from './patterns/github';
import { scanForHighEntropy } from './entropy';
import { scanForHomoglyphs, needsHomoglyphScan } from './homoglyphDetector';
import { scanForSecondaryScripts, needsDeepInspection } from './recursiveGuard';
import { getScannerType } from '../utils/filePathMatcher';
import { createScanResult, aggregateFindings } from './riskClassifier';

/**
 * Heuristics engine configuration
 */
export interface HeuristicsConfig {
  enableEntropyScan: boolean;
  enableHomoglyphScan: boolean;
  enableSecondaryScriptScan: boolean;
}

const DEFAULT_CONFIG: HeuristicsConfig = {
  enableEntropyScan: true,
  enableHomoglyphScan: true,
  enableSecondaryScriptScan: true,
};

/**
 * Scan a single file with the appropriate scanner
 */
export function scanFile(
  file: FileContent,
  config: Partial<HeuristicsConfig> = {}
): PatternResult {
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };

  if (!file.exists || !file.content) {
    return { findings: [] };
  }

  const findings: Finding[] = [];
  const scannerType = getScannerType(file.path);

  // Run pattern-specific scanner
  switch (scannerType) {
    case 'vscode': {
      const result = scanVSCodeTasks(file.content, file.path);
      findings.push(...result.findings);
      break;
    }
    case 'npm': {
      const result = scanNPMPackage(file.content, file.path);
      findings.push(...result.findings);
      break;
    }
    case 'python': {
      const result = scanPython(file.content, file.path);
      findings.push(...result.findings);
      break;
    }
    case 'rust': {
      const result = scanRust(file.content, file.path);
      findings.push(...result.findings);
      break;
    }
    case 'github': {
      const result = scanGitHubActions(file.content, file.path);
      findings.push(...result.findings);
      break;
    }
  }

  // Run additional scans if enabled
  if (mergedConfig.enableHomoglyphScan && needsHomoglyphScan(file.content)) {
    const homoglyphResult = scanForHomoglyphs(file.content, file.path);
    findings.push(...homoglyphResult.findings);
  }

  if (mergedConfig.enableEntropyScan) {
    const entropyResult = scanForHighEntropy(file.content, file.path);
    findings.push(...entropyResult.findings);
  }

  if (mergedConfig.enableSecondaryScriptScan && needsDeepInspection(file.content)) {
    const secondaryResult = scanForSecondaryScripts(file.content, file.path);
    findings.push(...secondaryResult.findings);
  }

  return { findings };
}

/**
 * Scan multiple files and aggregate results
 */
export function scanFiles(
  files: FileContent[],
  config: Partial<HeuristicsConfig> = {}
): PatternResult {
  const allFindings: Finding[][] = [];

  for (const file of files) {
    const result = scanFile(file, config);
    allFindings.push(result.findings);
  }

  return {
    findings: aggregateFindings(allFindings),
  };
}

/**
 * Full repository scan
 */
export function scanRepository(
  files: FileContent[],
  repository: RepositoryInfo,
  config: Partial<HeuristicsConfig> = {}
): ScanResult {
  const scannedFiles: string[] = [];
  const skippedFiles: string[] = [];
  const allFindings: Finding[][] = [];

  for (const file of files) {
    if (file.exists && file.content) {
      scannedFiles.push(file.path);
      const result = scanFile(file, config);
      allFindings.push(result.findings);
    } else {
      skippedFiles.push(file.path);
    }
  }

  const findings = aggregateFindings(allFindings);

  // If we couldn't scan any files but had files to scan, this is a problem
  // This can happen due to: rate limiting, files not found at expected paths, or network issues
  if (scannedFiles.length === 0 && skippedFiles.length > 0) {
    findings.push({
      riskLevel: RiskLevel.YELLOW,
      filePath: repository.url,
      description: `Unable to fetch files for scanning. This may be due to GitHub rate limiting, or the files don't exist at the expected paths.`,
      category: FindingCategory.FETCH_ERROR,
      matchedContent: `${skippedFiles.length} file(s): ${skippedFiles.slice(0, 3).join(', ')}`,
    });
  } else if (skippedFiles.length > 0 && scannedFiles.length > 0) {
    // Some files were skipped - add a warning
    findings.push({
      riskLevel: RiskLevel.YELLOW,
      filePath: repository.url,
      description: `${skippedFiles.length} file(s) could not be fetched - partial scan only`,
      category: FindingCategory.FETCH_ERROR,
      matchedContent: skippedFiles.slice(0, 3).join(', '),
    });
  }

  return createScanResult(
    findings,
    scannedFiles,
    skippedFiles,
    repository
  );
}

// Re-export scanners for direct use
export { scanVSCodeTasks } from './patterns/vscode';
export { scanNPMPackage } from './patterns/npm';
export { scanPython } from './patterns/python';
export { scanRust } from './patterns/rust';
export { scanGitHubActions } from './patterns/github';
export { scanForHighEntropy, calculateEntropy } from './entropy';
export { scanForHomoglyphs, detectHomoglyphs, detectInvisibleCharacters } from './homoglyphDetector';
export { scanForSecondaryScripts } from './recursiveGuard';
export * from './riskClassifier';
