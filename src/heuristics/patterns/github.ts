import { Finding, FindingCategory, PatternResult, PatternScanner, RiskLevel } from '../../shared/types';
import { GITHUB_ACTIONS_PATTERNS } from '../../shared/constants';

/**
 * Scanner for GitHub Actions workflow files
 * Detects pwn-request patterns, command injection, and secrets exposure
 */
export class GitHubActionsScanner implements PatternScanner {
  /**
   * Check if this scanner applies to the given file path
   */
  appliesTo(filePath: string): boolean {
    return (
      filePath.includes('.github/workflows/') &&
      (filePath.endsWith('.yml') || filePath.endsWith('.yaml'))
    );
  }

  /**
   * Scan GitHub Actions workflow content for malicious patterns
   */
  scan(content: string, filePath: string): PatternResult {
    const findings: Finding[] = [];

    const lines = content.split('\n');

    // Track workflow state
    let hasPullRequestTarget = false;
    let hasWorkflowRun = false;
    let hasCheckout = false;
    let checkoutRef = '';

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const trimmedLine = line.trim();

      // Check for dangerous event triggers
      if (trimmedLine.includes('pull_request_target')) {
        hasPullRequestTarget = true;
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'pull_request_target event detected - review for pwn-request vulnerability',
          category: FindingCategory.GITHUB_ACTIONS,
          matchedContent: trimmedLine,
        });
      }

      if (trimmedLine.includes('workflow_run')) {
        hasWorkflowRun = true;
      }

      // Check for checkout action
      if (trimmedLine.includes('actions/checkout')) {
        hasCheckout = true;
        // Look ahead for ref parameter
        for (let i = index + 1; i < Math.min(index + 10, lines.length); i++) {
          const nextLine = lines[i].trim();
          if (nextLine.startsWith('ref:')) {
            checkoutRef = nextLine;
            break;
          }
          if (nextLine.startsWith('-') || nextLine.startsWith('uses:')) break;
        }
      }

      // Check for command injection via injectable contexts
      for (const context of GITHUB_ACTIONS_PATTERNS.INJECTABLE_CONTEXTS) {
        if (trimmedLine.includes(context)) {
          // Check if it's in a run command (shell execution)
          const isInRun = this.isInRunBlock(lines, index);
          if (isInRun) {
            findings.push({
              riskLevel: RiskLevel.RED,
              filePath,
              lineNumber: lineNum,
              description: `Potential command injection via ${context}`,
              category: FindingCategory.GITHUB_ACTIONS,
              matchedContent: trimmedLine.substring(0, 100),
            });
          }
        }
      }

      // Check for secrets in echo/print statements
      if (this.hasSecretsExposure(trimmedLine)) {
        findings.push({
          riskLevel: RiskLevel.RED,
          filePath,
          lineNumber: lineNum,
          description: 'Potential secrets exposure in output',
          category: FindingCategory.GITHUB_ACTIONS,
          matchedContent: trimmedLine.substring(0, 100),
        });
      }

      // Check for unpinned action versions
      if (trimmedLine.includes('uses:') && this.hasUnpinnedAction(trimmedLine)) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'Unpinned action version - consider pinning to a specific SHA',
          category: FindingCategory.GITHUB_ACTIONS,
          matchedContent: trimmedLine,
        });
      }

      // Check for dangerous shell patterns
      if (this.hasDangerousShellPattern(trimmedLine)) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'Dangerous shell pattern detected',
          category: FindingCategory.GITHUB_ACTIONS,
          matchedContent: trimmedLine.substring(0, 100),
        });
      }

      // Check for curl piped to shell
      if (trimmedLine.includes('curl') && (trimmedLine.includes('| bash') || trimmedLine.includes('| sh'))) {
        findings.push({
          riskLevel: RiskLevel.RED,
          filePath,
          lineNumber: lineNum,
          description: 'curl piped to shell - potential code execution from remote source',
          category: FindingCategory.GITHUB_ACTIONS,
          matchedContent: trimmedLine.substring(0, 100),
        });
      }
    });

    // Check for pwn-request pattern (pull_request_target + checkout of PR)
    if (hasPullRequestTarget && hasCheckout) {
      if (checkoutRef.includes('pull_request') || checkoutRef.includes('head.ref') || checkoutRef.includes('head.sha')) {
        findings.push({
          riskLevel: RiskLevel.RED,
          filePath,
          description: 'Pwn-request vulnerability: pull_request_target with PR checkout allows arbitrary code execution',
          category: FindingCategory.GITHUB_ACTIONS,
          matchedContent: 'pull_request_target + checkout PR ref',
        });
      }
    }

    // Check for workflow_run with untrusted input
    if (hasWorkflowRun && content.includes('github.event.workflow_run')) {
      findings.push({
        riskLevel: RiskLevel.YELLOW,
        filePath,
        description: 'workflow_run event with workflow_run context - review for privilege escalation',
        category: FindingCategory.GITHUB_ACTIONS,
      });
    }

    return { findings };
  }

  /**
   * Check if the current line is within a run block
   */
  private isInRunBlock(lines: string[], currentIndex: number): boolean {
    // Look backwards to find if we're in a run: block
    for (let i = currentIndex; i >= Math.max(0, currentIndex - 20); i--) {
      const line = lines[i].trim();
      // Check for various run block patterns
      if (line.startsWith('run:') || line === 'run: |' || line.startsWith('- run:')) {
        return true;
      }
      // If we hit another step-level keyword (not in a run block), we're not in a run block
      if (line.startsWith('- uses:') || line.startsWith('uses:') || line.startsWith('- name:') || line.startsWith('steps:')) {
        return false;
      }
    }
    return false;
  }

  /**
   * Check for secrets exposure in output
   */
  private hasSecretsExposure(line: string): boolean {
    const secretsPattern = /\$\{\{\s*secrets\./;
    const outputPatterns = [
      /echo\s+.*\$\{\{\s*secrets\./,
      /printf.*\$\{\{\s*secrets\./,
      /cat.*\$\{\{\s*secrets\./,
      />>?\s*\$GITHUB_OUTPUT.*\$\{\{\s*secrets\./,
    ];
    return outputPatterns.some(p => p.test(line));
  }

  /**
   * Check for unpinned action versions
   */
  private hasUnpinnedAction(line: string): boolean {
    // Extract the action reference
    const match = line.match(/uses:\s*([^\s]+)/);
    if (!match) return false;

    const actionRef = match[1];

    // Check if it's pinned to a SHA (40 hex chars)
    if (/@[a-f0-9]{40}$/.test(actionRef)) {
      return false; // Pinned to SHA - good
    }

    // Check if using @main or @master (bad)
    if (/@(main|master)$/.test(actionRef)) {
      return true;
    }

    // Check if using a version tag (acceptable but not ideal)
    if (/@v?\d+(\.\d+)*$/.test(actionRef)) {
      return false; // Version tag - acceptable
    }

    // No version or SHA specified
    if (!actionRef.includes('@')) {
      return true;
    }

    return false;
  }

  /**
   * Check for dangerous shell patterns
   */
  private hasDangerousShellPattern(line: string): boolean {
    const dangerousPatterns = [
      /eval\s+/,
      /\$\(.*\$\{\{/,
      /`.*\$\{\{/,
    ];
    return dangerousPatterns.some(p => p.test(line));
  }
}

/**
 * Scan GitHub Actions workflow content
 */
export function scanGitHubActions(content: string, filePath: string = '.github/workflows/ci.yml'): PatternResult {
  const scanner = new GitHubActionsScanner();
  return scanner.scan(content, filePath);
}
