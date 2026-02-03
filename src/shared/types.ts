/**
 * Risk severity levels for detected issues
 */
export enum RiskLevel {
  /** Immediate RCE or data exfiltration detected */
  RED = 'RED',
  /** Suspicious patterns, obfuscation, or sensitive lifecycle hooks */
  YELLOW = 'YELLOW',
  /** No common attack vectors found */
  GREEN = 'GREEN',
}

/**
 * Individual finding from a heuristic scan
 */
export interface Finding {
  /** Risk level of this finding */
  riskLevel: RiskLevel;
  /** File path where the issue was detected */
  filePath: string;
  /** Human-readable description of the finding */
  description: string;
  /** Line number if applicable */
  lineNumber?: number;
  /** The matched pattern or content */
  matchedContent?: string;
  /** Category of the finding */
  category: FindingCategory;
}

/**
 * Categories of findings
 */
export enum FindingCategory {
  VSCODE = 'vscode',
  NPM = 'npm',
  PYTHON = 'python',
  RUST = 'rust',
  GITHUB_ACTIONS = 'github_actions',
  ENTROPY = 'entropy',
  HOMOGLYPH = 'homoglyph',
  PARSE_ERROR = 'parse_error',
  FETCH_ERROR = 'fetch_error',
}

/**
 * Result of scanning a repository
 */
export interface ScanResult {
  /** Overall risk level (highest of all findings) */
  overallRisk: RiskLevel;
  /** Individual findings */
  findings: Finding[];
  /** Files that were scanned */
  scannedFiles: string[];
  /** Files that were skipped (not found) */
  skippedFiles: string[];
  /** Timestamp of the scan */
  timestamp: number;
  /** Repository info */
  repository: RepositoryInfo;
}

/**
 * GitHub repository information
 */
export interface RepositoryInfo {
  owner: string;
  repo: string;
  branch?: string;
  url: string;
}

/**
 * File content fetched from GitHub
 */
export interface FileContent {
  path: string;
  content: string;
  exists: boolean;
}

/**
 * Configuration stored in Chrome storage
 */
export interface ExtensionConfig {
  /** Enable/disable specific heuristics */
  enabledHeuristics: {
    vscode: boolean;
    npm: boolean;
    python: boolean;
    rust: boolean;
    githubActions: boolean;
    entropy: boolean;
    homoglyph: boolean;
  };
  /** Custom entropy thresholds */
  entropyThresholds: {
    warning: number;
    critical: number;
  };
  /** Show notifications on scan completion */
  showNotifications: boolean;
}

/**
 * Default extension configuration
 */
export const DEFAULT_CONFIG: ExtensionConfig = {
  enabledHeuristics: {
    vscode: true,
    npm: true,
    python: true,
    rust: true,
    githubActions: true,
    entropy: true,
    homoglyph: true,
  },
  entropyThresholds: {
    warning: 5.5,
    critical: 6.5,
  },
  showNotifications: true,
};

/**
 * Pattern detection result from individual scanners
 */
export interface PatternResult {
  findings: Finding[];
}

/**
 * Scanner interface for pattern detectors
 */
export interface PatternScanner {
  /** Scan file content and return findings */
  scan(content: string, filePath: string): PatternResult;
  /** Check if this scanner applies to the given file */
  appliesTo(filePath: string): boolean;
}
