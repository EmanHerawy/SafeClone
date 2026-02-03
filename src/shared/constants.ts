/**
 * Critical file patterns to scan in repositories
 */
export const CRITICAL_FILES = {
  VSCODE: {
    TASKS: '.vscode/tasks.json',
    SETTINGS: '.vscode/settings.json',
    LAUNCH: '.vscode/launch.json',
    EXTENSIONS: '.vscode/extensions.json',
  },
  NPM: {
    PACKAGE: 'package.json',
    PACKAGE_LOCK: 'package-lock.json',
    NPM_RC: '.npmrc',
  },
  PYTHON: {
    SETUP: 'setup.py',
    PYPROJECT: 'pyproject.toml',
    REQUIREMENTS: 'requirements.txt',
  },
  RUST: {
    CARGO: 'Cargo.toml',
    CARGO_CONFIG: '.cargo/config.toml',
    CARGO_CONFIG_ALT: '.cargo/config',
  },
  GITHUB: {
    WORKFLOWS_DIR: '.github/workflows/',
  },
} as const;

/**
 * Folder patterns that trigger specific scans
 */
export const SCAN_TRIGGER_FOLDERS = {
  VSCODE: '.vscode/',
  CARGO_CONFIG: '.cargo/',
  GITHUB_WORKFLOWS: '.github/workflows/',
} as const;

/**
 * Dangerous shell commands that indicate potential RCE
 */
export const DANGEROUS_COMMANDS = [
  'curl',
  'wget',
  'bash',
  'sh',
  'powershell',
  'pwsh',
  'cmd',
  'eval',
  'exec',
  'nc',
  'netcat',
  'ncat',
  '/dev/tcp',
  'python -c',
  'python3 -c',
  'node -e',
  'ruby -e',
  'perl -e',
] as const;

/**
 * Network-related patterns that indicate data exfiltration
 */
export const NETWORK_PATTERNS = [
  /https?:\/\/[^\s"']+/i,
  /fetch\s*\(/i,
  /axios\./i,
  /request\s*\(/i,
  /http\.get/i,
  /http\.post/i,
  /XMLHttpRequest/i,
] as const;

/**
 * Environment variable access patterns
 */
export const ENV_ACCESS_PATTERNS = [
  /process\.env/,
  /\$\{?[A-Z_]+\}?/,
  /\$SECRET/i,
  /\$TOKEN/i,
  /\$API_KEY/i,
  /\$PASSWORD/i,
  /os\.environ/,
  /os\.getenv/,
] as const;

/**
 * Entropy thresholds for detecting obfuscation
 */
export const ENTROPY_THRESHOLDS = {
  /** Normal text/code - no concern */
  NORMAL: 3.5,
  /** Elevated - possible base64 or compression */
  WARNING: 5.5,
  /** High - likely encrypted or heavily obfuscated */
  CRITICAL: 6.5,
} as const;

/**
 * Zero-width and invisible characters (potential obfuscation)
 */
export const INVISIBLE_CHARS = [
  '\u200B', // Zero-width space
  '\u200C', // Zero-width non-joiner
  '\u200D', // Zero-width joiner
  '\uFEFF', // Zero-width no-break space (BOM)
  '\u00AD', // Soft hyphen
  '\u2060', // Word joiner
  '\u180E', // Mongolian vowel separator
] as const;

/**
 * Common homoglyph mappings (lookalike characters)
 */
export const HOMOGLYPHS: Record<string, string[]> = {
  'a': ['а', 'ɑ', 'α'], // Cyrillic а, Latin alpha, Greek alpha
  'c': ['с', 'ϲ'], // Cyrillic с, Greek lunate sigma
  'e': ['е', 'ε'], // Cyrillic е, Greek epsilon
  'o': ['о', 'ο', '0'], // Cyrillic о, Greek omicron, zero
  'p': ['р', 'ρ'], // Cyrillic р, Greek rho
  'x': ['х', 'χ'], // Cyrillic х, Greek chi
  'y': ['у', 'γ'], // Cyrillic у, Greek gamma
  'B': ['В', 'Β'], // Cyrillic В, Greek Beta
  'H': ['Н', 'Η'], // Cyrillic Н, Greek Eta
  'K': ['К', 'Κ'], // Cyrillic К, Greek Kappa
  'M': ['М', 'Μ'], // Cyrillic М, Greek Mu
  'T': ['Т', 'Τ'], // Cyrillic Т, Greek Tau
  'i': ['і', 'ι'], // Cyrillic і, Greek iota
  'j': ['ј'], // Cyrillic ј
  's': ['ѕ'], // Cyrillic ѕ
};

/**
 * Bidirectional override characters (text direction attacks)
 */
export const BIDI_CHARS = [
  '\u202A', // Left-to-right embedding
  '\u202B', // Right-to-left embedding
  '\u202C', // Pop directional formatting
  '\u202D', // Left-to-right override
  '\u202E', // Right-to-left override
  '\u2066', // Left-to-right isolate
  '\u2067', // Right-to-left isolate
  '\u2068', // First strong isolate
  '\u2069', // Pop directional isolate
] as const;

/**
 * NPM lifecycle scripts that can be abused
 */
export const NPM_LIFECYCLE_SCRIPTS = [
  'preinstall',
  'install',
  'postinstall',
  'preuninstall',
  'uninstall',
  'postuninstall',
  'prepublish',
  'preprepare',
  'prepare',
  'postprepare',
] as const;

/**
 * Python dangerous functions
 */
export const PYTHON_DANGEROUS_FUNCTIONS = [
  'os.system',
  'os.popen',
  'subprocess.call',
  'subprocess.run',
  'subprocess.Popen',
  'exec(',
  'eval(',
  '__import__',
  'compile(',
] as const;

/**
 * GitHub Actions dangerous patterns
 */
export const GITHUB_ACTIONS_PATTERNS = {
  /** Events that can be exploited */
  DANGEROUS_EVENTS: ['pull_request_target', 'workflow_run'],
  /** Contexts that can be injected */
  INJECTABLE_CONTEXTS: [
    'github.event.issue.title',
    'github.event.issue.body',
    'github.event.pull_request.title',
    'github.event.pull_request.body',
    'github.event.comment.body',
    'github.event.review.body',
    'github.event.review_comment.body',
    'github.head_ref',
  ],
} as const;

/**
 * GitHub raw content URL base
 */
export const GITHUB_RAW_BASE = 'https://raw.githubusercontent.com';

/**
 * GitHub API base URL
 */
export const GITHUB_API_BASE = 'https://api.github.com';
