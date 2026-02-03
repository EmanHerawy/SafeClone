import { Finding, FindingCategory, PatternResult, PatternScanner, RiskLevel } from '../../shared/types';
import { DANGEROUS_COMMANDS, NPM_LIFECYCLE_SCRIPTS, ENV_ACCESS_PATTERNS, NETWORK_PATTERNS } from '../../shared/constants';

/**
 * NPM package.json structure (partial)
 */
interface PackageJson {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  [key: string]: unknown;
}

/**
 * Suspicious package name patterns
 */
const SUSPICIOUS_PACKAGE_PATTERNS = [
  // Typosquatting patterns
  /^(lodash|moment|express|react|vue|angular|webpack|babel|eslint|jest|mocha|chai|axios|request|fs-extra|glob|rimraf|mkdirp|debug|commander|chalk|inquirer|yargs|minimist|dotenv|uuid|async|bluebird|underscore|ramda|jquery|bootstrap|tailwind)/,
  // Look for single character differences from popular packages
];

/**
 * Known malicious package name patterns
 */
const MALICIOUS_NAME_PATTERNS = [
  // Scope typosquatting
  /@[a-z]+\/(node-|nodejs-|npm-)/i,
  // Suspicious prefixes/suffixes
  /-backdoor$/i,
  /-malware$/i,
  /-stealer$/i,
  /^evil-/i,
];

/**
 * Scanner for NPM package.json files
 * Detects malicious lifecycle scripts and suspicious dependencies
 */
export class NPMScanner implements PatternScanner {
  /**
   * Check if this scanner applies to the given file path
   */
  appliesTo(filePath: string): boolean {
    return filePath.endsWith('package.json');
  }

  /**
   * Scan package.json content for malicious patterns
   */
  scan(content: string, filePath: string): PatternResult {
    const findings: Finding[] = [];

    // Try to parse JSON
    let pkg: PackageJson;
    try {
      pkg = JSON.parse(content);
    } catch (error) {
      findings.push({
        riskLevel: RiskLevel.YELLOW,
        filePath,
        description: 'Invalid JSON in package.json - could indicate obfuscation or corruption',
        category: FindingCategory.PARSE_ERROR,
      });
      return { findings };
    }

    // Scan lifecycle scripts
    if (pkg.scripts) {
      this.scanScripts(pkg.scripts, filePath, findings);
    }

    // Scan dependencies for suspicious names
    if (pkg.dependencies) {
      this.scanDependencies(pkg.dependencies, 'dependencies', filePath, findings);
    }

    if (pkg.devDependencies) {
      this.scanDependencies(pkg.devDependencies, 'devDependencies', filePath, findings);
    }

    return { findings };
  }

  /**
   * Scan npm scripts for dangerous commands
   */
  private scanScripts(scripts: Record<string, string>, filePath: string, findings: Finding[]): void {
    for (const [scriptName, scriptContent] of Object.entries(scripts)) {
      if (!scriptContent || typeof scriptContent !== 'string') continue;

      const isLifecycleScript = NPM_LIFECYCLE_SCRIPTS.includes(scriptName as typeof NPM_LIFECYCLE_SCRIPTS[number]);

      // Check for dangerous commands in lifecycle scripts
      if (isLifecycleScript) {
        const dangerousCmd = this.findDangerousCommand(scriptContent);
        if (dangerousCmd) {
          findings.push({
            riskLevel: RiskLevel.RED,
            filePath,
            description: `Lifecycle script "${scriptName}" contains dangerous command: ${dangerousCmd}`,
            category: FindingCategory.NPM,
            matchedContent: scriptContent.substring(0, 150),
          });
        }

        // Check for network calls in lifecycle scripts
        if (this.hasNetworkCall(scriptContent)) {
          findings.push({
            riskLevel: RiskLevel.RED,
            filePath,
            description: `Lifecycle script "${scriptName}" makes network requests`,
            category: FindingCategory.NPM,
            matchedContent: scriptContent.substring(0, 150),
          });
        }

        // Check for environment variable access
        if (this.hasEnvAccess(scriptContent)) {
          findings.push({
            riskLevel: RiskLevel.YELLOW,
            filePath,
            description: `Lifecycle script "${scriptName}" accesses environment variables`,
            category: FindingCategory.NPM,
            matchedContent: scriptContent.substring(0, 150),
          });
        }

        // Check for base64 decoding (obfuscation indicator)
        if (this.hasBase64Operations(scriptContent)) {
          findings.push({
            riskLevel: RiskLevel.YELLOW,
            filePath,
            description: `Lifecycle script "${scriptName}" performs base64 operations (possible obfuscation)`,
            category: FindingCategory.NPM,
            matchedContent: scriptContent.substring(0, 150),
          });
        }
      }

      // Check any script for suspicious patterns (not just lifecycle)
      if (this.hasEvalOrExec(scriptContent)) {
        const riskLevel = isLifecycleScript ? RiskLevel.RED : RiskLevel.YELLOW;
        findings.push({
          riskLevel,
          filePath,
          description: `Script "${scriptName}" uses eval or exec`,
          category: FindingCategory.NPM,
          matchedContent: scriptContent.substring(0, 150),
        });
      }
    }
  }

  /**
   * Scan dependencies for suspicious package names
   */
  private scanDependencies(
    deps: Record<string, string>,
    depType: string,
    filePath: string,
    findings: Finding[]
  ): void {
    for (const [pkgName, version] of Object.entries(deps)) {
      // Check for known malicious patterns
      if (this.isSuspiciousPackageName(pkgName)) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          description: `Suspicious package name in ${depType}: "${pkgName}" may be typosquatting`,
          category: FindingCategory.NPM,
          matchedContent: `${pkgName}: ${version}`,
        });
      }

      // Check for git URLs with suspicious domains
      if (this.isSuspiciousGitUrl(version)) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          description: `Package "${pkgName}" uses suspicious git URL`,
          category: FindingCategory.NPM,
          matchedContent: `${pkgName}: ${version}`,
        });
      }

      // Check for file: protocol (could be used for path traversal)
      if (version.startsWith('file:')) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          description: `Package "${pkgName}" uses local file reference`,
          category: FindingCategory.NPM,
          matchedContent: `${pkgName}: ${version}`,
        });
      }
    }
  }

  /**
   * Find dangerous commands in script content
   */
  private findDangerousCommand(script: string): string | null {
    const lowerScript = script.toLowerCase();

    for (const dangerous of DANGEROUS_COMMANDS) {
      const pattern = new RegExp(`\\b${dangerous.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
      if (pattern.test(lowerScript)) {
        return dangerous;
      }
    }

    return null;
  }

  /**
   * Check for network calls in script
   */
  private hasNetworkCall(script: string): boolean {
    return NETWORK_PATTERNS.some(pattern => pattern.test(script));
  }

  /**
   * Check for environment variable access
   */
  private hasEnvAccess(script: string): boolean {
    return ENV_ACCESS_PATTERNS.some(pattern => pattern.test(script));
  }

  /**
   * Check for base64 operations
   */
  private hasBase64Operations(script: string): boolean {
    const base64Patterns = [
      /atob\s*\(/i,
      /btoa\s*\(/i,
      /Buffer\.from\s*\([^)]+,\s*['"]base64['"]\)/i,
      /base64\s*-d/i,
      /--decode/i,
    ];
    return base64Patterns.some(pattern => pattern.test(script));
  }

  /**
   * Check for eval or exec usage
   */
  private hasEvalOrExec(script: string): boolean {
    const evalPatterns = [
      /\beval\s*\(/,
      /\bexec\s*\(/,
      /\bnew\s+Function\s*\(/,
      /child_process/,
    ];
    return evalPatterns.some(pattern => pattern.test(script));
  }

  /**
   * Check if package name looks suspicious
   */
  private isSuspiciousPackageName(name: string): boolean {
    // Check against known malicious patterns
    if (MALICIOUS_NAME_PATTERNS.some(pattern => pattern.test(name))) {
      return true;
    }

    // Check for homoglyph-like characters in package names
    const nonAscii = /[^\x00-\x7F]/;
    if (nonAscii.test(name)) {
      return true;
    }

    return false;
  }

  /**
   * Check for suspicious git URLs
   */
  private isSuspiciousGitUrl(version: string): boolean {
    if (!version.includes('git') && !version.includes('://')) {
      return false;
    }

    const suspiciousPatterns = [
      /git\+https?:\/\/[^\/]+\.[^\/]{2,6}\/.*\.git/i, // Non-GitHub/GitLab git URLs
      /github\.com\/[^\/]+\/[^\/]+#[a-f0-9]{40}/i, // Pinned to specific commit (could be good or suspicious)
    ];

    // Whitelist known providers
    const trustedProviders = [
      'github.com',
      'gitlab.com',
      'bitbucket.org',
    ];

    const urlMatch = version.match(/(?:git\+)?https?:\/\/([^\/]+)/);
    if (urlMatch && !trustedProviders.some(provider => urlMatch[1].includes(provider))) {
      return true;
    }

    return false;
  }
}

/**
 * Scan NPM package.json content
 */
export function scanNPMPackage(content: string, filePath: string = 'package.json'): PatternResult {
  const scanner = new NPMScanner();
  return scanner.scan(content, filePath);
}
