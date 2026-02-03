import { Finding, FindingCategory, PatternResult, PatternScanner, RiskLevel } from '../../shared/types';

/**
 * Scanner for Rust Cargo.toml and .cargo/config files
 * Detects malicious build scripts and configuration overrides
 */
export class RustScanner implements PatternScanner {
  /**
   * Check if this scanner applies to the given file path
   */
  appliesTo(filePath: string): boolean {
    return (
      filePath.endsWith('Cargo.toml') ||
      filePath.endsWith('.cargo/config.toml') ||
      filePath.endsWith('.cargo/config')
    );
  }

  /**
   * Scan Rust configuration file content for malicious patterns
   */
  scan(content: string, filePath: string): PatternResult {
    const findings: Finding[] = [];

    if (filePath.endsWith('Cargo.toml')) {
      this.scanCargoToml(content, filePath, findings);
    } else if (filePath.includes('.cargo/config')) {
      this.scanCargoConfig(content, filePath, findings);
    }

    return { findings };
  }

  /**
   * Scan Cargo.toml for suspicious patterns
   */
  private scanCargoToml(content: string, filePath: string, findings: Finding[]): void {
    const lines = content.split('\n');
    let inBuildDependencies = false;
    let inBuildSection = false;

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const trimmedLine = line.trim();

      // Track sections
      if (trimmedLine.startsWith('[')) {
        inBuildDependencies = trimmedLine.includes('[build-dependencies]');
        inBuildSection = trimmedLine.includes('[package]') === false && trimmedLine.includes('build');
      }

      // Check for [build-dependencies] section
      if (inBuildDependencies && trimmedLine && !trimmedLine.startsWith('[') && !trimmedLine.startsWith('#')) {
        // Only flag once per section
        if (lines[index - 1]?.trim() === '[build-dependencies]') {
          findings.push({
            riskLevel: RiskLevel.YELLOW,
            filePath,
            lineNumber: lineNum,
            description: 'Build dependencies detected - build.rs will run during compilation',
            category: FindingCategory.RUST,
            matchedContent: '[build-dependencies]',
          });
        }
      }

      // Check for build script specification
      if (trimmedLine.startsWith('build') && trimmedLine.includes('=')) {
        const buildScript = this.extractValue(trimmedLine);
        if (buildScript && buildScript !== 'build.rs') {
          findings.push({
            riskLevel: RiskLevel.YELLOW,
            filePath,
            lineNumber: lineNum,
            description: `Custom build script: ${buildScript}`,
            category: FindingCategory.RUST,
            matchedContent: trimmedLine,
          });
        }
      }

      // Check for suspicious package names in dependencies
      if (this.isSuspiciousDependency(trimmedLine)) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'Suspicious dependency pattern detected',
          category: FindingCategory.RUST,
          matchedContent: trimmedLine.substring(0, 100),
        });
      }

      // Check for git dependencies with suspicious URLs
      if (this.hasSuspiciousGitDependency(trimmedLine)) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'Git dependency from non-standard source',
          category: FindingCategory.RUST,
          matchedContent: trimmedLine.substring(0, 100),
        });
      }
    });

    // Check for proc-macro crates (can run arbitrary code at compile time)
    if (content.includes('proc-macro = true')) {
      findings.push({
        riskLevel: RiskLevel.YELLOW,
        filePath,
        description: 'Procedural macro crate - executes code at compile time',
        category: FindingCategory.RUST,
        matchedContent: 'proc-macro = true',
      });
    }
  }

  /**
   * Scan .cargo/config for dangerous overrides
   */
  private scanCargoConfig(content: string, filePath: string, findings: Finding[]): void {
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const trimmedLine = line.trim();

      // Check for rustc-wrapper override (RED - can replace compiler)
      if (trimmedLine.includes('rustc-wrapper') || trimmedLine.includes('rustc =')) {
        findings.push({
          riskLevel: RiskLevel.RED,
          filePath,
          lineNumber: lineNum,
          description: 'Rust compiler override detected - can execute arbitrary code',
          category: FindingCategory.RUST,
          matchedContent: trimmedLine,
        });
      }

      // Check for custom linker (YELLOW)
      if (trimmedLine.includes('linker') && trimmedLine.includes('=')) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'Custom linker specified',
          category: FindingCategory.RUST,
          matchedContent: trimmedLine,
        });
      }

      // Check for custom runner (YELLOW)
      if (trimmedLine.includes('runner') && trimmedLine.includes('=')) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'Custom runner specified - may execute arbitrary commands',
          category: FindingCategory.RUST,
          matchedContent: trimmedLine,
        });
      }

      // Check for RUSTFLAGS that could be malicious
      if (trimmedLine.includes('rustflags') || trimmedLine.includes('RUSTFLAGS')) {
        if (this.hasDangerousRustflags(trimmedLine)) {
          findings.push({
            riskLevel: RiskLevel.YELLOW,
            filePath,
            lineNumber: lineNum,
            description: 'Potentially dangerous RUSTFLAGS detected',
            category: FindingCategory.RUST,
            matchedContent: trimmedLine,
          });
        }
      }

      // Check for source replacement (supply chain risk)
      if (trimmedLine.includes('[source.') && !trimmedLine.includes('[source.crates-io]')) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'Custom registry source detected - potential supply chain risk',
          category: FindingCategory.RUST,
          matchedContent: trimmedLine,
        });
      }
    });

    // Check for [target] sections with dangerous configurations
    if (content.includes('[target.') && (content.includes('rustc-wrapper') || content.includes('linker'))) {
      findings.push({
        riskLevel: RiskLevel.YELLOW,
        filePath,
        description: 'Target-specific build configuration detected',
        category: FindingCategory.RUST,
      });
    }
  }

  /**
   * Extract value from TOML assignment
   */
  private extractValue(line: string): string | null {
    const match = line.match(/=\s*["']?([^"'\s]+)["']?/);
    return match ? match[1] : null;
  }

  /**
   * Check for suspicious dependency patterns
   */
  private isSuspiciousDependency(line: string): boolean {
    // Check for path dependencies that might be traversal attempts
    if (line.includes('path = "') && line.includes('..')) {
      return true;
    }
    return false;
  }

  /**
   * Check for suspicious git dependencies
   */
  private hasSuspiciousGitDependency(line: string): boolean {
    if (!line.includes('git = "')) return false;

    // Whitelist common git hosts
    const trustedHosts = ['github.com', 'gitlab.com', 'bitbucket.org', 'rust-lang.github.io'];
    const gitUrl = line.match(/git\s*=\s*"([^"]+)"/);

    if (gitUrl) {
      const url = gitUrl[1];
      return !trustedHosts.some(host => url.includes(host));
    }

    return false;
  }

  /**
   * Check for dangerous RUSTFLAGS
   */
  private hasDangerousRustflags(line: string): boolean {
    const dangerousFlags = [
      '-C link-arg',
      '-C linker=',
      'codegen-units',
      '-Z',
    ];
    return dangerousFlags.some(flag => line.includes(flag));
  }
}

/**
 * Scan Rust configuration file content
 */
export function scanRust(content: string, filePath: string = 'Cargo.toml'): PatternResult {
  const scanner = new RustScanner();
  return scanner.scan(content, filePath);
}
