import { Finding, FindingCategory, PatternResult, PatternScanner, RiskLevel } from '../../shared/types';
import { PYTHON_DANGEROUS_FUNCTIONS } from '../../shared/constants';

/**
 * Scanner for Python setup.py and pyproject.toml files
 * Detects malicious build hooks and dangerous function calls
 */
export class PythonScanner implements PatternScanner {
  /**
   * Check if this scanner applies to the given file path
   */
  appliesTo(filePath: string): boolean {
    return (
      filePath.endsWith('setup.py') ||
      filePath.endsWith('pyproject.toml') ||
      filePath.endsWith('setup.cfg')
    );
  }

  /**
   * Scan Python file content for malicious patterns
   */
  scan(content: string, filePath: string): PatternResult {
    const findings: Finding[] = [];

    if (filePath.endsWith('setup.py')) {
      this.scanSetupPy(content, filePath, findings);
    } else if (filePath.endsWith('pyproject.toml')) {
      this.scanPyprojectToml(content, filePath, findings);
    }

    return { findings };
  }

  /**
   * Scan setup.py for dangerous patterns
   */
  private scanSetupPy(content: string, filePath: string, findings: Finding[]): void {
    const lines = content.split('\n');

    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const trimmedLine = line.trim();

      // Check for dangerous function calls
      for (const func of PYTHON_DANGEROUS_FUNCTIONS) {
        if (this.containsFunction(trimmedLine, func)) {
          const riskLevel = this.getDangerousFunctionRisk(func);
          findings.push({
            riskLevel,
            filePath,
            lineNumber: lineNum,
            description: `Dangerous function call: ${func}`,
            category: FindingCategory.PYTHON,
            matchedContent: trimmedLine.substring(0, 100),
          });
        }
      }

      // Check for base64 decoding (obfuscation)
      if (this.hasBase64Operations(trimmedLine)) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'Base64 decoding detected (possible obfuscation)',
          category: FindingCategory.PYTHON,
          matchedContent: trimmedLine.substring(0, 100),
        });
      }

      // Check for network operations
      if (this.hasNetworkOperations(trimmedLine)) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          lineNumber: lineNum,
          description: 'Network operation detected in setup.py',
          category: FindingCategory.PYTHON,
          matchedContent: trimmedLine.substring(0, 100),
        });
      }
    });

    // Check for cmdclass override (custom install command)
    if (this.hasCmdclassOverride(content)) {
      findings.push({
        riskLevel: RiskLevel.YELLOW,
        filePath,
        description: 'Custom cmdclass detected - may execute arbitrary code during installation',
        category: FindingCategory.PYTHON,
        matchedContent: 'cmdclass override',
      });
    }

    // Check for data_files pointing to sensitive locations
    if (this.hasSensitiveDataFiles(content)) {
      findings.push({
        riskLevel: RiskLevel.RED,
        filePath,
        description: 'data_files target sensitive system locations',
        category: FindingCategory.PYTHON,
        matchedContent: 'data_files to sensitive path',
      });
    }
  }

  /**
   * Scan pyproject.toml for dangerous patterns
   */
  private scanPyprojectToml(content: string, filePath: string, findings: Finding[]): void {
    const lines = content.split('\n');

    // Check for build system with custom scripts
    if (content.includes('[tool.poetry.scripts]') || content.includes('[project.scripts]')) {
      // Check if scripts contain suspicious commands
      const scriptsSection = this.extractSection(content, 'scripts');
      if (scriptsSection && this.hasSuspiciousScript(scriptsSection)) {
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          description: 'Suspicious entry point scripts detected',
          category: FindingCategory.PYTHON,
        });
      }
    }

    // Check for build backend with custom hooks
    if (content.includes('[tool.hatch.build.hooks]') || content.includes('[tool.setuptools.cmdclass]')) {
      findings.push({
        riskLevel: RiskLevel.YELLOW,
        filePath,
        description: 'Custom build hooks detected - may execute arbitrary code during installation',
        category: FindingCategory.PYTHON,
      });
    }

    // Check for inline scripts in build configuration
    lines.forEach((line, index) => {
      if (line.includes('os.system') || line.includes('subprocess') || line.includes('exec(')) {
        findings.push({
          riskLevel: RiskLevel.RED,
          filePath,
          lineNumber: index + 1,
          description: 'Dangerous function call in pyproject.toml',
          category: FindingCategory.PYTHON,
          matchedContent: line.trim().substring(0, 100),
        });
      }
    });
  }

  /**
   * Check if line contains a specific function call
   */
  private containsFunction(line: string, func: string): boolean {
    // Handle different function call patterns
    const patterns = [
      new RegExp(`\\b${func.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`, 'i'),
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Get risk level for dangerous function
   */
  private getDangerousFunctionRisk(func: string): RiskLevel {
    const highRisk = ['os.system', 'os.popen', 'subprocess.call', 'subprocess.run', 'subprocess.Popen', 'exec(', 'eval('];
    return highRisk.some(f => func.includes(f)) ? RiskLevel.RED : RiskLevel.YELLOW;
  }

  /**
   * Check for base64 operations
   */
  private hasBase64Operations(line: string): boolean {
    const patterns = [
      /base64\.b64decode/i,
      /base64\.decodebytes/i,
      /codecs\.decode.*base64/i,
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for network operations
   */
  private hasNetworkOperations(line: string): boolean {
    const patterns = [
      /urllib\.request/i,
      /requests\.(get|post|put|delete)/i,
      /httplib/i,
      /socket\./i,
      /urlopen/i,
    ];
    return patterns.some(p => p.test(line));
  }

  /**
   * Check for cmdclass override
   */
  private hasCmdclassOverride(content: string): boolean {
    return /cmdclass\s*=\s*\{/.test(content) || /cmdclass\s*=\s*dict/.test(content);
  }

  /**
   * Check for sensitive data_files paths
   */
  private hasSensitiveDataFiles(content: string): boolean {
    const sensitivePaths = [
      /\/etc\//,
      /\/usr\/bin/,
      /\/usr\/local\/bin/,
      /~\/\./,
      /\$HOME\//,
      /\.ssh/,
      /\.bashrc/,
      /\.profile/,
      /\.zshrc/,
    ];

    const dataFilesMatch = content.match(/data_files\s*=\s*\[([\s\S]*?)\]/);
    if (!dataFilesMatch) return false;

    return sensitivePaths.some(p => p.test(dataFilesMatch[1]));
  }

  /**
   * Extract a section from TOML content
   */
  private extractSection(content: string, sectionName: string): string | null {
    const regex = new RegExp(`\\[.*${sectionName}.*\\]([\\s\\S]*?)(?=\\[|$)`, 'i');
    const match = content.match(regex);
    return match ? match[1] : null;
  }

  /**
   * Check if script section has suspicious commands
   */
  private hasSuspiciousScript(scriptsContent: string): boolean {
    const suspicious = [
      /curl/i,
      /wget/i,
      /bash\s+-c/i,
      /sh\s+-c/i,
      /eval/i,
      /exec/i,
    ];
    return suspicious.some(p => p.test(scriptsContent));
  }
}

/**
 * Scan Python file content
 */
export function scanPython(content: string, filePath: string = 'setup.py'): PatternResult {
  const scanner = new PythonScanner();
  return scanner.scan(content, filePath);
}
