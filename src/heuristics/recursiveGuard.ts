import { Finding, FindingCategory, PatternResult, RiskLevel } from '../shared/types';

/**
 * Patterns that indicate secondary script loading/execution
 */
const SECONDARY_SCRIPT_PATTERNS = {
  /** Shell command execution */
  shell: [
    /curl\s+.*\|\s*(bash|sh|zsh)/gi,
    /wget\s+.*-O\s*-\s*\|\s*(bash|sh)/gi,
    /\$\(curl\s+[^)]+\)/gi,
    /`curl\s+[^`]+`/gi,
    /source\s+<\(curl/gi,
    /eval\s+"\$\(curl/gi,
  ],

  /** PowerShell execution */
  powershell: [
    /Invoke-Expression\s*\(\s*\(?\s*New-Object/gi,
    /IEX\s*\(\s*\(?\s*New-Object/gi,
    /\[System\.Net\.WebClient\].*DownloadString/gi,
    /Invoke-WebRequest.*\|\s*Invoke-Expression/gi,
    /iwr.*\|\s*iex/gi,
  ],

  /** Node.js/JavaScript execution */
  node: [
    /eval\s*\(\s*require\s*\(/gi,
    /new\s+Function\s*\([^)]*require/gi,
    /child_process.*exec.*\$\{/gi,
    /require\s*\(\s*['"]child_process['"]\s*\)/gi,
  ],

  /** Python execution */
  python: [
    /exec\s*\(\s*urllib/gi,
    /exec\s*\(\s*requests\.get/gi,
    /eval\s*\(\s*base64\.b64decode/gi,
    /__import__\s*\(\s*['"]urllib/gi,
  ],

  /** Dynamic code loading */
  dynamic: [
    /import\s*\(\s*['"`][^'"`]*\$\{/gi, // Dynamic import with interpolation
    /require\s*\(\s*[^'"]/gi, // Dynamic require (non-literal)
    /\bimportlib\.import_module\s*\(/gi,
  ],
};

/**
 * Extract potential URLs from content
 */
export function extractUrls(content: string): string[] {
  const urlPattern = /https?:\/\/[^\s"'`<>)\]]+/gi;
  const matches = content.match(urlPattern) || [];
  return [...new Set(matches)]; // Dedupe
}

/**
 * Extract potential script file references
 */
export function extractScriptReferences(content: string): string[] {
  const patterns = [
    /['"]([^'"]+\.(sh|bash|ps1|py|rb|pl|js))['"]/gi,
    /source\s+['"]?([^\s'"]+\.sh)['"]?/gi,
    /\.\s+['"]?([^\s'"]+\.sh)['"]?/gi,
    /python\s+['"]?([^\s'"]+\.py)['"]?/gi,
    /node\s+['"]?([^\s'"]+\.js)['"]?/gi,
  ];

  const references: string[] = [];

  for (const pattern of patterns) {
    let match;
    const patternCopy = new RegExp(pattern.source, pattern.flags);
    while ((match = patternCopy.exec(content)) !== null) {
      if (match[1]) {
        references.push(match[1]);
      }
    }
  }

  return [...new Set(references)];
}

/**
 * Scan for patterns that load and execute secondary scripts
 */
export function scanForSecondaryScripts(content: string, filePath: string): PatternResult {
  const findings: Finding[] = [];

  // Check each pattern category
  for (const [category, patterns] of Object.entries(SECONDARY_SCRIPT_PATTERNS)) {
    for (const pattern of patterns) {
      const matches = content.match(pattern);
      if (matches) {
        for (const match of matches) {
          findings.push({
            riskLevel: RiskLevel.RED,
            filePath,
            description: `Secondary script execution pattern (${category}): downloads and executes remote code`,
            category: FindingCategory.VSCODE, // Using VSCODE as general category for now
            matchedContent: match.substring(0, 100),
          });
        }
      }
    }
  }

  // Extract URLs that might be fetching malicious scripts
  const urls = extractUrls(content);
  const suspiciousUrls = urls.filter(url => {
    const lowerUrl = url.toLowerCase();
    return (
      lowerUrl.includes('.sh') ||
      lowerUrl.includes('.ps1') ||
      lowerUrl.includes('.py') ||
      lowerUrl.includes('.rb') ||
      lowerUrl.includes('raw.') ||
      lowerUrl.includes('pastebin') ||
      lowerUrl.includes('paste.') ||
      lowerUrl.includes('hastebin') ||
      lowerUrl.includes('gist.')
    );
  });

  if (suspiciousUrls.length > 0 && findings.length === 0) {
    // Only add URL warning if we didn't already find execution patterns
    findings.push({
      riskLevel: RiskLevel.YELLOW,
      filePath,
      description: `References to potentially executable remote content`,
      category: FindingCategory.VSCODE,
      matchedContent: suspiciousUrls.slice(0, 3).join(', '),
    });
  }

  // Limit findings
  if (findings.length > 5) {
    const limited = findings.slice(0, 5);
    limited.push({
      riskLevel: RiskLevel.YELLOW,
      filePath,
      description: `${findings.length - 5} additional secondary script patterns detected`,
      category: FindingCategory.VSCODE,
    });
    return { findings: limited };
  }

  return { findings };
}

/**
 * Check if content contains patterns that warrant deeper inspection
 */
export function needsDeepInspection(content: string): boolean {
  // Quick heuristics for deeper inspection
  const quickPatterns = [
    /curl.*\|/i,
    /wget.*-O.*-/i,
    /Invoke-Expression/i,
    /IEX\s*\(/i,
    /eval\s*\(/i,
    /exec\s*\(/i,
    /child_process/i,
    /__import__/i,
  ];

  return quickPatterns.some(p => p.test(content));
}
