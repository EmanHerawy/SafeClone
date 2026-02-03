import { Finding, FindingCategory, PatternResult, RiskLevel } from '../shared/types';
import { ENTROPY_THRESHOLDS } from '../shared/constants';

/**
 * Calculate Shannon entropy of a string
 * Entropy measures the randomness/unpredictability of data
 *
 * @param data - The string to calculate entropy for
 * @returns Entropy value (typically 0-8 for byte data)
 */
export function calculateEntropy(data: string): number {
  if (!data || data.length === 0) {
    return 0;
  }

  // Count frequency of each character
  const frequencies: Map<string, number> = new Map();
  for (const char of data) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  // Calculate entropy using Shannon's formula
  // H = -Σ p(x) * log2(p(x))
  let entropy = 0;
  const length = data.length;

  for (const count of frequencies.values()) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy;
}

/**
 * Classify entropy level
 */
export function classifyEntropy(entropy: number): 'normal' | 'elevated' | 'high' | 'critical' {
  if (entropy >= ENTROPY_THRESHOLDS.CRITICAL) {
    return 'critical';
  } else if (entropy >= ENTROPY_THRESHOLDS.WARNING) {
    return 'high';
  } else if (entropy >= ENTROPY_THRESHOLDS.NORMAL) {
    return 'elevated';
  }
  return 'normal';
}

/**
 * Check if a string looks like base64
 */
export function isLikelyBase64(data: string): boolean {
  // Base64 pattern: alphanumeric + / + = padding
  const base64Pattern = /^[A-Za-z0-9+/]+=*$/;

  // Remove whitespace for check
  const cleaned = data.replace(/\s/g, '');

  // Must be at least 20 chars and match pattern
  if (cleaned.length < 20) {
    return false;
  }

  // Check if it matches base64 pattern
  if (!base64Pattern.test(cleaned)) {
    return false;
  }

  // Check if length is appropriate (base64 is typically multiple of 4)
  // Allow some flexibility for partial matches
  return cleaned.length % 4 === 0 || cleaned.length % 4 <= 2;
}

/**
 * Check if a string looks like hex encoded
 */
export function isLikelyHex(data: string): boolean {
  const hexPattern = /^[A-Fa-f0-9]+$/;
  const cleaned = data.replace(/\s/g, '');

  // Must be at least 32 chars (16 bytes) and even length
  return cleaned.length >= 32 && cleaned.length % 2 === 0 && hexPattern.test(cleaned);
}

/**
 * Scan content for high entropy sections that might indicate obfuscation
 */
export function scanForHighEntropy(
  content: string,
  filePath: string,
  windowSize: number = 100,
  stepSize: number = 50
): PatternResult {
  const findings: Finding[] = [];

  // Skip very small files
  if (content.length < windowSize) {
    const entropy = calculateEntropy(content);
    const level = classifyEntropy(entropy);

    if (level === 'critical' || level === 'high') {
      findings.push(createEntropyFinding(entropy, level, filePath, content));
    }
    return { findings };
  }

  // Track high entropy regions to avoid duplicate findings
  const highEntropyRegions: Set<number> = new Set();

  // Sliding window analysis
  for (let i = 0; i < content.length - windowSize; i += stepSize) {
    const window = content.slice(i, i + windowSize);
    const entropy = calculateEntropy(window);
    const level = classifyEntropy(entropy);

    // Skip if we've already found high entropy in this region
    const regionKey = Math.floor(i / (windowSize * 2));
    if (highEntropyRegions.has(regionKey)) {
      continue;
    }

    if (level === 'critical') {
      highEntropyRegions.add(regionKey);
      findings.push({
        riskLevel: RiskLevel.RED,
        filePath,
        description: `Critical entropy (${entropy.toFixed(2)}) detected - likely encrypted or heavily obfuscated`,
        category: FindingCategory.ENTROPY,
        matchedContent: window.substring(0, 50) + '...',
      });
    } else if (level === 'high') {
      // Check if it's likely base64 or hex (less suspicious)
      if (isLikelyBase64(window)) {
        highEntropyRegions.add(regionKey);
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          description: `High entropy base64 data (${entropy.toFixed(2)}) - review for hidden content`,
          category: FindingCategory.ENTROPY,
          matchedContent: window.substring(0, 50) + '...',
        });
      } else if (!isLikelyHex(window)) {
        highEntropyRegions.add(regionKey);
        findings.push({
          riskLevel: RiskLevel.YELLOW,
          filePath,
          description: `High entropy (${entropy.toFixed(2)}) detected - possible obfuscation`,
          category: FindingCategory.ENTROPY,
          matchedContent: window.substring(0, 50) + '...',
        });
      }
    }
  }

  // Limit findings to avoid overwhelming output
  if (findings.length > 5) {
    const criticalFindings = findings.filter(f => f.riskLevel === RiskLevel.RED);
    const yellowFindings = findings.filter(f => f.riskLevel === RiskLevel.YELLOW);

    const limitedFindings = [
      ...criticalFindings.slice(0, 3),
      ...yellowFindings.slice(0, 2),
    ];

    if (findings.length > limitedFindings.length) {
      limitedFindings.push({
        riskLevel: RiskLevel.YELLOW,
        filePath,
        description: `${findings.length - limitedFindings.length} additional high entropy regions detected`,
        category: FindingCategory.ENTROPY,
      });
    }

    return { findings: limitedFindings };
  }

  return { findings };
}

/**
 * Create an entropy finding
 */
function createEntropyFinding(
  entropy: number,
  level: 'high' | 'critical',
  filePath: string,
  sample: string
): Finding {
  if (level === 'critical') {
    return {
      riskLevel: RiskLevel.RED,
      filePath,
      description: `Critical entropy (${entropy.toFixed(2)}) - likely encrypted or heavily obfuscated`,
      category: FindingCategory.ENTROPY,
      matchedContent: sample.substring(0, 50),
    };
  }

  return {
    riskLevel: RiskLevel.YELLOW,
    filePath,
    description: `High entropy (${entropy.toFixed(2)}) detected - possible obfuscation`,
    category: FindingCategory.ENTROPY,
    matchedContent: sample.substring(0, 50),
  };
}
