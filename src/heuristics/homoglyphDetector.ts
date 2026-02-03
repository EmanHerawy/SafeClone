import { Finding, FindingCategory, PatternResult, RiskLevel } from '../shared/types';
import { INVISIBLE_CHARS, HOMOGLYPHS, BIDI_CHARS } from '../shared/constants';

/**
 * Result of homoglyph/hidden character detection
 */
export interface HiddenCharacterResult {
  type: 'zero-width' | 'homoglyph' | 'bidi';
  position: number;
  character: string;
  codePoint: string;
  context?: string;
}

/**
 * Detect zero-width and invisible characters
 */
export function detectInvisibleCharacters(content: string): HiddenCharacterResult[] {
  const results: HiddenCharacterResult[] = [];

  for (let i = 0; i < content.length; i++) {
    const char = content[i];

    // Check for zero-width characters
    if (INVISIBLE_CHARS.includes(char as typeof INVISIBLE_CHARS[number])) {
      results.push({
        type: 'zero-width',
        position: i,
        character: char,
        codePoint: `U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`,
        context: getContext(content, i),
      });
    }

    // Check for bidi override characters
    if (BIDI_CHARS.includes(char as typeof BIDI_CHARS[number])) {
      results.push({
        type: 'bidi',
        position: i,
        character: char,
        codePoint: `U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`,
        context: getContext(content, i),
      });
    }
  }

  return results;
}

/**
 * Detect homoglyph characters (lookalikes from other scripts)
 */
export function detectHomoglyphs(content: string): HiddenCharacterResult[] {
  const results: HiddenCharacterResult[] = [];

  for (let i = 0; i < content.length; i++) {
    const char = content[i];

    // Check if this character is a homoglyph
    for (const [latin, lookalikes] of Object.entries(HOMOGLYPHS)) {
      if (lookalikes.includes(char)) {
        results.push({
          type: 'homoglyph',
          position: i,
          character: char,
          codePoint: `U+${char.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`,
          context: `'${char}' looks like '${latin}' at position ${i}`,
        });
      }
    }
  }

  return results;
}

/**
 * Get context around a position in the string
 */
function getContext(content: string, position: number, radius: number = 10): string {
  const start = Math.max(0, position - radius);
  const end = Math.min(content.length, position + radius + 1);
  let context = content.slice(start, end);

  // Replace invisible chars with visible markers
  context = context.replace(/[\u200B-\u200D\uFEFF]/g, '[ZWSP]');
  context = context.replace(/[\u202A-\u202E\u2066-\u2069]/g, '[BIDI]');

  if (start > 0) context = '...' + context;
  if (end < content.length) context = context + '...';

  return context;
}

/**
 * Check if a string contains any non-ASCII characters
 */
export function hasNonAscii(content: string): boolean {
  return /[^\x00-\x7F]/.test(content);
}

/**
 * Check if a string contains mixed scripts (potential homoglyph attack)
 */
export function hasMixedScripts(content: string): boolean {
  const hasLatin = /[a-zA-Z]/.test(content);
  const hasCyrillic = /[\u0400-\u04FF]/.test(content);
  const hasGreek = /[\u0370-\u03FF]/.test(content);

  // Count how many scripts are present
  const scriptCount = [hasLatin, hasCyrillic, hasGreek].filter(Boolean).length;
  return scriptCount > 1;
}

/**
 * Scan content for homoglyphs and hidden characters
 */
export function scanForHomoglyphs(content: string, filePath: string): PatternResult {
  const findings: Finding[] = [];

  // Detect invisible characters
  const invisibleChars = detectInvisibleCharacters(content);
  if (invisibleChars.length > 0) {
    // Group by type
    const zeroWidth = invisibleChars.filter(c => c.type === 'zero-width');
    const bidi = invisibleChars.filter(c => c.type === 'bidi');

    if (zeroWidth.length > 0) {
      findings.push({
        riskLevel: RiskLevel.RED,
        filePath,
        description: `${zeroWidth.length} zero-width character(s) detected - potential obfuscation`,
        category: FindingCategory.HOMOGLYPH,
        matchedContent: zeroWidth.slice(0, 3).map(c => `${c.codePoint} at pos ${c.position}`).join(', '),
      });
    }

    if (bidi.length > 0) {
      findings.push({
        riskLevel: RiskLevel.RED,
        filePath,
        description: `${bidi.length} bidirectional override character(s) detected - potential Trojan Source attack`,
        category: FindingCategory.HOMOGLYPH,
        matchedContent: bidi.slice(0, 3).map(c => `${c.codePoint} at pos ${c.position}`).join(', '),
      });
    }
  }

  // Detect homoglyphs
  const homoglyphs = detectHomoglyphs(content);
  if (homoglyphs.length > 0) {
    // Only report if there's mixed script context (legitimate use vs attack)
    if (hasMixedScripts(content)) {
      findings.push({
        riskLevel: RiskLevel.RED,
        filePath,
        description: `${homoglyphs.length} homoglyph character(s) detected in mixed-script context - potential spoofing attack`,
        category: FindingCategory.HOMOGLYPH,
        matchedContent: homoglyphs.slice(0, 3).map(c => c.context).join('; '),
      });
    } else if (homoglyphs.length > 0) {
      // Single script but has lookalikes - could be legitimate Cyrillic/Greek text
      // or could be attempted spoofing
      findings.push({
        riskLevel: RiskLevel.YELLOW,
        filePath,
        description: `${homoglyphs.length} potential homoglyph character(s) detected`,
        category: FindingCategory.HOMOGLYPH,
        matchedContent: homoglyphs.slice(0, 3).map(c => c.context).join('; '),
      });
    }
  }

  return { findings };
}

/**
 * Quick check if content needs detailed homoglyph scanning
 */
export function needsHomoglyphScan(content: string): boolean {
  // Quick check for any suspicious characters
  return (
    hasNonAscii(content) ||
    INVISIBLE_CHARS.some(c => content.includes(c)) ||
    BIDI_CHARS.some(c => content.includes(c))
  );
}
