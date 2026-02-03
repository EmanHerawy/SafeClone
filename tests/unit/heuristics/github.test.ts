import { scanGitHubActions, GitHubActionsScanner } from '../../../src/heuristics/patterns/github';
import { RiskLevel, FindingCategory } from '../../../src/shared/types';
import * as fs from 'fs';
import * as path from 'path';

describe('GitHub Actions Pattern Scanner', () => {
  const scanner = new GitHubActionsScanner();

  describe('appliesTo', () => {
    it('should apply to workflow yml files', () => {
      expect(scanner.appliesTo('.github/workflows/ci.yml')).toBe(true);
    });

    it('should apply to workflow yaml files', () => {
      expect(scanner.appliesTo('.github/workflows/build.yaml')).toBe(true);
    });

    it('should not apply to other yml files', () => {
      expect(scanner.appliesTo('config.yml')).toBe(false);
      expect(scanner.appliesTo('.github/ISSUE_TEMPLATE/bug.yml')).toBe(false);
    });
  });

  describe('pull_request_target detection', () => {
    it('should return YELLOW for pull_request_target event', () => {
      const content = `
name: CI
on:
  pull_request_target:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo "test"
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('pull_request_target'))).toBe(true);
    });
  });

  describe('pwn-request vulnerability detection', () => {
    it('should return RED for pull_request_target with PR checkout', () => {
      const content = `
name: CI
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm install
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Pwn-request'))).toBe(true);
    });
  });

  describe('command injection detection', () => {
    it('should return RED for injection via pull_request title', () => {
      const content = `
name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "PR Title: \${{ github.event.pull_request.title }}"
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('command injection'))).toBe(true);
    });

    it('should return RED for injection via issue body', () => {
      const content = `
name: Issue Handler
on: issues
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.event.issue.body }}"
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });

    it('should return RED for injection via head.ref', () => {
      const content = `
name: CI
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: git checkout \${{ github.head_ref }}
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });
  });

  describe('secrets exposure detection', () => {
    it('should return RED for secrets in echo', () => {
      const content = `
name: CI
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ secrets.API_KEY }}
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('secrets exposure'))).toBe(true);
    });
  });

  describe('unpinned action detection', () => {
    it('should return YELLOW for action on main branch', () => {
      const content = `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Unpinned action'))).toBe(true);
    });

    it('should return YELLOW for action on master branch', () => {
      const content = `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: some-org/action@master
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
    });

    it('should not flag pinned action with SHA', () => {
      const content = `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
`;
      const result = scanGitHubActions(content);

      expect(result.findings.filter(f => f.description.includes('Unpinned'))).toHaveLength(0);
    });

    it('should not flag action with version tag', () => {
      const content = `
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`;
      const result = scanGitHubActions(content);

      expect(result.findings.filter(f => f.description.includes('Unpinned'))).toHaveLength(0);
    });
  });

  describe('curl piped to shell', () => {
    it('should return RED for curl piped to bash', () => {
      const content = `
name: CI
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s https://example.com/install.sh | bash
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('curl piped to shell'))).toBe(true);
    });

    it('should return RED for curl piped to sh', () => {
      const content = `
name: CI
on: push
jobs:
  install:
    runs-on: ubuntu-latest
    steps:
      - run: curl https://example.com/script | sh
`;
      const result = scanGitHubActions(content);

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });
  });

  describe('safe workflow', () => {
    it('should return no findings for safe workflow', () => {
      const content = `
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm test
`;
      const result = scanGitHubActions(content);

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('fixture files', () => {
    it('should detect malicious patterns in malicious-workflow.yml fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/github/malicious-workflow.yml');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanGitHubActions(content, '.github/workflows/malicious.yml');

      // Should find RED findings
      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      // Should have multiple findings
      expect(result.findings.length).toBeGreaterThan(1);
    });

    it('should return no findings for safe-workflow.yml fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/github/safe-workflow.yml');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanGitHubActions(content, '.github/workflows/safe.yml');

      expect(result.findings).toHaveLength(0);
    });
  });
});
