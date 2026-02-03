import { scanRust, RustScanner } from '../../../src/heuristics/patterns/rust';
import { RiskLevel, FindingCategory } from '../../../src/shared/types';
import * as fs from 'fs';
import * as path from 'path';

describe('Rust Pattern Scanner', () => {
  const scanner = new RustScanner();

  describe('appliesTo', () => {
    it('should apply to Cargo.toml', () => {
      expect(scanner.appliesTo('Cargo.toml')).toBe(true);
    });

    it('should apply to .cargo/config.toml', () => {
      expect(scanner.appliesTo('.cargo/config.toml')).toBe(true);
    });

    it('should apply to .cargo/config', () => {
      expect(scanner.appliesTo('.cargo/config')).toBe(true);
    });

    it('should not apply to other files', () => {
      expect(scanner.appliesTo('package.json')).toBe(false);
      expect(scanner.appliesTo('main.rs')).toBe(false);
    });
  });

  describe('build-dependencies detection', () => {
    it('should return YELLOW for [build-dependencies] section', () => {
      const content = `
[package]
name = "test"
version = "0.1.0"

[build-dependencies]
cc = "1.0"
`;
      const result = scanRust(content, 'Cargo.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Build dependencies'))).toBe(true);
    });
  });

  describe('custom build script detection', () => {
    it('should return YELLOW for custom build script', () => {
      const content = `
[package]
name = "test"
version = "0.1.0"
build = "custom-build.rs"
`;
      const result = scanRust(content, 'Cargo.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Custom build script'))).toBe(true);
    });

    it('should not flag default build.rs', () => {
      const content = `
[package]
name = "test"
version = "0.1.0"
build = "build.rs"
`;
      const result = scanRust(content, 'Cargo.toml');

      expect(result.findings.filter(f => f.description.includes('Custom build script'))).toHaveLength(0);
    });
  });

  describe('rustc-wrapper detection', () => {
    it('should return RED for rustc-wrapper override', () => {
      const content = `
[build]
rustc-wrapper = "/path/to/malicious/wrapper"
`;
      const result = scanRust(content, '.cargo/config.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('compiler override'))).toBe(true);
    });

    it('should return RED for rustc override', () => {
      const content = `
[build]
rustc = "/path/to/fake/rustc"
`;
      const result = scanRust(content, '.cargo/config.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });
  });

  describe('custom linker detection', () => {
    it('should return YELLOW for custom linker', () => {
      const content = `
[target.x86_64-unknown-linux-gnu]
linker = "/custom/linker"
`;
      const result = scanRust(content, '.cargo/config.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Custom linker'))).toBe(true);
    });
  });

  describe('custom runner detection', () => {
    it('should return YELLOW for custom runner', () => {
      const content = `
[target.x86_64-unknown-linux-gnu]
runner = ["sudo", "./run.sh"]
`;
      const result = scanRust(content, '.cargo/config.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Custom runner'))).toBe(true);
    });
  });

  describe('suspicious git dependencies', () => {
    it('should return YELLOW for git dependency from unknown host', () => {
      const content = `
[dependencies]
malware = { git = "https://evil-git-server.com/payload" }
`;
      const result = scanRust(content, 'Cargo.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Git dependency'))).toBe(true);
    });

    it('should not flag GitHub git dependencies', () => {
      const content = `
[dependencies]
safe = { git = "https://github.com/safe/crate" }
`;
      const result = scanRust(content, 'Cargo.toml');

      expect(result.findings.filter(f => f.description.includes('Git dependency'))).toHaveLength(0);
    });
  });

  describe('path traversal detection', () => {
    it('should return YELLOW for path with traversal', () => {
      const content = `
[dependencies]
local = { path = "../../../system/malware" }
`;
      const result = scanRust(content, 'Cargo.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Suspicious dependency'))).toBe(true);
    });
  });

  describe('proc-macro detection', () => {
    it('should return YELLOW for proc-macro crate', () => {
      const content = `
[lib]
proc-macro = true
`;
      const result = scanRust(content, 'Cargo.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Procedural macro'))).toBe(true);
    });
  });

  describe('custom source registry', () => {
    it('should return YELLOW for custom source registry', () => {
      const content = `
[source.custom-registry]
registry = "https://my-private-registry.com/index"
`;
      const result = scanRust(content, '.cargo/config.toml');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('Custom registry'))).toBe(true);
    });
  });

  describe('safe Cargo.toml', () => {
    it('should return no findings for safe Cargo.toml', () => {
      const content = `
[package]
name = "safe-crate"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
`;
      const result = scanRust(content, 'Cargo.toml');

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('fixture files', () => {
    it('should detect malicious patterns in malicious-cargo.toml fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/rust/malicious-cargo.toml');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanRust(content, 'Cargo.toml');

      // Should find YELLOW findings
      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      // Should have multiple findings
      expect(result.findings.length).toBeGreaterThan(1);
    });

    it('should return no findings for safe-cargo.toml fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/rust/safe-cargo.toml');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanRust(content, 'Cargo.toml');

      expect(result.findings).toHaveLength(0);
    });
  });
});
