import {
  parseGitHubUrl,
  isGitHubRepoUrl,
  buildRawFileUrl,
  buildApiContentsUrl,
  normalizeFilePath,
  getRepoKey,
} from '../../../src/utils/urlParser';

describe('URL Parser', () => {
  describe('parseGitHubUrl', () => {
    it('should parse basic repo URL', () => {
      const result = parseGitHubUrl('https://github.com/owner/repo');

      expect(result).not.toBeNull();
      expect(result?.owner).toBe('owner');
      expect(result?.repo).toBe('repo');
      expect(result?.branch).toBeUndefined();
    });

    it('should parse repo URL with tree path', () => {
      const result = parseGitHubUrl('https://github.com/owner/repo/tree/main');

      expect(result).not.toBeNull();
      expect(result?.owner).toBe('owner');
      expect(result?.repo).toBe('repo');
      expect(result?.branch).toBe('main');
    });

    it('should parse repo URL with blob path', () => {
      const result = parseGitHubUrl('https://github.com/owner/repo/blob/develop/src/index.ts');

      expect(result).not.toBeNull();
      expect(result?.owner).toBe('owner');
      expect(result?.repo).toBe('repo');
      expect(result?.branch).toBe('develop');
    });

    it('should parse repo URL with feature branch', () => {
      const result = parseGitHubUrl('https://github.com/owner/repo/tree/feature/new-feature');

      expect(result).not.toBeNull();
      expect(result?.branch).toBe('feature');
    });

    it('should return null for non-GitHub URLs', () => {
      expect(parseGitHubUrl('https://gitlab.com/owner/repo')).toBeNull();
      expect(parseGitHubUrl('https://bitbucket.org/owner/repo')).toBeNull();
    });

    it('should return null for GitHub pages without repo', () => {
      expect(parseGitHubUrl('https://github.com/settings')).toBeNull();
      expect(parseGitHubUrl('https://github.com')).toBeNull();
    });

    it('should handle invalid URLs', () => {
      expect(parseGitHubUrl('not-a-url')).toBeNull();
      expect(parseGitHubUrl('')).toBeNull();
    });

    it('should preserve the original URL', () => {
      const url = 'https://github.com/owner/repo/tree/main';
      const result = parseGitHubUrl(url);

      expect(result?.url).toBe(url);
    });
  });

  describe('isGitHubRepoUrl', () => {
    it('should return true for repo URLs', () => {
      expect(isGitHubRepoUrl('https://github.com/owner/repo')).toBe(true);
      expect(isGitHubRepoUrl('https://github.com/owner/repo/tree/main')).toBe(true);
      expect(isGitHubRepoUrl('https://github.com/owner/repo/blob/main/README.md')).toBe(true);
    });

    it('should return false for non-repo GitHub pages', () => {
      expect(isGitHubRepoUrl('https://github.com/settings')).toBe(false);
      expect(isGitHubRepoUrl('https://github.com/explore')).toBe(false);
      expect(isGitHubRepoUrl('https://github.com/trending')).toBe(false);
      expect(isGitHubRepoUrl('https://github.com/marketplace')).toBe(false);
    });

    it('should return false for non-GitHub URLs', () => {
      expect(isGitHubRepoUrl('https://gitlab.com/owner/repo')).toBe(false);
      expect(isGitHubRepoUrl('https://google.com')).toBe(false);
    });

    it('should return false for org pages', () => {
      expect(isGitHubRepoUrl('https://github.com/orgs/myorg')).toBe(false);
    });
  });

  describe('buildRawFileUrl', () => {
    it('should build correct raw file URL', () => {
      const url = buildRawFileUrl('owner', 'repo', 'main', 'src/index.ts');

      expect(url).toBe('https://raw.githubusercontent.com/owner/repo/main/src/index.ts');
    });

    it('should handle leading slash in file path', () => {
      const url = buildRawFileUrl('owner', 'repo', 'main', '/src/index.ts');

      expect(url).toBe('https://raw.githubusercontent.com/owner/repo/main/src/index.ts');
    });

    it('should handle branch names with slashes', () => {
      const url = buildRawFileUrl('owner', 'repo', 'feature/branch', 'file.txt');

      expect(url).toBe('https://raw.githubusercontent.com/owner/repo/feature/branch/file.txt');
    });
  });

  describe('buildApiContentsUrl', () => {
    it('should build correct API URL for root', () => {
      const url = buildApiContentsUrl('owner', 'repo');

      expect(url).toBe('https://api.github.com/repos/owner/repo/contents/');
    });

    it('should build correct API URL for path', () => {
      const url = buildApiContentsUrl('owner', 'repo', 'src');

      expect(url).toBe('https://api.github.com/repos/owner/repo/contents/src');
    });

    it('should handle leading slash in path', () => {
      const url = buildApiContentsUrl('owner', 'repo', '/src/lib');

      expect(url).toBe('https://api.github.com/repos/owner/repo/contents/src/lib');
    });
  });

  describe('normalizeFilePath', () => {
    it('should remove leading slashes', () => {
      expect(normalizeFilePath('/src/index.ts')).toBe('src/index.ts');
      expect(normalizeFilePath('///path/to/file')).toBe('path/to/file');
    });

    it('should remove trailing slashes', () => {
      expect(normalizeFilePath('src/')).toBe('src');
      expect(normalizeFilePath('path/to/dir/')).toBe('path/to/dir');
    });

    it('should handle paths without slashes', () => {
      expect(normalizeFilePath('file.txt')).toBe('file.txt');
    });
  });

  describe('getRepoKey', () => {
    it('should generate key without branch', () => {
      const key = getRepoKey({
        owner: 'owner',
        repo: 'repo',
        url: 'https://github.com/owner/repo',
      });

      expect(key).toBe('owner/repo');
    });

    it('should generate key with branch', () => {
      const key = getRepoKey({
        owner: 'owner',
        repo: 'repo',
        branch: 'main',
        url: 'https://github.com/owner/repo',
      });

      expect(key).toBe('owner/repo@main');
    });
  });
});
