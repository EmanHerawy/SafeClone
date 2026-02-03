import type { RepositoryInfo } from '../shared/types';

/**
 * Parse a GitHub URL to extract repository information
 * Supports various GitHub URL formats
 */
export function parseGitHubUrl(url: string): RepositoryInfo | null {
  try {
    const urlObj = new URL(url);

    // Must be github.com
    if (!urlObj.hostname.endsWith('github.com')) {
      return null;
    }

    // Parse the pathname
    const pathParts = urlObj.pathname.split('/').filter(Boolean);

    // Need at least owner/repo
    if (pathParts.length < 2) {
      return null;
    }

    const owner = pathParts[0];
    const repo = pathParts[1];

    // Extract branch if available
    let branch: string | undefined;

    // Check for /tree/branch or /blob/branch pattern
    if (pathParts.length >= 4 && (pathParts[2] === 'tree' || pathParts[2] === 'blob')) {
      branch = pathParts[3];
    }

    // Check for /commit/hash pattern
    if (pathParts.length >= 4 && pathParts[2] === 'commit') {
      // This is a commit, not a branch
      branch = undefined;
    }

    return {
      owner,
      repo,
      branch,
      url,
    };
  } catch {
    return null;
  }
}

/**
 * Check if a URL is a GitHub repository page
 */
export function isGitHubRepoUrl(url: string): boolean {
  try {
    const urlObj = new URL(url);

    if (!urlObj.hostname.endsWith('github.com')) {
      return false;
    }

    const pathParts = urlObj.pathname.split('/').filter(Boolean);

    // Need at least owner/repo
    if (pathParts.length < 2) {
      return false;
    }

    // Exclude non-repo pages
    const nonRepoFirstPaths = [
      'settings',
      'notifications',
      'explore',
      'trending',
      'marketplace',
      'sponsors',
      'login',
      'signup',
      'about',
      'pricing',
      'enterprise',
      'features',
      'security',
      'team',
      'customer-stories',
    ];

    if (nonRepoFirstPaths.includes(pathParts[0])) {
      return false;
    }

    // Exclude organization pages without a specific repo
    const orgOnlyPaths = ['orgs', 'organizations'];
    if (orgOnlyPaths.includes(pathParts[0])) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Build raw.githubusercontent.com URL for a file
 */
export function buildRawFileUrl(
  owner: string,
  repo: string,
  branch: string,
  filePath: string
): string {
  // Remove leading slash if present
  const cleanPath = filePath.startsWith('/') ? filePath.slice(1) : filePath;
  return `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${cleanPath}`;
}

/**
 * Build GitHub API URL for repository contents
 */
export function buildApiContentsUrl(
  owner: string,
  repo: string,
  path: string = ''
): string {
  const cleanPath = path.startsWith('/') ? path.slice(1) : path;
  return `https://api.github.com/repos/${owner}/${repo}/contents/${cleanPath}`;
}

/**
 * Extract the default branch from a GitHub page
 * This is a fallback when we can't determine the branch from the URL
 */
export function extractDefaultBranch(html: string): string | null {
  // Look for the default branch in various places in the HTML
  const patterns = [
    /data-default-branch="([^"]+)"/,
    /"defaultBranch":"([^"]+)"/,
    /ref=([^"&]+)/,
  ];

  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match && match[1]) {
      return match[1];
    }
  }

  return null;
}

/**
 * Normalize a file path (remove leading slashes, etc.)
 */
export function normalizeFilePath(path: string): string {
  return path.replace(/^\/+/, '').replace(/\/+$/, '');
}

/**
 * Get the repository key for caching
 */
export function getRepoKey(info: RepositoryInfo): string {
  const base = `${info.owner}/${info.repo}`;
  return info.branch ? `${base}@${info.branch}` : base;
}
