import type { FileContent } from '../shared/types';
import { buildRawFileUrl } from '../utils/urlParser';

/**
 * Fetch a raw file from a public GitHub repository
 */
export async function fetchRawFile(
  owner: string,
  repo: string,
  branch: string,
  filePath: string
): Promise<FileContent> {
  const url = buildRawFileUrl(owner, repo, branch, filePath);

  try {
    const response = await fetch(url, {
      headers: {
        Accept: 'text/plain',
      },
    });

    if (!response.ok) {
      if (response.status === 404) {
        return {
          path: filePath,
          content: '',
          exists: false,
        };
      }
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const content = await response.text();

    return {
      path: filePath,
      content,
      exists: true,
    };
  } catch (error) {
    console.error(`Error fetching ${filePath}:`, error);
    return {
      path: filePath,
      content: '',
      exists: false,
    };
  }
}

/**
 * Fetch multiple files in parallel
 */
export async function fetchMultipleFiles(
  owner: string,
  repo: string,
  branch: string,
  filePaths: string[]
): Promise<FileContent[]> {
  const promises = filePaths.map(path =>
    fetchRawFile(owner, repo, branch, path)
  );

  return Promise.all(promises);
}

/**
 * Get repository default branch via GitHub API (public repos only)
 */
export async function getDefaultBranch(
  owner: string,
  repo: string
): Promise<string> {
  const url = `https://api.github.com/repos/${owner}/${repo}`;

  try {
    const response = await fetch(url, {
      headers: {
        Accept: 'application/vnd.github.v3+json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    return data.default_branch || 'main';
  } catch (error) {
    console.error('Error fetching default branch:', error);
    // Fallback to common defaults
    return 'main';
  }
}

/**
 * Get repository file tree via GitHub API (public repos only)
 */
export async function getFileTree(
  owner: string,
  repo: string,
  branch: string
): Promise<string[]> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`;

  try {
    const response = await fetch(url, {
      headers: {
        Accept: 'application/vnd.github.v3+json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    if (!data.tree) {
      return [];
    }

    // Return all file paths
    return data.tree
      .filter((item: { type: string }) => item.type === 'blob' || item.type === 'tree')
      .map((item: { path: string; type: string }) =>
        item.type === 'tree' ? `${item.path}/` : item.path
      );
  } catch (error) {
    console.error('Error fetching file tree:', error);
    return [];
  }
}

/**
 * Fetch repository info (public repos only)
 */
export async function fetchRepositoryInfo(
  owner: string,
  repo: string
): Promise<{
  defaultBranch: string;
  fileTree: string[];
} | null> {
  try {
    const defaultBranch = await getDefaultBranch(owner, repo);
    const fileTree = await getFileTree(owner, repo, defaultBranch);

    return {
      defaultBranch,
      fileTree,
    };
  } catch (error) {
    console.error('Error fetching repository info:', error);
    return null;
  }
}
