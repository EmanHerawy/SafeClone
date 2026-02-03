/**
 * Observe GitHub file tree for relevant files
 * Extracts file list from the DOM
 */

type FileTreeCallback = (files: string[]) => void;

let fileTreeObservers: FileTreeCallback[] = [];
let mutationObserver: MutationObserver | null = null;

/**
 * Register a callback for file tree changes
 */
export function onFileTreeChange(callback: FileTreeCallback): () => void {
  fileTreeObservers.push(callback);

  return () => {
    fileTreeObservers = fileTreeObservers.filter(cb => cb !== callback);
  };
}

/**
 * Extract file list from GitHub's file tree
 */
export function extractFileTree(): string[] {
  const files: string[] = [];

  // Try multiple selectors for GitHub's file tree
  const selectors = [
    // New GitHub UI (React-based)
    '[data-testid="tree-view-list"] a[href*="/blob/"]',
    '[data-testid="tree-view-list"] a[href*="/tree/"]',
    // Older GitHub UI
    '.js-navigation-item .content a',
    '.Box-row a[href*="/blob/"]',
    '.Box-row a[href*="/tree/"]',
    // File tree sidebar
    '.tree-browser a[href*="/blob/"]',
    '.tree-browser a[href*="/tree/"]',
    // Repository content table
    'table[aria-labelledby] a[href*="/blob/"]',
    'table[aria-labelledby] a[href*="/tree/"]',
  ];

  for (const selector of selectors) {
    const elements = document.querySelectorAll(selector);

    elements.forEach(el => {
      const href = el.getAttribute('href');
      if (href) {
        // Extract file path from href
        const match = href.match(/\/(blob|tree)\/[^/]+\/(.+)/);
        if (match && match[2]) {
          const path = match[2];
          // Add trailing slash for directories
          const isDir = href.includes('/tree/');
          files.push(isDir ? `${path}/` : path);
        }
      }
    });
  }

  // Also check for .vscode, package.json, etc. in visible text
  const fileNames = document.querySelectorAll('[data-file-name], .file-name');
  fileNames.forEach(el => {
    const name = el.textContent?.trim();
    if (name) {
      files.push(name);
    }
  });

  // Deduplicate and sort
  return [...new Set(files)].sort();
}

/**
 * Notify observers of file tree changes
 */
function notifyObservers(): void {
  const files = extractFileTree();
  fileTreeObservers.forEach(callback => {
    try {
      callback(files);
    } catch (error) {
      console.error('File tree callback error:', error);
    }
  });
}

/**
 * Start observing file tree changes
 */
export function startFileTreeObserver(): void {
  // Find the main content area to observe
  const targetSelectors = [
    'main',
    '#repo-content-pjax-container',
    '.repository-content',
    '[data-turbo-frame="repo-content-turbo-frame"]',
  ];

  let target: Element | null = null;
  for (const selector of targetSelectors) {
    target = document.querySelector(selector);
    if (target) break;
  }

  if (!target) {
    // Fallback to body
    target = document.body;
  }

  // Create mutation observer
  mutationObserver = new MutationObserver((mutations) => {
    // Debounce updates
    let hasRelevantChanges = false;

    for (const mutation of mutations) {
      if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
        hasRelevantChanges = true;
        break;
      }
    }

    if (hasRelevantChanges) {
      // Debounce notification
      setTimeout(notifyObservers, 100);
    }
  });

  mutationObserver.observe(target, {
    childList: true,
    subtree: true,
  });

  // Initial extraction
  notifyObservers();
}

/**
 * Stop observing file tree changes
 */
export function stopFileTreeObserver(): void {
  if (mutationObserver) {
    mutationObserver.disconnect();
    mutationObserver = null;
  }
}

/**
 * Check if a file exists in the tree
 */
export function hasFileInTree(fileName: string): boolean {
  const files = extractFileTree();
  return files.some(f =>
    f === fileName ||
    f.endsWith(`/${fileName}`) ||
    f.startsWith(`${fileName}/`)
  );
}

/**
 * Get critical files present in the file tree
 */
export function getCriticalFilesPresent(): string[] {
  const files = extractFileTree();
  const criticalPatterns = [
    '.vscode/',
    'package.json',
    'setup.py',
    'pyproject.toml',
    'Cargo.toml',
    '.cargo/',
    '.github/workflows/',
  ];

  return criticalPatterns.filter(pattern =>
    files.some(f => f === pattern || f.startsWith(pattern) || f.endsWith(pattern.replace('/', '')))
  );
}
