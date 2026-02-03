/**
 * SafeClone Content Script
 * Runs on GitHub pages to detect repositories and trigger scans
 */

import './content.css';
import { parseGitHubUrl, isGitHubRepoUrl } from '../utils/urlParser';
import { startNavigationDetection, onNavigate, getCurrentUrl } from './spaNavigationDetector';
import { startFileTreeObserver, extractFileTree, getCriticalFilesPresent } from './fileTreeObserver';
import { showLoading, showResults, showMinimized, hideOverlay } from './uiOverlay';
import { MessageType } from '../shared/messageTypes';
import type { ScanResult, RepositoryInfo } from '../shared/types';

// Track current repository
let currentRepo: RepositoryInfo | null = null;
let lastScanResult: ScanResult | null = null;

/**
 * Initialize the content script
 */
function init(): void {
  console.log('SafeClone content script initialized');

  // Start navigation detection
  startNavigationDetection();

  // Handle URL changes
  onNavigate(handleUrlChange);

  // Start file tree observer
  startFileTreeObserver();

  // Initial check
  handleUrlChange(getCurrentUrl());

  // Listen for messages from background
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'TRIGGER_SCAN') {
      triggerScan();
      sendResponse({ success: true });
    }
    return true;
  });
}

/**
 * Handle URL changes
 */
async function handleUrlChange(url: string): Promise<void> {
  // Check if this is a GitHub repo page
  if (!isGitHubRepoUrl(url)) {
    hideOverlay();
    currentRepo = null;
    return;
  }

  // Parse the URL
  const repoInfo = parseGitHubUrl(url);
  if (!repoInfo) {
    hideOverlay();
    currentRepo = null;
    return;
  }

  // Check if repo changed
  const repoChanged =
    !currentRepo ||
    currentRepo.owner !== repoInfo.owner ||
    currentRepo.repo !== repoInfo.repo;

  currentRepo = repoInfo;

  // If repo changed, trigger a new scan after a short delay
  if (repoChanged) {
    lastScanResult = null;

    // Wait for page to load
    setTimeout(() => {
      // Check if we have critical files present
      const criticalFiles = getCriticalFilesPresent();

      if (criticalFiles.length > 0) {
        triggerScan();
      } else {
        // Show minimized safe badge or fetch file tree
        fetchFileTreeAndScan();
      }
    }, 500);
  }
}

/**
 * Fetch file tree from API and trigger scan
 */
async function fetchFileTreeAndScan(): Promise<void> {
  if (!currentRepo) return;

  try {
    // Request file tree from background
    const response = await chrome.runtime.sendMessage({
      type: MessageType.GET_FILE_TREE,
      repository: currentRepo,
    });

    if (response.type === MessageType.FILE_TREE && response.files.length > 0) {
      // Check if there are critical files to scan
      const criticalPatterns = [
        '.vscode/',
        'package.json',
        'setup.py',
        'pyproject.toml',
        'Cargo.toml',
        '.cargo/',
        '.github/workflows/',
      ];

      const hasCriticalFiles = response.files.some((file: string) =>
        criticalPatterns.some(pattern =>
          file === pattern ||
          file.startsWith(pattern) ||
          file.endsWith(pattern.replace('/', ''))
        )
      );

      if (hasCriticalFiles) {
        triggerScanWithFileTree(response.files);
      }
    }
  } catch (error) {
    console.error('Error fetching file tree:', error);
  }
}

/**
 * Trigger a repository scan
 */
async function triggerScan(): Promise<void> {
  if (!currentRepo) return;

  // Get file tree from DOM or API
  let fileTree = extractFileTree();

  if (fileTree.length === 0) {
    // Fetch from API
    try {
      const response = await chrome.runtime.sendMessage({
        type: MessageType.GET_FILE_TREE,
        repository: currentRepo,
      });

      if (response.type === MessageType.FILE_TREE) {
        fileTree = response.files;
      }
    } catch (error) {
      console.error('Error fetching file tree:', error);
    }
  }

  triggerScanWithFileTree(fileTree);
}

/**
 * Trigger scan with a specific file tree
 */
async function triggerScanWithFileTree(fileTree: string[]): Promise<void> {
  if (!currentRepo || fileTree.length === 0) return;

  // Show loading state
  showLoading();

  try {
    // Send scan request to background
    const response = await chrome.runtime.sendMessage({
      type: MessageType.SCAN_REPOSITORY,
      repository: currentRepo,
      fileTree,
    });

    if (response.type === MessageType.SCAN_RESULT) {
      lastScanResult = response.result;
      showResults(response.result);

      // Auto-minimize after delay if safe
      if (response.result.overallRisk === 'GREEN') {
        setTimeout(() => {
          showMinimized(response.result);
        }, 3000);
      }
    } else if (response.type === MessageType.ERROR) {
      console.error('Scan error:', response.error);
      hideOverlay();
    }
  } catch (error) {
    console.error('Error sending scan request:', error);
    hideOverlay();
  }
}

/**
 * Get current scan result
 */
export function getCurrentScanResult(): ScanResult | null {
  return lastScanResult;
}

/**
 * Get current repository info
 */
export function getCurrentRepository(): RepositoryInfo | null {
  return currentRepo;
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
