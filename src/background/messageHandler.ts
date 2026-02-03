import type { Message, ScanResultMessage, ErrorMessage, FileTreeMessage, StatusMessage } from '../shared/messageTypes';
import { MessageType } from '../shared/messageTypes';
import type { ScanResult, RepositoryInfo } from '../shared/types';
import { RiskLevel } from '../shared/types';
import { storage } from '../shared/storage';
import { fetchMultipleFiles, getDefaultBranch, getFileTree } from './fetchService';
import { getFilesToScan } from '../utils/filePathMatcher';
import { scanRepository } from '../heuristics';

// Track scanning state
let isScanning = false;
let lastScanResult: ScanResult | null = null;

/**
 * Handle incoming messages from content scripts and popup
 */
export async function handleMessage(
  message: Message,
  sender: chrome.runtime.MessageSender
): Promise<Message> {
  try {
    switch (message.type) {
      case MessageType.SCAN_REPOSITORY:
        return await handleScanRepository(message.repository, message.fileTree);

      case MessageType.GET_FILE_TREE:
        return await handleGetFileTree(message.repository);

      case MessageType.GET_STATUS:
        return handleGetStatus();

      case MessageType.CLEAR_CACHE:
        await storage.clearCache();
        lastScanResult = null;
        return { type: MessageType.STATUS, isScanning: false };

      default:
        return {
          type: MessageType.ERROR,
          error: `Unknown message type: ${(message as Message).type}`,
        };
    }
  } catch (error) {
    console.error('Message handler error:', error);
    return {
      type: MessageType.ERROR,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Handle repository scan request (public repos only)
 */
async function handleScanRepository(
  repository: RepositoryInfo,
  fileTree: string[]
): Promise<ScanResultMessage | ErrorMessage> {
  if (isScanning) {
    return {
      type: MessageType.ERROR,
      error: 'Scan already in progress',
    };
  }

  isScanning = true;

  try {
    // Determine branch
    const branch = repository.branch || await getDefaultBranch(
      repository.owner,
      repository.repo
    );

    // Get files to scan
    const filesToScan = getFilesToScan(fileTree);

    if (filesToScan.length === 0) {
      const result: ScanResult = {
        overallRisk: RiskLevel.GREEN,
        findings: [],
        scannedFiles: [],
        skippedFiles: [],
        timestamp: Date.now(),
        repository,
      };

      lastScanResult = result;
      await storage.setLastScan(result);

      return {
        type: MessageType.SCAN_RESULT,
        result,
      };
    }

    // Fetch all files from public repo
    const files = await fetchMultipleFiles(
      repository.owner,
      repository.repo,
      branch,
      filesToScan
    );

    // Run scan
    const result = scanRepository(files, repository);

    // Cache result
    lastScanResult = result;
    await storage.setLastScan(result);
    await storage.cacheScan(
      storage.getRepoKey(repository.owner, repository.repo, branch),
      result
    );

    return {
      type: MessageType.SCAN_RESULT,
      result,
    };
  } catch (error) {
    console.error('Scan error:', error);
    return {
      type: MessageType.ERROR,
      error: error instanceof Error ? error.message : 'Scan failed',
    };
  } finally {
    isScanning = false;
  }
}

/**
 * Handle file tree request (public repos only)
 */
async function handleGetFileTree(
  repository: RepositoryInfo
): Promise<FileTreeMessage | ErrorMessage> {
  try {
    const branch = repository.branch || await getDefaultBranch(
      repository.owner,
      repository.repo
    );

    const files = await getFileTree(repository.owner, repository.repo, branch);

    return {
      type: MessageType.FILE_TREE,
      files,
    };
  } catch (error) {
    return {
      type: MessageType.ERROR,
      error: error instanceof Error ? error.message : 'Failed to fetch file tree',
    };
  }
}

/**
 * Handle status request
 */
function handleGetStatus(): StatusMessage {
  return {
    type: MessageType.STATUS,
    isScanning,
    lastScan: lastScanResult || undefined,
  };
}
