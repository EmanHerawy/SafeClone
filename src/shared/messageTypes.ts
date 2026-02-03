import type { ScanResult, RepositoryInfo, FileContent } from './types';

/**
 * Message types for Chrome runtime messaging
 */
export enum MessageType {
  /** Request to scan a repository */
  SCAN_REPOSITORY = 'SCAN_REPOSITORY',
  /** Scan result response */
  SCAN_RESULT = 'SCAN_RESULT',
  /** Request to fetch a file */
  FETCH_FILE = 'FETCH_FILE',
  /** File content response */
  FILE_CONTENT = 'FILE_CONTENT',
  /** Request to get file tree */
  GET_FILE_TREE = 'GET_FILE_TREE',
  /** File tree response */
  FILE_TREE = 'FILE_TREE',
  /** Error response */
  ERROR = 'ERROR',
  /** Get scan status */
  GET_STATUS = 'GET_STATUS',
  /** Status response */
  STATUS = 'STATUS',
  /** Clear cache */
  CLEAR_CACHE = 'CLEAR_CACHE',
}

/**
 * Base message interface
 */
export interface BaseMessage {
  type: MessageType;
}

/**
 * Request to scan a repository
 */
export interface ScanRepositoryMessage extends BaseMessage {
  type: MessageType.SCAN_REPOSITORY;
  repository: RepositoryInfo;
  fileTree: string[];
}

/**
 * Scan result response
 */
export interface ScanResultMessage extends BaseMessage {
  type: MessageType.SCAN_RESULT;
  result: ScanResult;
}

/**
 * Request to fetch a file
 */
export interface FetchFileMessage extends BaseMessage {
  type: MessageType.FETCH_FILE;
  repository: RepositoryInfo;
  filePath: string;
}

/**
 * File content response
 */
export interface FileContentMessage extends BaseMessage {
  type: MessageType.FILE_CONTENT;
  file: FileContent;
}

/**
 * Request file tree
 */
export interface GetFileTreeMessage extends BaseMessage {
  type: MessageType.GET_FILE_TREE;
  repository: RepositoryInfo;
}

/**
 * File tree response
 */
export interface FileTreeMessage extends BaseMessage {
  type: MessageType.FILE_TREE;
  files: string[];
}

/**
 * Error response
 */
export interface ErrorMessage extends BaseMessage {
  type: MessageType.ERROR;
  error: string;
}

/**
 * Get scan status request
 */
export interface GetStatusMessage extends BaseMessage {
  type: MessageType.GET_STATUS;
}

/**
 * Status response
 */
export interface StatusMessage extends BaseMessage {
  type: MessageType.STATUS;
  isScanning: boolean;
  lastScan?: ScanResult;
}

/**
 * Clear cache message
 */
export interface ClearCacheMessage extends BaseMessage {
  type: MessageType.CLEAR_CACHE;
}

/**
 * Union type of all messages
 */
export type Message =
  | ScanRepositoryMessage
  | ScanResultMessage
  | FetchFileMessage
  | FileContentMessage
  | GetFileTreeMessage
  | FileTreeMessage
  | ErrorMessage
  | GetStatusMessage
  | StatusMessage
  | ClearCacheMessage;

/**
 * Type guard for scan repository message
 */
export function isScanRepositoryMessage(msg: Message): msg is ScanRepositoryMessage {
  return msg.type === MessageType.SCAN_REPOSITORY;
}

/**
 * Type guard for fetch file message
 */
export function isFetchFileMessage(msg: Message): msg is FetchFileMessage {
  return msg.type === MessageType.FETCH_FILE;
}

/**
 * Type guard for scan result message
 */
export function isScanResultMessage(msg: Message): msg is ScanResultMessage {
  return msg.type === MessageType.SCAN_RESULT;
}
