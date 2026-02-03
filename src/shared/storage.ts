import type { ExtensionConfig, ScanResult } from './types';
import { DEFAULT_CONFIG } from './types';

/**
 * Storage keys
 */
const STORAGE_KEYS = {
  CONFIG: 'safeclone_config',
  LAST_SCAN: 'safeclone_last_scan',
  SCAN_CACHE: 'safeclone_scan_cache',
} as const;

/**
 * Chrome storage abstraction for extension configuration and data
 */
export const storage = {
  /**
   * Get extension configuration
   */
  async getConfig(): Promise<ExtensionConfig> {
    return new Promise((resolve) => {
      chrome.storage.sync.get(STORAGE_KEYS.CONFIG, (result) => {
        const config = result[STORAGE_KEYS.CONFIG];
        resolve(config ? { ...DEFAULT_CONFIG, ...config } : DEFAULT_CONFIG);
      });
    });
  },

  /**
   * Save extension configuration
   */
  async setConfig(config: Partial<ExtensionConfig>): Promise<void> {
    const currentConfig = await this.getConfig();
    const newConfig = { ...currentConfig, ...config };
    return new Promise((resolve) => {
      chrome.storage.sync.set({ [STORAGE_KEYS.CONFIG]: newConfig }, resolve);
    });
  },

  /**
   * Get last scan result
   */
  async getLastScan(): Promise<ScanResult | null> {
    return new Promise((resolve) => {
      chrome.storage.local.get(STORAGE_KEYS.LAST_SCAN, (result) => {
        resolve(result[STORAGE_KEYS.LAST_SCAN] || null);
      });
    });
  },

  /**
   * Save last scan result
   */
  async setLastScan(scan: ScanResult): Promise<void> {
    return new Promise((resolve) => {
      chrome.storage.local.set({ [STORAGE_KEYS.LAST_SCAN]: scan }, resolve);
    });
  },

  /**
   * Get cached scan for a repository
   */
  async getCachedScan(repoKey: string): Promise<ScanResult | null> {
    return new Promise((resolve) => {
      chrome.storage.local.get(STORAGE_KEYS.SCAN_CACHE, (result) => {
        const cache = result[STORAGE_KEYS.SCAN_CACHE] || {};
        resolve(cache[repoKey] || null);
      });
    });
  },

  /**
   * Cache scan result for a repository
   */
  async cacheScan(repoKey: string, scan: ScanResult): Promise<void> {
    return new Promise((resolve) => {
      chrome.storage.local.get(STORAGE_KEYS.SCAN_CACHE, (result) => {
        const cache = result[STORAGE_KEYS.SCAN_CACHE] || {};
        cache[repoKey] = scan;
        chrome.storage.local.set({ [STORAGE_KEYS.SCAN_CACHE]: cache }, resolve);
      });
    });
  },

  /**
   * Clear scan cache
   */
  async clearCache(): Promise<void> {
    return new Promise((resolve) => {
      chrome.storage.local.remove([STORAGE_KEYS.SCAN_CACHE, STORAGE_KEYS.LAST_SCAN], resolve);
    });
  },

  /**
   * Generate cache key for a repository
   */
  getRepoKey(owner: string, repo: string, branch?: string): string {
    return `${owner}/${repo}${branch ? `@${branch}` : ''}`;
  },
};
