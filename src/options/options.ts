import { storage } from '../shared/storage';
import { MessageType } from '../shared/messageTypes';

/**
 * Options page script for SafeClone
 * Works with public GitHub repositories only
 */

// Elements
const scanVscode = document.getElementById('scan-vscode') as HTMLInputElement;
const scanNpm = document.getElementById('scan-npm') as HTMLInputElement;
const scanPython = document.getElementById('scan-python') as HTMLInputElement;
const scanRust = document.getElementById('scan-rust') as HTMLInputElement;
const scanGithub = document.getElementById('scan-github') as HTMLInputElement;
const scanEntropy = document.getElementById('scan-entropy') as HTMLInputElement;
const scanHomoglyph = document.getElementById('scan-homoglyph') as HTMLInputElement;
const clearCacheBtn = document.getElementById('clear-cache') as HTMLButtonElement;
const saveBtn = document.getElementById('save-btn') as HTMLButtonElement;
const statusEl = document.getElementById('status') as HTMLDivElement;

/**
 * Load saved settings
 */
async function loadSettings(): Promise<void> {
  try {
    const config = await storage.getConfig();

    // Load scanning options
    scanVscode.checked = config.enabledHeuristics.vscode;
    scanNpm.checked = config.enabledHeuristics.npm;
    scanPython.checked = config.enabledHeuristics.python;
    scanRust.checked = config.enabledHeuristics.rust;
    scanGithub.checked = config.enabledHeuristics.githubActions;
    scanEntropy.checked = config.enabledHeuristics.entropy;
    scanHomoglyph.checked = config.enabledHeuristics.homoglyph;
  } catch (error) {
    console.error('Error loading settings:', error);
    showStatus('Failed to load settings', 'error');
  }
}

/**
 * Save settings
 */
async function saveSettings(): Promise<void> {
  try {
    await storage.setConfig({
      enabledHeuristics: {
        vscode: scanVscode.checked,
        npm: scanNpm.checked,
        python: scanPython.checked,
        rust: scanRust.checked,
        githubActions: scanGithub.checked,
        entropy: scanEntropy.checked,
        homoglyph: scanHomoglyph.checked,
      },
    });

    showStatus('Settings saved successfully!', 'success');
  } catch (error) {
    console.error('Error saving settings:', error);
    showStatus('Failed to save settings', 'error');
  }
}

/**
 * Clear cache
 */
async function clearCache(): Promise<void> {
  try {
    await chrome.runtime.sendMessage({
      type: MessageType.CLEAR_CACHE,
    });
    showStatus('Cache cleared successfully!', 'success');
  } catch (error) {
    console.error('Error clearing cache:', error);
    showStatus('Failed to clear cache', 'error');
  }
}

/**
 * Show status message
 */
function showStatus(message: string, type: 'success' | 'error'): void {
  statusEl.textContent = message;
  statusEl.className = `status ${type}`;
  statusEl.classList.remove('hidden');

  setTimeout(() => {
    statusEl.classList.add('hidden');
  }, 3000);
}

// Event listeners
saveBtn.addEventListener('click', saveSettings);
clearCacheBtn.addEventListener('click', clearCache);

// Load settings on page load
loadSettings();
