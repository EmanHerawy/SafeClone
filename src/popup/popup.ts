import { MessageType } from '../shared/messageTypes';
import type { ScanResult } from '../shared/types';
import { RiskLevel } from '../shared/types';

/**
 * Popup script for SafeClone extension
 */

const contentEl = document.getElementById('content')!;
const loaderEl = document.getElementById('loader')!;
const optionsLink = document.getElementById('options-link')!;

// Open options page
optionsLink.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

/**
 * Initialize popup
 */
async function init(): Promise<void> {
  try {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab.url || !tab.url.includes('github.com')) {
      showNoRepo();
      return;
    }

    // Get status from background
    const response = await chrome.runtime.sendMessage({
      type: MessageType.GET_STATUS,
    });

    if (response.type === MessageType.STATUS) {
      if (response.isScanning) {
        showScanning();
      } else if (response.lastScan) {
        showResults(response.lastScan);
      } else {
        showNoScan();
      }
    } else {
      showNoScan();
    }
  } catch (error) {
    console.error('Popup init error:', error);
    showError('Failed to load status');
  }
}

/**
 * Show no repository message
 */
function showNoRepo(): void {
  contentEl.innerHTML = `
    <div class="no-repo">
      <div class="no-repo-icon">📂</div>
      <p>Navigate to a GitHub repository to scan for security issues.</p>
    </div>
  `;
}

/**
 * Show scanning state
 */
function showScanning(): void {
  contentEl.innerHTML = `
    <div class="loader">
      <div class="spinner"></div>
      <span>Scanning repository...</span>
    </div>
  `;
}

/**
 * Show no scan performed yet
 */
function showNoScan(): void {
  contentEl.innerHTML = `
    <div class="status-card">
      <div class="status-icon gray">?</div>
      <div class="status-title">No Scan Performed</div>
      <div class="status-desc">Navigate to a GitHub repository to scan.</div>
    </div>
    <div class="actions">
      <button class="btn btn-primary" id="scan-btn">Scan Current Page</button>
    </div>
  `;

  document.getElementById('scan-btn')?.addEventListener('click', triggerScan);
}

/**
 * Show scan results
 */
function showResults(result: ScanResult): void {
  const riskClass = result.overallRisk.toLowerCase();
  const riskIcon = result.overallRisk === RiskLevel.RED ? '⚠️' :
                   result.overallRisk === RiskLevel.YELLOW ? '⚡' : '✓';
  const riskTitle = result.overallRisk === RiskLevel.RED ? 'Dangerous' :
                    result.overallRisk === RiskLevel.YELLOW ? 'At Risk' : 'Safe';
  const riskDesc = result.overallRisk === RiskLevel.RED
    ? 'Immediate security risks detected'
    : result.overallRisk === RiskLevel.YELLOW
    ? 'Suspicious patterns found'
    : 'No common attack vectors found';

  let findingsHtml = '';
  if (result.findings.length > 0) {
    const items = result.findings.slice(0, 5).map(finding => {
      const findingClass = finding.riskLevel.toLowerCase();
      const location = finding.lineNumber
        ? `${finding.filePath}:${finding.lineNumber}`
        : finding.filePath;

      return `
        <li class="finding-item ${findingClass}">
          <div class="finding-file">${escapeHtml(location)}</div>
          <div class="finding-desc">${escapeHtml(finding.description)}</div>
        </li>
      `;
    }).join('');

    const moreCount = result.findings.length - 5;
    const moreHtml = moreCount > 0
      ? `<li class="finding-item yellow"><div class="finding-desc">... and ${moreCount} more</div></li>`
      : '';

    findingsHtml = `<ul class="findings-list">${items}${moreHtml}</ul>`;
  }

  contentEl.innerHTML = `
    <div class="status-card">
      <div class="status-icon ${riskClass}">${riskIcon}</div>
      <div class="status-title">${riskTitle}</div>
      <div class="status-desc">${riskDesc}</div>
    </div>
    ${findingsHtml}
    <div class="actions">
      <button class="btn btn-primary" id="rescan-btn">Rescan</button>
      <button class="btn btn-secondary" id="clear-btn">Clear</button>
    </div>
  `;

  document.getElementById('rescan-btn')?.addEventListener('click', triggerScan);
  document.getElementById('clear-btn')?.addEventListener('click', clearCache);
}

/**
 * Show error message
 */
function showError(message: string): void {
  contentEl.innerHTML = `
    <div class="status-card">
      <div class="status-icon gray">❌</div>
      <div class="status-title">Error</div>
      <div class="status-desc">${escapeHtml(message)}</div>
    </div>
  `;
}

/**
 * Trigger a scan on the current page
 */
async function triggerScan(): Promise<void> {
  showScanning();

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tab.id) {
      await chrome.tabs.sendMessage(tab.id, { type: 'TRIGGER_SCAN' });

      // Wait a bit and refresh status
      setTimeout(async () => {
        const response = await chrome.runtime.sendMessage({
          type: MessageType.GET_STATUS,
        });

        if (response.type === MessageType.STATUS && response.lastScan) {
          showResults(response.lastScan);
        }
      }, 2000);
    }
  } catch (error) {
    console.error('Trigger scan error:', error);
    showError('Failed to start scan');
  }
}

/**
 * Clear scan cache
 */
async function clearCache(): Promise<void> {
  try {
    await chrome.runtime.sendMessage({
      type: MessageType.CLEAR_CACHE,
    });
    showNoScan();
  } catch (error) {
    console.error('Clear cache error:', error);
  }
}

/**
 * Escape HTML
 */
function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Initialize
init();
