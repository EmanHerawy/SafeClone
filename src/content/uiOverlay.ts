import type { ScanResult } from '../shared/types';
import { RiskLevel, FindingCategory } from '../shared/types';
import { getRiskColor, getRiskDescription, formatFindingsForDisplay } from '../heuristics/riskClassifier';

const OVERLAY_ID = 'safeclone-overlay';
const SHADOW_HOST_ID = 'safeclone-shadow-host';

let shadowRoot: ShadowRoot | null = null;

/**
 * Create the shadow DOM host element
 */
function createShadowHost(): HTMLElement {
  // Remove existing host if present
  const existing = document.getElementById(SHADOW_HOST_ID);
  if (existing) {
    existing.remove();
  }

  const host = document.createElement('div');
  host.id = SHADOW_HOST_ID;
  host.style.cssText = `
    position: fixed;
    top: 10px;
    right: 10px;
    z-index: 9999999;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  `;

  document.body.appendChild(host);
  shadowRoot = host.attachShadow({ mode: 'closed' });

  return host;
}

/**
 * Get styles for the overlay
 */
function getOverlayStyles(): string {
  return `
    .safeclone-overlay {
      background: white;
      border-radius: 8px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
      min-width: 280px;
      max-width: 400px;
      font-size: 14px;
      animation: slideIn 0.3s ease-out;
    }

    @keyframes slideIn {
      from {
        opacity: 0;
        transform: translateY(-10px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .safeclone-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      border-bottom: 1px solid #e1e4e8;
    }

    .safeclone-status {
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .safeclone-shield {
      width: 24px;
      height: 24px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 14px;
    }

    .safeclone-shield.red { background: #dc3545; color: white; }
    .safeclone-shield.yellow { background: #ffc107; color: black; }
    .safeclone-shield.green { background: #28a745; color: white; }

    .safeclone-title {
      font-weight: 600;
      color: #24292e;
    }

    .safeclone-close {
      background: none;
      border: none;
      cursor: pointer;
      padding: 4px;
      color: #586069;
      font-size: 18px;
      line-height: 1;
    }

    .safeclone-close:hover {
      color: #24292e;
    }

    .safeclone-content {
      padding: 12px 16px;
      max-height: 300px;
      overflow-y: auto;
    }

    .safeclone-description {
      color: #586069;
      margin-bottom: 12px;
      font-size: 13px;
    }

    .safeclone-findings {
      list-style: none;
      padding: 0;
      margin: 0;
    }

    .safeclone-finding {
      padding: 8px;
      margin-bottom: 8px;
      background: #f6f8fa;
      border-radius: 4px;
      font-size: 12px;
      word-break: break-word;
    }

    .safeclone-finding.red {
      border-left: 3px solid #dc3545;
    }

    .safeclone-finding.yellow {
      border-left: 3px solid #ffc107;
    }

    .safeclone-finding-header {
      display: flex;
      align-items: center;
      gap: 6px;
      margin-bottom: 4px;
    }

    .safeclone-finding-icon {
      font-size: 12px;
    }

    .safeclone-finding-file {
      font-weight: 500;
      color: #24292e;
    }

    .safeclone-finding-desc {
      color: #586069;
    }

    .safeclone-footer {
      padding: 8px 16px;
      border-top: 1px solid #e1e4e8;
      font-size: 11px;
      color: #586069;
      display: flex;
      justify-content: space-between;
    }

    .safeclone-loader {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 16px;
    }

    .safeclone-spinner {
      width: 20px;
      height: 20px;
      border: 2px solid #e1e4e8;
      border-top-color: #0366d6;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .safeclone-minimized {
      cursor: pointer;
      padding: 8px;
      background: white;
      border-radius: 50%;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    }

    .safeclone-minimized:hover {
      box-shadow: 0 4px 15px rgba(0, 0, 0, 0.15);
    }
  `;
}

/**
 * Show loading state
 */
export function showLoading(): void {
  if (!shadowRoot) {
    createShadowHost();
  }

  const html = `
    <style>${getOverlayStyles()}</style>
    <div class="safeclone-overlay">
      <div class="safeclone-loader">
        <div class="safeclone-spinner"></div>
        <span>Scanning repository...</span>
      </div>
    </div>
  `;

  shadowRoot!.innerHTML = html;
}

/**
 * Show scan results
 */
export function showResults(result: ScanResult): void {
  if (!shadowRoot) {
    createShadowHost();
  }

  // Check if this is a fetch error (couldn't download files)
  const hasFetchError = result.findings.some(f => f.category === FindingCategory.FETCH_ERROR);
  const onlyFetchError = hasFetchError && result.findings.length === 1;

  const riskClass = onlyFetchError ? 'yellow' : result.overallRisk.toLowerCase();
  const riskIcon = onlyFetchError ? '⚠️' :
                   result.overallRisk === RiskLevel.RED ? '⚠️' :
                   result.overallRisk === RiskLevel.YELLOW ? '⚡' : '✓';
  const riskLabel = onlyFetchError ? 'Scan Incomplete' :
                    result.overallRisk === RiskLevel.RED ? 'Dangerous' :
                    result.overallRisk === RiskLevel.YELLOW ? 'Potential Risk' : 'Safe';

  let findingsHtml = '';
  if (result.findings.length > 0) {
    const findingItems = result.findings.slice(0, 10).map(finding => {
      const icon = finding.category === FindingCategory.FETCH_ERROR ? '⚠️' :
                   finding.riskLevel === RiskLevel.RED ? '🔴' : '🟡';
      const findingClass = finding.riskLevel.toLowerCase();
      const location = finding.lineNumber
        ? `${finding.filePath}:${finding.lineNumber}`
        : finding.filePath;

      return `
        <li class="safeclone-finding ${findingClass}">
          <div class="safeclone-finding-header">
            <span class="safeclone-finding-icon">${icon}</span>
            <span class="safeclone-finding-file">${location}</span>
          </div>
          <div class="safeclone-finding-desc">${escapeHtml(finding.description)}</div>
        </li>
      `;
    }).join('');

    const moreCount = result.findings.length - 10;
    const moreHtml = moreCount > 0
      ? `<li class="safeclone-finding yellow">... and ${moreCount} more finding(s)</li>`
      : '';

    findingsHtml = `<ul class="safeclone-findings">${findingItems}${moreHtml}</ul>`;
  }

  const html = `
    <style>${getOverlayStyles()}</style>
    <div class="safeclone-overlay" id="${OVERLAY_ID}">
      <div class="safeclone-header">
        <div class="safeclone-status">
          <div class="safeclone-shield ${riskClass}">${riskIcon}</div>
          <span class="safeclone-title">${riskLabel}</span>
        </div>
        <button class="safeclone-close" id="safeclone-close">×</button>
      </div>
      <div class="safeclone-content">
        <div class="safeclone-description">${onlyFetchError ? 'Could not fetch files - may be rate limited or files not found' : getRiskDescription(result.overallRisk)}</div>
        ${findingsHtml}
      </div>
      <div class="safeclone-footer">
        <span>Scanned ${result.scannedFiles.length} file(s)</span>
        <span>SafeClone</span>
      </div>
    </div>
  `;

  shadowRoot!.innerHTML = html;

  // Add close button handler
  const closeBtn = shadowRoot!.getElementById('safeclone-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', hideOverlay);
  }
}

/**
 * Show minimized badge
 */
export function showMinimized(result: ScanResult): void {
  if (!shadowRoot) {
    createShadowHost();
  }

  // Check if this is a fetch error (couldn't download files)
  const hasFetchError = result.findings.some(f => f.category === FindingCategory.FETCH_ERROR);
  const onlyFetchError = hasFetchError && result.findings.length === 1;

  const riskClass = onlyFetchError ? 'yellow' : result.overallRisk.toLowerCase();
  const riskIcon = onlyFetchError ? '⚠️' :
                   result.overallRisk === RiskLevel.RED ? '⚠️' :
                   result.overallRisk === RiskLevel.YELLOW ? '⚡' : '✓';

  const html = `
    <style>${getOverlayStyles()}</style>
    <div class="safeclone-minimized safeclone-shield ${riskClass}" id="safeclone-minimized" title="Click to expand SafeClone results">
      ${riskIcon}
    </div>
  `;

  shadowRoot!.innerHTML = html;

  // Add click handler to expand
  const badge = shadowRoot!.getElementById('safeclone-minimized');
  if (badge) {
    badge.addEventListener('click', () => showResults(result));
  }
}

/**
 * Hide the overlay completely
 */
export function hideOverlay(): void {
  const host = document.getElementById(SHADOW_HOST_ID);
  if (host) {
    host.remove();
  }
  shadowRoot = null;
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Check if overlay is currently visible
 */
export function isOverlayVisible(): boolean {
  return document.getElementById(SHADOW_HOST_ID) !== null;
}
