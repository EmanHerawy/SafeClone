/**
 * SafeClone Background Service Worker
 * Handles message routing and file fetching
 */

import { handleMessage } from './messageHandler';
import type { Message } from '../shared/messageTypes';

// Listen for messages from content scripts and popup
chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  // Handle async messages
  handleMessage(message, sender)
    .then(response => sendResponse(response))
    .catch(error => {
      console.error('Background script error:', error);
      sendResponse({
        type: 'ERROR',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    });

  // Return true to indicate async response
  return true;
});

// Listen for extension installation/update
chrome.runtime.onInstalled.addListener((details) => {
  console.log('SafeClone installed/updated:', details.reason);

  if (details.reason === 'install') {
    // First install - could show welcome page
    console.log('SafeClone installed successfully!');
  } else if (details.reason === 'update') {
    // Extension updated
    console.log(`SafeClone updated to version ${chrome.runtime.getManifest().version}`);
  }
});

// Handle extension icon click (when no popup)
chrome.action.onClicked.addListener((tab) => {
  if (tab.url?.includes('github.com')) {
    // Trigger a scan on the current page
    chrome.tabs.sendMessage(tab.id!, { type: 'TRIGGER_SCAN' });
  }
});

console.log('SafeClone background service worker started');
