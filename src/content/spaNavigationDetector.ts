/**
 * Detect GitHub SPA navigation changes
 * GitHub uses turbo/pjax for navigation, so we need to detect URL changes
 */

type NavigationCallback = (url: string) => void;

let lastUrl = window.location.href;
let observers: NavigationCallback[] = [];

/**
 * Register a callback for URL changes
 */
export function onNavigate(callback: NavigationCallback): () => void {
  observers.push(callback);

  // Return unsubscribe function
  return () => {
    observers = observers.filter(cb => cb !== callback);
  };
}

/**
 * Check if the URL has changed and notify observers
 */
function checkUrlChange(): void {
  const currentUrl = window.location.href;

  if (currentUrl !== lastUrl) {
    lastUrl = currentUrl;
    observers.forEach(callback => {
      try {
        callback(currentUrl);
      } catch (error) {
        console.error('Navigation callback error:', error);
      }
    });
  }
}

/**
 * Start watching for navigation changes
 */
export function startNavigationDetection(): void {
  // Listen for popstate (back/forward navigation)
  window.addEventListener('popstate', checkUrlChange);

  // Listen for pushstate/replacestate (turbo/pjax navigation)
  const originalPushState = history.pushState.bind(history);
  const originalReplaceState = history.replaceState.bind(history);

  history.pushState = function (...args) {
    originalPushState(...args);
    checkUrlChange();
  };

  history.replaceState = function (...args) {
    originalReplaceState(...args);
    checkUrlChange();
  };

  // Also use MutationObserver on the title element as a fallback
  const titleObserver = new MutationObserver(() => {
    checkUrlChange();
  });

  const titleElement = document.querySelector('title');
  if (titleElement) {
    titleObserver.observe(titleElement, {
      childList: true,
      characterData: true,
      subtree: true,
    });
  }

  // Watch for turbo events (GitHub uses turbo-drive)
  document.addEventListener('turbo:load', checkUrlChange);
  document.addEventListener('turbo:render', checkUrlChange);

  // Initial check
  checkUrlChange();
}

/**
 * Stop watching for navigation changes
 */
export function stopNavigationDetection(): void {
  window.removeEventListener('popstate', checkUrlChange);
  document.removeEventListener('turbo:load', checkUrlChange);
  document.removeEventListener('turbo:render', checkUrlChange);
}

/**
 * Get the current URL
 */
export function getCurrentUrl(): string {
  return window.location.href;
}
