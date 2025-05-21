const API_ENDPOINT = 'https://kavishnayeem-phishpatrol.hf.space/scan';
let scanStartTime = 0;
// Function to detect the URL from the search bar and display it
function displayCurrentUrl() {
  chrome.tabs.query({active: true, currentWindow: true}, tabs => {
    const currentUrl = tabs[0].url;
    document.getElementById('currentUrl').textContent = currentUrl;
  });
}

// Call the function to display the current URL when the popup is opened
document.addEventListener('DOMContentLoaded', displayCurrentUrl);


// DOM Elements
const elements = {
  loadingOverlay: document.querySelector('.loading-overlay'),
  scanBtn: document.getElementById('scanBtn'),
  timeTaken: document.getElementById('timeTaken'),
  totalUrls: document.getElementById('totalUrls'),
  confidence: document.getElementById('confidence'),
  pageVerdict: document.getElementById('pageVerdict'),
  reasons: document.getElementById('reasons')
};

// Initialize event listeners
function init() {
  elements.scanBtn.addEventListener('click', scanPage);
}

async function scanPage() {
  try {
    // Wait for DOM to be loaded before accessing elements
    document.addEventListener('DOMContentLoaded', init);
    const startTime = Date.now();
    showLoading(true);
    
    // Get URLs from current page
    const urls = await new Promise(resolve => {
      chrome.tabs.query({active: true, currentWindow: true}, tabs => {
        chrome.scripting.executeScript({
          target: {tabId: tabs[0].id},
          func: () => Array.from(document.querySelectorAll('a')).map(a => a.href).filter(Boolean)
        }, results => resolve([...new Set(results[0]?.result || [])]));
      });
    });

    if (!urls.length) {
      showError('No URLs found');
      return;
    }

    // Call optimized API endpoint
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({urls})
    });

    if (!response.ok) throw new Error(`Scan failed: ${response.status}`);
    const data = await response.json();
    console.log(data);

    // Update UI with scan results
    elements.timeTaken.textContent = data.time_taken;
    elements.totalUrls.textContent = data.total_urls;
    elements.pageVerdict.textContent = data.overall_verdict.toUpperCase();
    
    // Calculate and update confidence
    const confidencePercentage = data.overall_verdict === 'safe' 
      ? (data.legitimate / data.total_urls * 100).toFixed(2)
      : (data.phishing / data.total_urls * 100).toFixed(2);
    elements.confidence.textContent = confidencePercentage + '%';

    // Update reasons
    if (data.results && data.results.length > 0 && data.results[0].reasons && data.results[0].reasons.length > 0) {
      const reasons = data.results[0].reasons;
      elements.reasons.textContent = reasons.map(reason => reason.trim()).join('\n');
    } else {
      elements.reasons.textContent = 'No unusual urls detected';
    }

  } catch (error) {
    showError(error.message);
  } finally {
    showLoading(false);
  }
}

// Get URLs from current page
async function getPageUrls() {
  return new Promise((resolve) => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      chrome.scripting.executeScript({
        target: { tabId: tabs[0].id },
        func: () => Array.from(document.querySelectorAll('a')).map(a => a.href).filter(Boolean)
      }, (results) => {
        resolve([...new Set(results[0]?.result || [])]);
      });
    });
  });
}

// Show/hide loading overlay
function showLoading(show) {
  elements.loadingOverlay.style.display = show ? 'flex' : 'none';
}

// Show error message
function showError(message) {
  const errorElement = document.createElement('div');
  errorElement.className = 'error-message';
  errorElement.textContent = message;
  document.body.prepend(errorElement);
  setTimeout(() => errorElement.remove(), 5000);
}

// Initialize extension
document.addEventListener('DOMContentLoaded', init);