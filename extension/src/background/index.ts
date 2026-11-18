chrome.runtime.onInstalled.addListener((details) => {
  console.log("[phishbowl] installed:", details.reason);
});

chrome.runtime.onStartup.addListener(() => {
  console.log("[phishbowl] browser startup — SW alive");
});