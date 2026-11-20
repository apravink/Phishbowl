import { extractFeatures } from "./features";
import { isAllowed } from "./allowlist";

chrome.runtime.onInstalled.addListener((details) => {
  console.log("[phishbowl] installed:", details.reason);
});

chrome.runtime.onStartup.addListener(() => {
  console.log("[phishbowl] browser startup — SW alive");
});

chrome.webNavigation.onCommitted.addListener((details) =>{
  if(details.frameId !== 0) return;
  const url = new URL(details.url);
  if (!/^https?:$/.test(url.protocol)) return; 
  const allowed = isAllowed(url.hostname);
  console.log("[phishbowl", url.hostname, {allowed, ...extractFeatures(url) })
  chrome.action.setBadgeText({ tabId: details.tabId, text: allowed ? "" : "?" });
  chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: "#888" });
})

