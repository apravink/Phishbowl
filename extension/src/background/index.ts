import { extractFeatures } from "./features";
import { isAllowed } from "./allowlist";
import {
  REFRESH_ALARM,
  getBlocklist,
  matchBlocked,
  recordHit,
  refreshBlocklist,
  scheduleRefresh,
} from "./blocklist";

chrome.runtime.onInstalled.addListener((details) => {
  console.log("[phishbowl] installed:", details.reason);
  scheduleRefresh();
});

chrome.runtime.onStartup.addListener(() => {
  console.log("[phishbowl] browser startup — SW alive");
  scheduleRefresh();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) void refreshBlocklist();
});

/** REQ-1 scope: main frame, http(s) only, skip localhost — non-http
 *  schemes (chrome-extension:, file:, about:) fall out at the protocol
 *  test. Kept here until T2 folds it into cascade.ts. */
function shouldCheck(u: URL): boolean {
  if (!/^https?:$/.test(u.protocol)) return false;
  const h = u.hostname.toLowerCase();
  return h !== "localhost" && !h.endsWith(".localhost") && h !== "127.0.0.1" && h !== "[::1]";
}

const BADGE_COLORS = {
  blocked: "#c0392b",
  neutral: "#888",
} as const;
type BadgeColor = (typeof BADGE_COLORS)[keyof typeof BADGE_COLORS];

function setBadge(tabId: number, text: string, color: BadgeColor) {
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return; // REQ-1: main frame only

  let url: URL;
  try {
    url = new URL(details.url);
  } catch {
    return;
  }
  if (!shouldCheck(url)) {
    setBadge(details.tabId, "", BADGE_COLORS.neutral); // clear stale badge on off-scope nav
    return;
  }

  if (isAllowed(url.hostname)) {
    setBadge(details.tabId, "", BADGE_COLORS.neutral);
    return;
  }

  void (async () => {
    const blocklist = await getBlocklist();
    const hit = matchBlocked(url.hostname, blocklist);
    if (hit) {
      setBadge(details.tabId, "!", BADGE_COLORS.blocked); // Phase 3 acceptance: feed host → red badge
      void recordHit(hit);
      console.log("[phishbowl] T1 block:", url.hostname, "→", hit, extractFeatures(url));
    } else {
      setBadge(details.tabId, "?", BADGE_COLORS.neutral); // unresolved — T2/T3 pending
    }
  })();
});
