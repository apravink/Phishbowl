// T1 — local phishing blocklist (REQ-2).
//  Feed URLs are resolved to hosts at refresh time; matching is host-level.
//  Pure core (parse/match/merge) is injectable and unit-tested (NFR-7);
//  the chrome.* layer is kept thin.

export const BLOCKLIST_CAP = 10_000; 
export const FEED_URL = "https://openphish.com/feed.txt"; // direct until Phase 5 proxy
export const REFRESH_ALARM = "blocklist.refresh";
const REFRESH_PERIOD_MIN = 24 * 60; // REQ-2: 24h refresh
const STALE_MS = 24 * 60 * 60 * 1000;

const KEY_LIST = "blocklist.v1"; // §2.5: newline-joined hosts + meta
const KEY_HITS = "hitcounts.v1"; // §2.5: host -> local match count

type StoredBlocklist = {
  hosts: string;
  ts: number;
  etag?: string;
  lastModified?: string;
};

// ── pure core ─────────────────────────────────────────────────────────────

function parseFeedHost(line: string): string | null {
  const raw = line.split(",")[0].trim();
  if (!raw || raw.startsWith("#")) return null;
  try {
    const { protocol, hostname } = new URL(raw);
    if (protocol !== "http:" && protocol !== "https:") return null;
    return hostname.toLowerCase() || null;
  } catch {
    return null;
  }
}

/** OpenPhish community feed: one URL per line, optionally followed by
 *  comma-separated metadata columns (brand, phish_id). Resolve to hosts,
 *  dedupe, keep feed order — position doubles as the age proxy for
 *  eviction (OpenPhish appends newest last). Junk lines are skipped,
 *  not fatal: one malformed URL must not lose the feed (NFR-6). */
export function parseOpenPhishFeed(text: string): string[] {
  const hosts = new Set<string>();
  for (const line of text.split("\n")) {
    const host = parseFeedHost(line);
    if (host) hosts.add(host);
  }
  return [...hosts];
}

/** T1 host match. True when the host equals or is a subdomain of a
 *  blocklisted host — label walk, same boundary discipline as T0, so
 *  "evil.com" matches "login.evil.com" but neither "notevil.com" nor
 *  "evil.com.attacker.io". Returns the matched entry (hit-counting,
 *  verdict reason) or null. */
export function matchBlocked(
  host: string,
  blocklist: ReadonlySet<string>,
): string | null {
  const labels = host.toLowerCase().split(".");
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join(".");
    if (blocklist.has(candidate)) return candidate;
  }
  return null;
}

/** Union of stored (older) and fresh feed hosts, capped per REQ-2.
 *  Overflow eviction: lowest local hit-count first, then oldest —
 *  index in the union is the age proxy (stored first, then fresh).
 *  Survivors keep union order. */
export function mergeBlocklist(
  stored: readonly string[],
  fresh: readonly string[],
  hitcounts: ReadonlyMap<string, number>,
  cap: number = BLOCKLIST_CAP,
): string[] {
  const union = [...stored];
  const inUnion = new Set(stored);
  for (const h of fresh) {
    if (!inUnion.has(h)) {
      union.push(h);
      inUnion.add(h);
    }
  }
  if (union.length <= cap) return union;

  const order = union.map((_, i) => i);
  order.sort((a, b) => {
    const ha = hitcounts.get(union[a]) ?? 0;
    const hb = hitcounts.get(union[b]) ?? 0;
    return ha !== hb ? ha - hb : a - b; // fewer hits, then older, evicts first
  });
  const evict = new Set(order.slice(0, union.length - cap));
  return union.filter((_, i) => !evict.has(i));
}

// ── chrome layer (thin) ───────────────────────────────────────────────────

// SW idle-restarts have zero memory state (§2.7): hydrate lazily, cache
// the promise, and invalidate on refresh.
let cache: Promise<ReadonlySet<string>> | null = null;

export function getBlocklist(): Promise<ReadonlySet<string>> {
  cache ??= chrome.storage.local
    .get(KEY_LIST)
    .then((o) => {
      const stored = o[KEY_LIST] as StoredBlocklist | undefined;
      return new Set(stored?.hosts ? stored.hosts.split("\n") : []) as ReadonlySet<string>;
    })
    .catch((e) => {
      cache = null; // a rejected promise must not latch
      throw e;
    });
  return cache;
}

/** Bump the local match count of a blocked entry — feeds REQ-2 eviction. */
export async function recordHit(host: string): Promise<void> {
  const o = await chrome.storage.local.get(KEY_HITS);
  const hits = (o[KEY_HITS] ?? {}) as Record<string, number>;
  hits[host] = (hits[host] ?? 0) + 1;
  await chrome.storage.local.set({ [KEY_HITS]: hits });
}

/** Conditional GET (ETag/Last-Modified) → 304 skips the reparse (REQ-2).
 *  Any failure keeps the stale copy (NFR-6); never throws to the alarm. */
export async function refreshBlocklist(): Promise<void> {
  const o = await chrome.storage.local.get(KEY_LIST);
  const stored = o[KEY_LIST] as StoredBlocklist | undefined;
  const headers: Record<string, string> = {};
  if (stored?.etag) headers["If-None-Match"] = stored.etag;
  if (stored?.lastModified) headers["If-Modified-Since"] = stored.lastModified;

  let res: Response;
  try {
    res = await fetch(FEED_URL, { headers, cache: "no-store" });
  } catch (e) {
    console.warn("[phishbowl] blocklist fetch failed — keeping stale copy:", e);
    return;
  }

  if (res.status === 304 && stored) {
    await chrome.storage.local.set({ [KEY_LIST]: { ...stored, ts: Date.now() } });
    cache = null;
    return;
  }
  if (!res.ok) {
    console.warn("[phishbowl] blocklist fetch status", res.status, "— keeping stale copy");
    return;
  }

  const fresh = parseOpenPhishFeed(await res.text());
  const [list, hitsObj] = await Promise.all([
    getBlocklist(),
    chrome.storage.local.get(KEY_HITS),
  ]);
  const hitcounts = new Map(
    Object.entries((hitsObj[KEY_HITS] ?? {}) as Record<string, number>),
  );
  const merged = mergeBlocklist([...list], fresh, hitcounts);
  const meta: StoredBlocklist = {
    hosts: merged.join("\n"),
    ts: Date.now(),
    etag: res.headers.get("etag") ?? undefined,
    lastModified: res.headers.get("last-modified") ?? undefined,
  };
  await chrome.storage.local.set({ [KEY_LIST]: meta });
  cache = null;
}

/** 24h alarm + immediate catch-up fetch if the list is stale/absent
 *  (the SW may have slept through scheduled fires). */
export function scheduleRefresh(): void {
  chrome.alarms.create(REFRESH_ALARM, { periodInMinutes: REFRESH_PERIOD_MIN });
  void chrome.storage.local
    .get(KEY_LIST)
    .then((o) => {
      const stored = o[KEY_LIST] as StoredBlocklist | undefined;
      if (!stored || Date.now() - stored.ts > STALE_MS) return refreshBlocklist();
    })
    .catch((e) => console.warn("[phishbowl] blocklist staleness check failed:", e));
}
