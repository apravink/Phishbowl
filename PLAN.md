# PLAN.md — Phishbowl

Chrome extension (MV3) that classifies the current URL as phishing/benign via a 4-tier cascade ending in TypeSafe AI's **Jev** decision model, fronted by a Cloudflare Worker proxy. Blocked pages show a custom interstitial.

## 1. Product Requirements Document

### 1.1 Goals
- Detect known and novel phishing URLs at navigation time, URL-signals only
- Zero-config for end users; all keys server-side
- Privacy-preserving: no page content read; minimal, documented data egress
- Webstore-reviewable: minimal justified permissions, no misleading UI

### 1.2 User stories
- US-1 Navigate to known phish → blocked instantly, clear red interstitial explaining why
- US-2 Navigate to suspicious-unknown URL → Jev verdict; warn if phishing-likely
- US-3 "Proceed anyway" on interstitial → host allowed for this session
- US-4 Popup shows current verdict, reason, brand, manual re-check
- US-5 Block triggers badge + one OS notification per host per session
- US-6 URL-only data egress; no DOM content, no browsing history
- US-7 Operator deploys proxy with keys in env; no key ever in client

### 1.3 Functional requirements
| ID | Requirement |
|---|---|
| REQ-1 | 4-tier cascade on every main-frame navigation. Skip subframes, `chrome-extension://`, `file://`, localhost, `about:` |
| REQ-2 | Local blocklist: 10k URL cap (~0.5 MB, `chrome.storage.local`), 24h refresh via `chrome.alarms` from proxy with version-hash/ETag skip (~1 MB/day worst case), eviction by local hit-count then feed age |
| REQ-3 | Feeds: OpenPhish community (bulk, redistributable) + Google Safe Browsing Lookup v4 (proxy-side; **ephemeral only** — minutes-scale in-memory, never persisted or redistributed, per Google ToS) |
| REQ-4 | Tranco top-20k allowlist (~300 KB) bundled at build time; refreshed quarterly via extension release |
| REQ-5 | URL-only lexical feature vector (~15 fields): host entropy, subdomain depth, hyphen count, digit ratio, suspicious-TLD set, IP-literal host, punycode/homoglyph detection, brand-in-host/path, URL length, path depth |
| REQ-6 | Jev integration (`jev-1.14.0`, pinned) via proxy: `state` = URL + feature vector; questions = `is_phishing` (Noul) + `impersonating_brand` (Choice). Provisional thresholds — block p≥0.85 & conf≥0.6, amber 0.5–0.85; tune in Phase 6 |
| REQ-7 | Verdict caching: client `chrome.storage.session` LRU (500) + server KV (TTL 7d, SHA-256 keyed) |
| REQ-8 | Blocking = event-then-redirect: `webNavigation.onCommitted` → cascade → `chrome.tabs.update` to `blocked.html?orig=…` (URL, reason, brand, "Go back" default, "Proceed anyway" → host+session exception). `web_accessible_resources` stays empty |
| REQ-9 | Badge (red/amber/gray) + OS notification once per host per session |
| REQ-10 | Popup: current tab verdict, reason, brand, "Check this page" re-run, feed status. No extra permissions |
| REQ-11 | Options page: notification toggle + telemetry opt-out only |
| REQ-12 | Proxy: `POST /verdict`, `GET /feeds/blocklist`, `GET /health`; Jev + GSB keys in env; daily Jev budget guard; CORS locked to extension origin; D1 usage events |
| REQ-14 | Anonymous metrics: `install_id` UUID on install; D1 `events(install_id, event_type, ts, url_hash, verdict_kind, source)`; scheduled rollups → DAU/MAU, verdict distribution, block rate, Jev spend. Opt-out. Webstore listing needs privacy policy |

### 1.4 Non-functional requirements
- NFR-1 MV3-clean: no remote-hosted code; runtime fetches are pure data (blocklist, verdicts) only
- NFR-2 Privacy: URL + derived features only; documented egress; telemetry anonymous + opt-out
- NFR-3 Latency: tiers 0–2 <5ms local; Jev path p95 <800ms
- NFR-4 Cost: Jev calls gated by pre-filter + dual caching; proxy-side daily budget guard
- NFR-5 Permissions (justified in listing): `storage`, `alarms`, `notifications`, `webNavigation`, `tabs`; host: `<all_urls>` + proxy origin
- NFR-6 Failure semantics: Jev error/timeout → amber "unverified," never hard block. Feed failure → stale cache + badge notice. Proxy down → extension degrades to T0–T2 only
- NFR-7 Testability: unit tests for extractor + cascade; golden URL corpus; proxy tested under wrangler
- NFR-8 Capacity: free tier supports ~5–8k DAU; Workers Paid ($5/mo) beyond

### 1.5 Out of scope (v1)
DOM/content signals · custom ML training · web dashboard · Firefox/Edge ports · DNR session fast-path (backlog) · enterprise policy

### 1.6 Risks
| Risk | Mitigation |
|---|---|
| False positives on odd-but-legit URLs | Threshold tuning (Phase 6), amber tier, proceed-anyway |
| Webstore scrutiny on broad host permissions | Standard security-extension justification, minimal set |
| OpenPhish format drift | Proxy normalizes; client sees stable schema; stale cache on failure |
| Jev API/alias changes | Pinned model version; proxy is single integration point |
| GSB ToS violation via caching | Ephemeral-only design enforced in Phase 5 review |
| Cost overrun | Pre-filter gating, dual cache, budget guard |

## 2. Low-Level Design

### 2.1 Architecture
```
Navigation ──▶ onCommitted ──▶ CASCADE (service worker)
                               T0 Tranco allowlist (bundled) ──clean──▶ done
                               T1 Local blocklist (storage) ──hit──▶ BLOCK
                               T2 Lexical pre-filter ──benign──▶ done
                               T3 POST /verdict (Worker)
                                  ├─ KV verdict cache (7d)
                                  ├─ GSB Lookup (ephemeral)
                                  └─ Jev (jev-1.14.0) ──▶ threshold ──▶ BLOCK | AMBER | clean
BLOCK ──▶ tabs.update → blocked.html interstitial + badge + notification
24h alarm ──▶ GET /feeds/blocklist ──▶ storage update
```

### 2.2 File tree
```
phisher-chrome-web/
├── extension/
│   ├── public/manifest.json
│   ├── src/
│   │   ├── background/ (index.ts, cascade.ts, blocklist.ts, allowlist.ts,
│   │   │                features.ts, verdict-cache.ts, block.ts, badge.ts, notify.ts)
│   │   ├── popup/    (index.html, main.ts)
│   │   ├── blocked/  (blocked.html, main.ts)
│   │   ├── options/  (options.html, main.ts)
│   │   └── shared/
│   └── tests/
├── worker/
│   ├── src/ (index.ts [Hono], feeds.ts, gsb.ts, jev.ts, kv.ts, metrics.ts)
│   └── tests/
├── scripts/fetch-tranco.ts
├── shared/types.ts          (Verdict, FeatureVector, BlocklistEntry — imported by both)
└── migrations/0001_events.sql
```

### 2.3 Core types & signatures
```ts
type VerdictKind = 'clean' | 'suspicious' | 'phishing' | 'unverified';
type Verdict = { kind: VerdictKind; source: 'allowlist'|'blocklist'|'prefilter'|'gsb'|'jev'|'error';
                 reason: string; brand?: string; p?: number; confidence?: number; ts: number };

extractFeatures(u: URL): FeatureVector;              // pure, unit-tested
decide(u: URL, ctx: CascadeCtx): Promise<Verdict>;   // orchestrator

POST /verdict  { url: string, features: FeatureVector, install_id: string }
             →  { verdict: Verdict, cached: boolean }
GET  /feeds/blocklist  (If-None-Match) → 200 [urls] | 304
GET  /health           →  { ok, feed_age_h, jev_calls_today }
```

### 2.4 Jev request (worker-side, pinned `jev-1.14.0`)
```json
{ "state": { "url": "...", "host": "...", "tld": "...", "features": { }, "checked_at": "ISO" },
  "questions": {
    "is_phishing": { "type": "noul",
      "instructions": "Considering the URL and features, does this attempt to impersonate a legitimate brand or trick users into revealing credentials?" },
    "impersonating_brand": { "type": "choice", "options": ["none", "paypal", "apple", "...top-100"],
      "instructions": "Which brand, if any, does this URL impersonate?" } } }
```

### 2.5 Storage
- `chrome.storage.local`: `blocklist.v1` (newline-joined string + meta), `hitcounts.v1`, `settings.v1`
- `chrome.storage.session`: `exceptions.v1` (host set), `verdicts.v1` (LRU 500)
- KV: `v:<sha256(url)>` → Verdict JSON, TTL 7d
- D1: `events(install_id TEXT, event_type TEXT, ts INT, url_hash TEXT, verdict_kind TEXT, source TEXT)`

### 2.6 Phases
| # | Phase | Ships | Maps to | Acceptance |
|---|---|---|---|---|
| 1 | Skeleton | pnpm + Vite + TS + @crxjs, manifest, empty SW, vitest/eslint | REQ-1, NFR-1 | `pnpm build` → loadable unpacked extension |
| 2 | Feature extractor | `extractFeatures()`, brand list, homoglyph maps | REQ-5 | Unit tests green on curated benign/phish corpus |
| 3 | Local cascade T0–T2 | Tranco script, blocklist store + alarm, onCommitted → badge | REQ-1/2/4 | Feed URL → red badge; top sites unaffected |
| 4 | Blocking UX | blocked.html, session exceptions, notifications, popup shell | REQ-8/9/10 | E2E: test URL blocks, proceed works for session, notify once |
| 5 | Worker proxy | Hono routes, OpenPhish normalizer, GSB (ephemeral, ToS-reviewed), Jev caller, KV, budget guard, D1 | REQ-3/6/12/14 | wrangler dev + curl suite; KV TTL verified; GSB never persisted |
| 6 | Jev tuning | Wire T3; state/question design; threshold sweep on ~2k labeled URLs | REQ-6/7 | Precision/recall report; thresholds documented |
| 7 | UI polish | Full popup; options = 2 toggles | REQ-10/11 | Manual pass |
| 8 | Hardening | Privacy doc + policy page, permission justifications, README, edge-case audit | NFR-2/5/6 | Bundle audit clean |

Phases 3–4 deliver a working local-only product before infra dependency exists.

### 2.7 Edge cases (non-exhaustive, tested)
SW idle-restarts (zero memory state) · rapid multi-tab navigation (debounce) · URL credentials/punycode normalization · interstitial re-entry loop guard (exception consumed before redirect) · Jev 5xx/timeout → unverified · GSB quota exhaustion → silent skip · feed fetch failure → stale cache + badge notice · blocklist overflow → hit-count eviction · repeat-offender hosts → notification dedupe.

### 2.8 Backlog
DNR session fast-path (zero-flash repeat blocks) · DOM content signals · web dashboard · Firefox/Edge port · community reporting of false pos/negs.
