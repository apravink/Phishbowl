# Phishbowl

Chrome extension (MV3) that flags phishing URLs via a 4-tier cascade:

1. **T0** — Tranco top-20k allowlist (bundled)
2. **T1** — Local known-phishing blocklist (OpenPhish + Jev-confirmed, refreshed daily)
3. **T2** — URL lexical pre-filter
4. **T3** — [Jev](https://docs.typesafe.ai) decision model + Google Safe Browsing, behind a Cloudflare Worker proxy

Full PRD, LLD, and phase plan: see [PLAN.md](./PLAN.md).

## Layout

```
extension/   Chrome extension (service worker, popup, interstitial, options)
worker/      Cloudflare Worker proxy (verdict API, feed aggregator, metrics)
shared/      Types shared by extension and worker
scripts/     Build-time tooling (e.g. Tranco allowlist fetch)
migrations/  D1 schema migrations
```
