import { TRANCO } from "./tranco.gen";

/** T0 — Tranco top-20k allowlist (REQ-4).
 *  True when the host equals or is a subdomain of an allowlisted domain.
 *
 *  Label-walk suffix match: "news.bbc.co.uk" tries news.bbc.co.uk,
 *  bbc.co.uk, co.uk, uk — Tranco stores apex domains (bbc.co.uk), so
 *  subdomains resolve in ≤ ~4 hops. Naive w.r.t. the public suffix list
 *  (same v1 caveat as subdomain_depth: a hypothetical attacker on
 *  "evil.co.uk" would match if "co.uk" itself were ever ranked — it
 *  never is, because Tranco only lists apex registrable domains).
 *  Set is injectable so tests run against a tiny fixture. */
export function isAllowed(
  host: string,
  allowlist: ReadonlySet<string> = TRANCO,
): boolean {
  const labels = host.toLowerCase().split(".");
  for (let i = 0; i < labels.length; i++) {
    if (allowlist.has(labels.slice(i).join("."))) return true;
  }
  return false;
}
