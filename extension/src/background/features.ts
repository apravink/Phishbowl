import type { FeatureVector } from "../../../shared/types";
import { UNICODE_CONFUSABLES } from "./confusables.gen";

// ── brands ────────────────────────────────────────────────────────────────
// Seed list; grow to ~top-100 during Phase 6 tuning.
// Accepted v1 noise: "apple" also matches appleinsider.com — separating
// "brand present" from "brand impersonated" is T0/Jev's job, not the
// extractor's (see PLAN.md §2.1 cascade).
const BRANDS = [
  "paypal", "apple", "google", "microsoft", "amazon", "netflix",
  "facebook", "instagram", "whatsapp", "coinbase", "binance",
  "metamask", "chase", "wellsfargo", "dhl", "fedex", "usps",
  "steam", "discord", "adobe", "icloud", "outlook", "linkedin",
];

const findBrand = (s: string): string | null =>
  BRANDS.find((b) => s.includes(b)) ?? null;

/** TLDs heavily overrepresented in abuse/phishing feeds.
 *  Tuning knob — expect churn in Phase 6 (PLAN.md threshold tuning).
 *  "zip"/"mov" included for file-extension confusion ("https://invoice.zip"). */
export const SUSPICIOUS_TLDS: ReadonlySet<string> = new Set([
  "xyz", "top", "gq", "tk", "ml", "cf", "ga", "click", "cam",
  "rest", "cfd", "sbs", "icu", "quest", "monster", "buzz",
  "zip", "mov",
]);

// ── confusables / skeleton ────────────────────────────────────────────────
// Base data is generated from Unicode UTS#39 (confusables.gen.ts) and covers
// ~1.4k lookalikes incl. fullwidth, math alphanumerics, Armenian, IPA.
// ASCII→ASCII entries in it ("0"→"o", "1"→"l") serve brand-skeleton matching
// only and are excluded from homoglyph detection by the >0x7f source check.

/** Local overrides beyond UTS#39, merged last so they win. Skeleton output
 *  feeds brand substring matching on lowercased hosts — that objective
 *  justifies deviating from the standard's general-purpose skeletons. */
const SKELETON_EXTRAS = new Map<string, string>([
  // Palochka: UTS#39 skeletons ӏ→ı→i, but in a lowercased domain it is
  // planted to fake "l" — аррӏе.com must unmask to apple.com. Homoglyph
  // detection is unaffected (key membership is identical either way).
  ["\u04CF", "l"],
]);

const CONFUSABLES = new Map([...UNICODE_CONFUSABLES, ...SKELETON_EXTRAS]);

/** The string as it visually appears: each confusable character replaced by
 *  the Latin character it impersonates, everything else untouched.
 *  Single-pass (no multi-char confusables like rn→m; the generated data is
 *  transitively closed, so one pass suffices). */
export function skeleton(s: string): string {
  return [...s].map((ch) => CONFUSABLES.get(ch) ?? ch).join("");
}

/** True when a non-ASCII confusable appears in a host with an all-ASCII TLD —
 *  the Latin-brand homograph registration pattern (аррӏе.com). Legit non-Latin
 *  domains register non-Latin TLDs (сайт.рф) and stay false.
 *  Known v1 false positive: a legit non-Latin word registered under .com. */
export function hasHomoglyph(host: string): boolean {
  const decoded = decodeHost(host);
  const tld = decoded.slice(decoded.lastIndexOf(".") + 1);
  const tldIsAscii =
    tld !== "" && [...tld].every((c) => c.codePointAt(0)! <= 0x7f);
  return (
    tldIsAscii &&
    [...decoded].some((c) => c.codePointAt(0)! > 0x7f && CONFUSABLES.has(c))
  );
}

// ── simple host helpers ───────────────────────────────────────────────────
const digitRatio = (host: string): number => {
  if (host.length === 0) return 0;

  let digits = 0;
  for (const ch of host) {
    if (ch >= "0" && ch <= "9") digits += 1;
  }
  return digits / host.length;
};

/** True when the host is a raw IP literal instead of a domain name.
 *  Octet-range strictness lives upstream: a numeric-ending host that fails
 *  IPv4 parsing makes the URL constructor itself throw (WHATWG). */
const isIpHost = (hostname: string): boolean => {
  if (hostname.startsWith("[")) return true; // IPv6 keeps brackets in .hostname
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
};

/** Per-character Shannon entropy of a string. Algorithmically generated
 *  hosts (DGAs) score ~3.7–4.5; english-like hosts ~2.5–3.
 *  Formula: H = -Σ p(c) · log₂ p(c) */
const shannonEntropy = (s: string): number => {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
};

// ── punycode (RFC 3492) ───────────────────────────────────────────────────
const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700;
const INITIAL_BIAS = 72, INITIAL_N = 128; // 0x80 = first non-ASCII code point

function decodeDigit(cp: number): number {
  if (cp >= 0x61 && cp <= 0x7a) return cp - 0x61; // a-z → 0-25
  if (cp >= 0x41 && cp <= 0x5a) return cp - 0x41; // A-Z → 0-25 (case-insensitive)
  if (cp >= 0x30 && cp <= 0x39) return cp - 0x30 + 26; // 0-9 → 26-35
  throw new Error(`invalid punycode digit: 0x${cp.toString(16)}`);
}

/** RFC 3492 §6.1 — bias adaptation. All divisions are integer (floor). */
function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  delta = firstTime ? Math.floor(delta / DAMP) : Math.floor(delta / 2);
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > Math.floor(((BASE - TMIN) * TMAX) / 2)) {
    delta = Math.floor(delta / (BASE - TMIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - TMIN + 1) * delta) / (delta + SKEW));
}

/** Decode one label WITHOUT the "xn--" prefix. RFC 3492 §6.2.
 *  Verified against Node's punycode oracle and RFC §7.1 vectors. */
export function decodePunycode(input: string): string {
  // 1. Everything before the LAST '-' is literal ASCII.
  const d = input.lastIndexOf("-");
  const basic = d > 0 ? input.slice(0, d) : "";
  const ext = input.slice(d + 1); // d === -1 ⇒ whole string is encoded part
  const output: number[] = [...basic].map((c) => c.codePointAt(0)!);

  let n = INITIAL_N, i = 0, bias = INITIAL_BIAS, p = 0;
  while (p < ext.length) {
    // 2. Read one variable-length integer into i.
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (p >= ext.length) throw new Error("truncated punycode");
      const digit = decodeDigit(ext.charCodeAt(p++)); // ext is pure ASCII
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break; // low digit terminates the integer
      w *= BASE - t;
    }
    // 3. Apply: insert code point n at position i (bias adaptation between rounds).
    bias = adapt(i - oldi, output.length + 1, oldi === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    output.splice(i, 0, n); // insert, don't overwrite
    i += 1;
  }
  return String.fromCodePoint(...output); // code-point array → handles emoji domains too
}

/** Host-level wrapper: decodePunycode's contract is one label, no prefix. */
export function decodeHost(host: string): string {
  return host.split(".")
    .map((l) => (l.startsWith("xn--") ? decodePunycode(l.slice(4)) : l))
    .join(".");
}

// ── the extractor ─────────────────────────────────────────────────────────
/** Pure URL → FeatureVector. No chrome.*, no I/O — unit-testable (NFR-7).
 *  Brand matching runs on the decoded + skeleton host so homograph attacks
 *  (xn--80ak6aa92e.com) resolve to their apparent form (apple.com). */
export const extractFeatures = (u: URL): FeatureVector => {
  const host = u.hostname.toLowerCase();
  const labels = host.split(".");

  return {
    url_length: u.href.length,
    path_depth: u.pathname.split("/").filter(Boolean).length,
    query_length: u.search.length,
    has_credentials: u.username !== "",
    hyphen_count: (host.match(/-/g) ?? []).length,
    digit_ratio: digitRatio(host),
    subdomain_depth: Math.max(0, labels.length - 2), // naive; co.uk counts wrong — v1 caveat
    tld_suspicious: SUSPICIOUS_TLDS.has(labels[labels.length - 1]),
    ip_host: isIpHost(u.hostname),
    punycode: labels.some((l) => l.startsWith("xn--")),
    host_entropy: shannonEntropy(host),
    homoglyph: hasHomoglyph(host),
    brand_in_host: findBrand(skeleton(decodeHost(host))),
    brand_in_path: findBrand(u.pathname.toLowerCase()),
  };
};
