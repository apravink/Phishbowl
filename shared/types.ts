export type VerdictKind = 'clean' | 'suspicious' | 'phishing' | 'unverified';
export type SourceType = 'allowlist'|'blocklist'|'prefilter'|'gsb'|'jev'|'error';

export type Verdict = {
    kind:VerdictKind;
    source: SourceType;
    reason: string;
    brand?: string;
    p?: number
    confidence?: number;
    ts: number;
}

export type FeatureVector = {
      // — host shape —
  host_entropy: number;         // Shannon entropy of hostname chars (~0–4.7)
  subdomain_depth: number;      // number of labels beyond the registrable domain
  hyphen_count: number;         // hyphens in the host (not the whole URL)
  digit_ratio: number;          // fraction of digits in host, 0–1
  tld_suspicious: boolean;      // TLD ∈ {xyz, top, zip, mov, gq, tk, ...}
  ip_host: boolean;             // host is an IPv4/IPv6 literal
  punycode: boolean;            // raw host contained an xn-- label
  homoglyph: boolean;           // decoded host has confusables (а→a, р→p...)

  // — brand signals —
  brand_in_host: string | null; // matched brand token, e.g. "paypal"; null if none
  brand_in_path: string | null;

  // — URL shape —
  url_length: number;           // full href length
  path_depth: number;           // '/'-separated segments in pathname
  has_credentials: boolean;     // user:pass@ prefix (classic obfuscation)
  query_length: number;         // search string length incl. "?"
}

