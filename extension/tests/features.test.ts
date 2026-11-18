import { describe, expect, it } from "vitest";
import {
  decodeHost,
  decodePunycode,
  extractFeatures,
  skeleton,
} from "../src/background/features";

const f = (href: string) => extractFeatures(new URL(href));

// The canonical apple.com homograph, fully Cyrillic incl. palochka U+04CF.
// Written as escapes on purpose: typing lookalikes by hand is how the wrong
// codepoint sneaks into a test.
const APPLE_HOMOGRAPH = "\u0430\u0440\u0440\u04CF\u0435.com"; // аррӏе.com
const CYRILLIC_IDN = "\u0441\u0430\u0439\u0442.\u0440\u0444"; // сайт.рф

describe("extractFeatures — URL shape", () => {
  it("url_length counts the full serialized href", () => {
    expect(f("https://a.com/").url_length).toBe(14);
  });

  it("path_depth ignores empty segments from leading/trailing slashes", () => {
    expect(f("https://a.com/x/y/").path_depth).toBe(2);
    expect(f("https://a.com").path_depth).toBe(0);
  });

  it("query_length includes the '?'", () => {
    expect(f("https://a.com/?x=1&y=2").query_length).toBe(8);
  });

  it("flags credential obfuscation (address bar hides everything before @)", () => {
    expect(f("https://paypal.com@evil.xyz/login").has_credentials).toBe(true);
    expect(f("https://evil.xyz/login").has_credentials).toBe(false);
  });
});

describe("extractFeatures — host shape", () => {
  it("digit ratio counts every digit char in the host", () => {
    expect(f("https://google.com/").digit_ratio).toBe(0);
    expect(f("https://w3.10.school/").digit_ratio).toBeCloseTo(3 / 12);
    expect(f("https://paypal-secure123.com/").digit_ratio).toBeCloseTo(3 / 20);
  });

  it("hyphen count is host-scoped, not URL-scoped", () => {
    expect(f("https://secure-login-verify.com/").hyphen_count).toBe(2);
  });

  it("subdomain depth (naive labels-2)", () => {
    expect(f("https://example.com/").subdomain_depth).toBe(0);
    expect(f("https://a.b.c.example.com/").subdomain_depth).toBe(3);
  });

  it("suspicious TLDs", () => {
    expect(f("https://account-paypal.xyz/").tld_suspicious).toBe(true);
    expect(f("https://invoice.zip/download").tld_suspicious).toBe(true);
    expect(f("https://en.wikipedia.org/").tld_suspicious).toBe(false);
    expect(f("https://bbc.co.uk/").tld_suspicious).toBe(false); // last label is "uk"
  });

  it("IP hosts", () => {
    expect(f("http://192.168.0.1/login").ip_host).toBe(true);
    expect(f("http://[2001:db8::1]/").ip_host).toBe(true);
    expect(f("https://1-2-3-4.xyz/").ip_host).toBe(false); // IP-shaped, but a domain
  });

  it("entropy: algorithmic >> english-like", () => {
    expect(f("https://x7fjq2bmakp.net/").host_entropy).toBeGreaterThan(
      f("https://www.wikipedia.org/").host_entropy,
    );
  });
});

describe("punycode (RFC 3492)", () => {
  it("decodes §7.1 test vectors", () => {
    expect(decodePunycode("bcher-kva")).toBe("bücher");
    expect(decodePunycode("3B-ww4c5e180e575a65lsy2b")).toBe("3年B組金八先生");
    // (D) — "word breaks and punctuation have been removed"
    expect(decodePunycode("Proprostnemluvesky-uyb24dma41a")).toBe(
      "Pročprostěnemluvíčesky",
    );
  });

  it("host-level wrapper decodes only xn-- labels", () => {
    expect(decodeHost("xn--bcher-kva.de")).toBe("bücher.de");
    expect(decodeHost("xn--80ak6aa92e.com")).toBe(APPLE_HOMOGRAPH);
    expect(decodeHost("plain.example.com")).toBe("plain.example.com");
  });

  it("round-trips a legit Cyrillic IDN", () => {
    expect(decodeHost("xn--80aswg.xn--p1ai")).toBe(CYRILLIC_IDN);
  });
});

describe("homoglyph + brand", () => {
  it("skeleton unmasks lookalikes", () => {
    expect(skeleton(decodeHost("xn--80ak6aa92e.com"))).toBe("apple.com");
    expect(skeleton("paypa1.com")).toBe("paypal.com"); // digit 1 → l
    expect(skeleton("google.com")).toBe("google.com"); // inert on clean input
  });

  it("detects the classic homograph attack end-to-end", () => {
    expect(f("https://xn--80ak6aa92e.com/")).toMatchObject({
      punycode: true,
      homoglyph: true,
      brand_in_host: "apple",
    });
  });

  it("legit Cyrillic IDNs are not flagged — non-Latin TLD", () => {
    expect(f("https://xn--80aswg.xn--p1ai/").homoglyph).toBe(false);
  });

  it("documents the guard's trade-off: Cyrillic word under .com IS flagged", () => {
    // сайт.com — legit-ish registration, indistinguishable from an attack
    // on Latin readers. Accepted v1 false positive; see hasHomoglyph comment.
    expect(f("https://xn--80aswg.com/").homoglyph).toBe(true);
  });

  it("brand matching", () => {
    expect(f("https://apple.com/").brand_in_host).toBe("apple");
    expect(f("https://example.com/paypal/login").brand_in_path).toBe("paypal");
    expect(f("https://example.com/").brand_in_host).toBeNull();
  });
});
