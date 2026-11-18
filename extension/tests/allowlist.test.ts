import { describe, expect, it } from "vitest";
import { isAllowed } from "../src/background/allowlist";
import { TRANCO } from "../src/background/tranco.gen";

describe("isAllowed — suffix walk (injected fixture)", () => {
  const set = new Set(["example.com", "bbc.co.uk", "t.co"]);

  it("matches apex and subdomains", () => {
    expect(isAllowed("example.com", set)).toBe(true);
    expect(isAllowed("www.example.com", set)).toBe(true);
    expect(isAllowed("a.b.c.example.com", set)).toBe(true);
  });

  it("does not match lookalike or sibling domains", () => {
    expect(isAllowed("notexample.com", set)).toBe(false); // not a suffix boundary
    expect(isAllowed("example.com.evil.xyz", set)).toBe(false); // suffix ≠ endsWith
    expect(isAllowed("bbc.com", set)).toBe(false); // sibling, not child
  });

  it("is case-insensitive", () => {
    expect(isAllowed("WWW.Example.COM", set)).toBe(true);
  });
});

describe("isAllowed — real Tranco data (list pinned in tranco.gen.ts)", () => {
  it("top sites and their subdomains are allowed", () => {
    expect(isAllowed("google.com")).toBe(true);
    expect(isAllowed("news.bbc.co.uk")).toBe(true);
    expect(isAllowed("en.wikipedia.org")).toBe(true);
  });

  it("an unranked host is not allowed", () => {
    expect(isAllowed("definitely-not-in-top-20k-zq.example")).toBe(false);
  });
});
