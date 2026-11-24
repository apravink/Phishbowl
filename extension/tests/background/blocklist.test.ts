import { describe, expect, it } from "vitest";
import {
  matchBlocked,
  mergeBlocklist,
  parseOpenPhishFeed,
} from "../../src/background/blocklist";

describe("parseOpenPhishFeed", () => {
  it("resolves URL lines to lowercase hosts, preserving feed order", () => {
    const feed = [
      "http://Phish-Alpha.example/login",
      "https://phish-beta.example/webscr",
      "http://phish-alpha.example/other",
    ].join("\n");
    expect(parseOpenPhishFeed(feed)).toEqual([
      "phish-alpha.example",
      "phish-beta.example",
    ]);
  });

  it("strips trailing comma-separated metadata columns", () => {
    const feed = "http://x.example/a,MyBrand,1700000123,attack_id\n";
    expect(parseOpenPhishFeed(feed)).toEqual(["x.example"]);
  });

  it("skips junk, comments, and non-http(s) lines without losing the rest", () => {
    const feed = [
      "not a url",
      "# comment",
      "",
      "ftp://x.example/file",
      "http://good.example/",
    ].join("\n");
    expect(parseOpenPhishFeed(feed)).toEqual(["good.example"]);
  });

  it("produces an empty list from an empty feed", () => {
    expect(parseOpenPhishFeed("")).toEqual([]);
  });
});

describe("matchBlocked — label walk (injected fixture)", () => {
  const set = new Set(["evil.example", "bad.co.uk"]);

  it("matches the exact host and subdomains", () => {
    expect(matchBlocked("evil.example", set)).toBe("evil.example");
    expect(matchBlocked("login.evil.example", set)).toBe("evil.example");
  });

  it("does not match lookalikes or reparented hosts", () => {
    expect(matchBlocked("notevil.example", set)).toBeNull();
    expect(matchBlocked("evil.example.attacker.io", set)).toBeNull();
    expect(matchBlocked("good.example", set)).toBeNull();
  });

  it("is case-insensitive", () => {
    expect(matchBlocked("LOGIN.EVIL.EXAMPLE", set)).toBe("evil.example");
  });

  it("returns the most specific match first (full host before parents)", () => {
    const both = new Set(["evil.example", "a.evil.example"]);
    expect(matchBlocked("a.evil.example", both)).toBe("a.evil.example");
  });
});

describe("mergeBlocklist — cap + eviction (REQ-2)", () => {
  it("unions stored and fresh, deduping, when under the cap", () => {
    const merged = mergeBlocklist(
      ["old-a.example", "kept.example"],
      ["kept.example", "new-b.example"],
      new Map(),
      10,
    );
    expect(merged).toEqual(["old-a.example", "kept.example", "new-b.example"]);
  });

  it("evicts lowest hit-count first when over the cap", () => {
    const stored = ["cold.example", "hot.example"];
    const fresh = ["new.example"];
    const hits = new Map([["hot.example", 5]]);
    expect(mergeBlocklist(stored, fresh, hits, 2)).toEqual([
      "hot.example",
      "new.example",
    ]);
  });

  it("breaks hit-count ties by age: older (earlier) entries evict first", () => {
    const stored = ["oldest.example", "younger.example"];
    const fresh = ["new.example"];
    expect(mergeBlocklist(stored, fresh, new Map(), 2)).toEqual([
      "younger.example",
      "new.example",
    ]);
  });

  it("respects the cap exactly under pressure from both sides", () => {
    const stored = ["s1", "s2", "s3"];
    const fresh = ["f1", "f2"];
    const merged = mergeBlocklist(stored, fresh, new Map([["s2", 1]]), 4);
    expect(merged).toHaveLength(4);
    expect(merged).toContain("s2"); // only locally-hot survivor
    expect(merged).toContain("f1");
    expect(merged).toContain("f2");
  });
});
