import { describe, expect, it } from "vitest";
import {
  auditRequestPath,
  auditRouteQuery,
  auditUTCTime,
  emptyAuditFilters,
  parseAuditQuery,
} from "../src/audit-query";

describe("exact audit query contract", () => {
  it("defaults to no filters without sending explicit empty values", () => {
    const parsed = parseAuditQuery({});
    expect(parsed.error).toBeNull();
    expect(parsed.filters).toEqual(emptyAuditFilters());
    expect(auditRequestPath(parsed)).toBe("/audit");
    expect(auditRouteQuery(parsed.filters)).toEqual({});
  });
  it("preserves exact case, unlisted action codes and opaque cursor bytes", () => {
    const cursor = "opaque~!x'()*.:-_";
    const parsed = parseAuditQuery({
      source: "resource",
      action: "Vendor.New_Action:1",
      actor: "user:ABC",
      target: "Node-A",
      cursor,
    });
    expect(parsed.error).toBeNull();
    expect(parsed.filters.action).toBe("Vendor.New_Action:1");
    expect(parsed.filters.actor).toBe("user:ABC");
    expect(parsed.cursor).toBe(cursor);
    const path = auditRequestPath(parsed)!;
    expect(path).toBe(
      "/audit?source=resource&action=Vendor.New_Action%3A1&actor=user%3AABC&target=Node-A&cursor=opaque%7E%21x%27%28%29%2A.%3A-_",
    );
    expect(path).toMatch(/^\/[a-z0-9/?=&_%.-]+$/i);
  });
  it.each([
    [{ source: "all" }, "source"],
    [{ source: "" }, "source"],
    [{ action: ["identity.login"] }, "action"],
    [{ actor: null }, "actor"],
    [{ actor: " user:ABC" }, "actor"],
    [{ actor: "user:ABC " }, "actor"],
    [{ target: "one two" }, "target"],
    [{ action: "identity.%" }, "action"],
    [{ action: "操作" }, "action"],
    [{ action: "A".repeat(65) }, "action"],
    [{ actor: "A".repeat(81) }, "actor"],
    [{ target: "A".repeat(129) }, "target"],
    [{ cursor: "" }, "cursor"],
    [{ cursor: "x".repeat(1025) }, "cursor"],
    [{ cursor: "a\nb" }, "cursor"],
    [{ cursor: "非ASCII" }, "cursor"],
    [{ limit: "200" }, "query"],
  ] as const)(
    "rejects invalid input %j without constructing a request",
    (query, field) => {
      const parsed = parseAuditQuery(query);
      expect(parsed.error?.field).toBe(field);
      expect(auditRequestPath(parsed)).toBeNull();
    },
  );
  it("does not carry a prior cursor into edited filters", () => {
    const before = parseAuditQuery({ action: "identity.login", cursor: "old" });
    expect(
      auditRouteQuery({ ...before.filters, action: "identity.logout" }),
    ).toEqual({ action: "identity.logout" });
  });
  it("keeps even maximum-length escaped fields inside the server query budget", () => {
    const parsed = parseAuditQuery({
      actor: ":".repeat(79).padStart(80, "A"),
      target: ":".repeat(127).padStart(128, "A"),
      cursor: "!".repeat(1024),
      action: ":".repeat(63).padStart(64, "A"),
      from: "2026-10-23T00:00:00.123456Z",
      until: "2026-10-24T00:00:00.123456Z",
      source: "resource",
    });
    expect(parsed.error).toBeNull();
    expect(
      auditRequestPath(parsed)!.slice("/audit?".length).length,
    ).toBeLessThanOrEqual(4096);
  });
});

describe("microsecond UTC audit boundaries", () => {
  it("applies the year lower bound after UTC conversion, like the Go contract", () => {
    expect(auditUTCTime("0999-12-31T23:59:59.123456-00:01")?.utc).toBe(
      "1000-01-01T00:00:59.123456Z",
    );
    expect(
      parseAuditQuery({ from: "0999-12-31T23:59:59-00:01" }).error,
    ).toBeNull();
  });
  it("normalizes explicit offsets without losing six fractional digits", () => {
    const before = auditUTCTime("2026-10-23T08:00:00.123456+08:00");
    const after = auditUTCTime("2026-10-23T00:00:00.123457Z");
    expect(before?.utc).toBe("2026-10-23T00:00:00.123456Z");
    expect(after!.micros - before!.micros).toBe(1n);
    expect(auditUTCTime("2026-10-22T17:30:00.120000-06:30")?.utc).toBe(
      "2026-10-23T00:00:00.12Z",
    );
  });
  it("accepts a one-microsecond [from,until) interval", () => {
    const parsed = parseAuditQuery({
      from: "2026-10-23T00:00:00.123456Z",
      until: "2026-10-23T00:00:00.123457Z",
    });
    expect(parsed.error).toBeNull();
  });
  it.each([
    "2026-02-30T00:00:00Z",
    "2025-02-29T00:00:00Z",
    "2026-10-23",
    "2026-10-23T00:00:00",
    "2026-10-23T24:00:00Z",
    "2026-10-23T00:60:00Z",
    "2026-10-23T00:00:60Z",
    "2026-10-23T00:00:00.1234567Z",
    "2026-10-23T00:00:00+24:00",
    "2026-10-23T00:00:00+00:60",
    "0999-12-31T00:00:00Z",
    "0000-01-01T00:00:00Z",
    "0026-10-23T00:00:00Z",
    "0099-12-31T23:59:59-00:01",
    "1000-01-01T00:00:00+00:01",
    "9999-12-31T23:59:59-00:01",
    " 2026-10-23T00:00:00Z",
    "2026-10-23t00:00:00z",
  ])("rejects invalid or timezone-ambiguous time %s", (raw) => {
    expect(auditUTCTime(raw)).toBeNull();
    expect(parseAuditQuery({ from: raw }).error?.field).toBe("from");
  });
  it.each([
    ["2026-10-23T00:00:00Z", "2026-10-23T08:00:00+08:00"],
    ["2026-10-23T00:00:00.123457Z", "2026-10-23T00:00:00.123456Z"],
  ])("rejects equal or reversed UTC intervals %s — %s", (from, until) => {
    expect(parseAuditQuery({ from, until }).error).toEqual({
      field: "until",
      reason: "range",
    });
  });
});
