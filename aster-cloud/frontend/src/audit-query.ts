// Audit filters are exact matches. Keep their wire representation independent
// of translated labels, local dates and the opaque server-owned cursor.
export const auditFilterKeys = [
  "source",
  "action",
  "actor",
  "target",
  "from",
  "until",
] as const;
export type AuditFilterKey = (typeof auditFilterKeys)[number];
export type AuditFilters = Record<AuditFilterKey, string>;
export interface AuditQueryError {
  field: AuditFilterKey | "cursor" | "query";
  reason: "unknown" | "single" | "empty" | "format" | "length" | "range";
}
export interface AuditQuery {
  filters: AuditFilters;
  cursor: string;
  error: AuditQueryError | null;
}
export function emptyAuditFilters(): AuditFilters {
  return { source: "", action: "", actor: "", target: "", from: "", until: "" };
}
function encode(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*~]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

// Date handles whole seconds safely in this year range; BigInt preserves the
// complete microsecond boundary instead of rounding it to JS milliseconds.
export function auditUTCTime(
  raw: string,
): { utc: string; micros: bigint } | null {
  const parts =
    /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,6}))?(Z|[+-]\d\d:\d\d)$/.exec(
      raw,
    );
  if (!parts) return null;
  const year = Number(parts[1]),
    month = Number(parts[2]),
    day = Number(parts[3]),
    hour = Number(parts[4]),
    minute = Number(parts[5]),
    second = Number(parts[6]),
    fraction = parts[7] || "",
    zone = parts[8]!;
  if (
    // Only raw year 0999 can cross into valid UTC year 1000 via an offset.
    // Reject earlier years before Date.UTC's special mapping of years 0..99.
    year < 999 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > 31 ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  )
    return null;
  const local = Date.UTC(year, month - 1, day, hour, minute, second),
    calendar = new Date(local);
  if (
    calendar.getUTCFullYear() !== year ||
    calendar.getUTCMonth() !== month - 1 ||
    calendar.getUTCDate() !== day
  )
    return null;
  let offset = 0;
  if (zone !== "Z") {
    const zoneHour = Number(zone.slice(1, 3)),
      zoneMinute = Number(zone.slice(4, 6));
    if (zoneHour > 23 || zoneMinute > 59) return null;
    offset = (zoneHour * 60 + zoneMinute) * 60000 * (zone[0] === "+" ? 1 : -1);
  }
  const milliseconds = local - offset,
    utcDate = new Date(milliseconds);
  if (utcDate.getUTCFullYear() < 1000 || utcDate.getUTCFullYear() > 9999)
    return null;
  const significant = fraction.replace(/0+$/, "");
  return {
    utc:
      utcDate.toISOString().slice(0, 19) +
      (significant ? `.${significant}` : "") +
      "Z",
    micros:
      BigInt(milliseconds) * 1000n + BigInt(fraction.padEnd(6, "0") || "0"),
  };
}
export function parseAuditQuery(
  query: Readonly<Record<string, unknown>>,
): AuditQuery {
  const filters = emptyAuditFilters();
  let cursor = "",
    error: AuditQueryError | null = null;
  const fail = (
    field: AuditQueryError["field"],
    reason: AuditQueryError["reason"],
  ) => {
    error ||= { field, reason };
  };
  for (const key of Object.keys(query)) {
    if (![...auditFilterKeys, "cursor"].includes(key)) {
      fail("query", "unknown");
      continue;
    }
    const field = key as AuditFilterKey | "cursor",
      value = query[key];
    if (typeof value !== "string") {
      fail(field, "single");
      continue;
    }
    if (field === "cursor") cursor = value;
    else filters[field] = value;
    if (!value) {
      fail(field, "empty");
      continue;
    }
    if (field === "source") {
      if (value !== "identity" && value !== "resource") fail(field, "format");
    } else if (field === "cursor") {
      if (value.length > 1024) fail(field, "length");
      else if (!/^[\x20-\x7e]+$/.test(value)) fail(field, "format");
    } else if (field === "from" || field === "until") {
      const time = auditUTCTime(value);
      if (!time) fail(field, "format");
      else filters[field] = time.utc;
    } else {
      if (value.length > { action: 64, actor: 80, target: 128 }[field])
        fail(field, "length");
      else if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(value))
        fail(field, "format");
    }
  }
  if (filters.from && filters.until) {
    const from = auditUTCTime(filters.from),
      until = auditUTCTime(filters.until);
    if (from && until && from.micros >= until.micros) fail("until", "range");
  }
  const result: AuditQuery = { filters, cursor, error };
  if (!error && auditQueryString(result).length > 4096)
    result.error = { field: "query", reason: "length" };
  return result;
}
export function auditRouteQuery(
  filters: AuditFilters,
  cursor = "",
): Record<string, string> {
  return Object.fromEntries([
    ...auditFilterKeys
      .filter((key) => filters[key] !== "")
      .map((key) => [key, filters[key]]),
    ...(cursor ? [["cursor", cursor]] : []),
  ]);
}
function auditQueryString(query: AuditQuery): string {
  return Object.entries(auditRouteQuery(query.filters, query.cursor))
    .map(([key, value]) => `${key}=${encode(value)}`)
    .join("&");
}
export function auditRequestPath(query: AuditQuery): string | null {
  if (query.error) return null;
  const parameters = auditQueryString(query);
  return `/audit${parameters ? `?${parameters}` : ""}`;
}
