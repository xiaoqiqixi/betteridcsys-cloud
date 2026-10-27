import type { Locale } from "./composables/preferences";

export function metricCounter(
  value: string | null,
  unit: "B" | "KiB",
  locale: Locale,
) {
  if (value === null) return locale === "en" ? "Not reported" : "未提供";
  return `${new Intl.NumberFormat(locale).format(BigInt(value))} ${unit}`;
}

export function metricCPUTime(value: string | null, locale: Locale) {
  if (value === null) return locale === "en" ? "Not reported" : "未提供";
  const nanos = BigInt(value),
    seconds = nanos / 1000000000n,
    fraction = (nanos % 1000000000n)
      .toString()
      .padStart(9, "0")
      .replace(/0+$/, "");
  return `${new Intl.NumberFormat(locale).format(seconds)}${fraction ? `.${fraction}` : ""} s`;
}

export function metricTimeText(raw: string, locale: Locale) {
  return new Intl.DateTimeFormat(locale === "en" ? "en-GB" : "zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "UTC",
    timeZoneName: "short",
  }).format(new Date(raw));
}
