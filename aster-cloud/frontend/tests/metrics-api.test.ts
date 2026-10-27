import { describe, expect, it, vi } from "vitest";
import {
  createApiClient,
  metricObservedNanos,
  metricsResponse,
  validMetrics,
} from "../src/api/client";
import {
  metricCounter,
  metricCPUTime,
  metricTimeText,
} from "../src/metrics-format";
import { instance, metrics } from "./fixtures";
const counters = [
  "cpu_time_ns",
  "memory_rss_kib",
  "memory_actual_kib",
  "memory_unused_kib",
  "block_read_bytes",
  "block_write_bytes",
  "network_receive_bytes",
  "network_transmit_bytes",
] as const;

describe("complete, identity-bound metrics contracts", () => {
  it("accepts all uint64 strings without converting them to JSON numbers", () => {
    const guard = metricsResponse(instance);
    expect(validMetrics(metrics)).toBe(true);
    expect(guard({ metrics })).toBe(true);
    expect(metrics.block_read_bytes).toBe("9007199254740993");
    expect(metrics.block_write_bytes).toBe("18446744073709551615");
  });
  it.each(Object.keys(metrics))("requires explicit field %s", (key) => {
    const value: Record<string, unknown> = { ...metrics };
    delete value[key];
    expect(validMetrics(value)).toBe(false);
  });
  it.each(counters)("accepts explicit null and zero for %s", (key) => {
    expect(validMetrics({ ...metrics, [key]: null })).toBe(true);
    expect(validMetrics({ ...metrics, [key]: "0" })).toBe(true);
    expect(validMetrics({ ...metrics, [key]: undefined })).toBe(false);
    expect(validMetrics({ ...metrics, [key]: 0 })).toBe(false);
  });
  it.each([
    "",
    "00",
    "01",
    "+1",
    "-1",
    " 1",
    "1 ",
    "1.0",
    "1e3",
    "0xff",
    "18446744073709551616",
    "99999999999999999999999999999999",
    "１",
    "1\n",
  ])("rejects non-canonical or overflowing counter %j", (value) => {
    for (const key of counters)
      expect(validMetrics({ ...metrics, [key]: value }), key).toBe(false);
  });
  it.each([0, -1, 1.5, 4097, "2", null, Number.MAX_SAFE_INTEGER + 1, Infinity])(
    "rejects invalid vCPU %j",
    (vcpus) => expect(validMetrics({ ...metrics, vcpus })).toBe(false),
  );
  it("allows the protocol maximum of 4096 vCPUs but still binds it to the page", () => {
    expect(validMetrics({ ...metrics, vcpus: 4096 })).toBe(true);
    expect(
      metricsResponse(instance)({ metrics: { ...metrics, vcpus: 4096 } }),
    ).toBe(false);
  });
  it.each(["extra", "Node_ID", "CPU_Time_NS"])(
    "rejects the unexpected field %s rather than silently weakening the contract",
    (key) => {
      expect(validMetrics({ ...metrics, [key]: "ignored" })).toBe(false);
    },
  );
  it.each([
    "running",
    "shutoff",
    "paused",
    "in_shutdown",
    "crashed",
    "pmsuspended",
    "idle",
    "blocked",
  ])("accepts normalized node state %s", (state) =>
    expect(validMetrics({ ...metrics, state })).toBe(true),
  );
  it.each(["Running", "unknown", "succeeded", "", ["running"], null])(
    "rejects invalid state %j",
    (state) => expect(validMetrics({ ...metrics, state })).toBe(false),
  );
  it.each([
    "2026-10-23T04:00:00Z",
    "2026-10-23T04:00:00.1Z",
    "2026-10-23T04:00:00.123456789Z",
    "2024-02-29T04:00:00Z",
  ])("accepts strict UTC-Z RFC3339Nano sample time %s", (observed_at) =>
    expect(validMetrics({ ...metrics, observed_at })).toBe(true),
  );
  it.each([
    "2026-02-30T04:00:00Z",
    "2026-02-29T04:00:00Z",
    "2026-00-01T04:00:00Z",
    "2026-13-01T04:00:00Z",
    "2026-10-23T24:00:00Z",
    "2026-10-23T04:60:00Z",
    "2026-10-23T04:00:60Z",
    "2026-10-23T04:00:00+24:00",
    "2026-10-23T04:00:00+00:60",
    "2026-10-23T04:00:00+00:00",
    "2026-10-23T12:00:00.123456789+08:00",
    "2026-10-23T01:00:00-03:00",
    "2026-10-23T04:00:00,123Z",
    "2026-10-23T4:00:00Z",
    "2026-10-23T04:00:00.1234567890Z",
    "2026-10-23 04:00:00Z",
    "2026-10-23T04:00:00",
    "0000-01-01T00:00:00Z",
    "2026-10-23T04:00:00Z\n",
    "not a time",
    null,
  ])("rejects malformed or normalized date %j", (observed_at) =>
    expect(validMetrics({ ...metrics, observed_at })).toBe(false),
  );
  it.each(["instance_id", "node_id", "owner_ref", "hostname"] as const)(
    "rejects a different %s before it reaches the component",
    (key) => {
      expect(
        metricsResponse(instance)({ metrics: { ...metrics, [key]: "other" } }),
      ).toBe(false);
      expect(validMetrics({ ...metrics, [key]: "" })).toBe(false);
    },
  );
  it("binds vCPU and captures the immutable request identity", () => {
    expect(
      metricsResponse(instance)({ metrics: { ...metrics, vcpus: 4 } }),
    ).toBe(false);
    const expected = structuredClone(instance),
      guard = metricsResponse(expected);
    expected.id = "f".repeat(32);
    expected.resources.cpu_cores = 4;
    expect(guard({ metrics })).toBe(true);
    expect(
      guard({ metrics: { ...metrics, instance_id: expected.id, vcpus: 4 } }),
    ).toBe(false);
  });
  it("rejects a protocol mismatch or missing metrics wrapper", () => {
    expect(
      validMetrics({ ...metrics, protocol: "aster.node.instance/1" }),
    ).toBe(false);
    expect(metricsResponse(instance)(metrics)).toBe(false);
    expect(metricsResponse(instance)({ metrics: null })).toBe(false);
    expect(metricsResponse(instance)({ metrics, extra: true })).toBe(false);
  });
  it("uses only the real same-origin GET and rejects a wrongly bound response", async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({ metrics: { ...metrics, node_id: "other" } }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        },
      ),
    );
    await expect(
      createApiClient(fetcher).get(
        `/instances/${instance.id}/metrics`,
        metricsResponse(instance),
      ),
    ).rejects.toMatchObject({ kind: "invalid" });
    expect(fetcher).toHaveBeenCalledOnce();
    expect(fetcher.mock.calls[0]).toMatchObject([
      `/console/v1/instances/${instance.id}/metrics`,
      { method: "GET", credentials: "same-origin", cache: "no-store" },
    ]);
  });
});

describe("lossless metrics formatting", () => {
  it("does not round counters beyond Number.MAX_SAFE_INTEGER", () => {
    expect(metricCounter("9007199254740993", "B", "en")).toBe(
      "9,007,199,254,740,993 B",
    );
    expect(metricCounter("18446744073709551615", "KiB", "zh-CN")).toBe(
      "18,446,744,073,709,551,615 KiB",
    );
  });
  it("keeps CPU nanosecond precision in a seconds label", () => {
    expect(metricCPUTime("1000000001", "en")).toBe("1.000000001 s");
    expect(metricCPUTime("18446744073709551615", "en")).toBe(
      "18,446,744,073.709551615 s",
    );
    expect(metricCPUTime("1000000000", "zh-CN")).toBe("1 s");
    expect(metricCPUTime("0", "zh-CN")).toBe("0 s");
  });
  it("distinguishes absent values from actual zero in both languages", () => {
    expect(metricCounter(null, "B", "en")).toBe("Not reported");
    expect(metricCounter(null, "KiB", "zh-CN")).toBe("未提供");
    expect(metricCounter("0", "B", "en")).toBe("0 B");
    expect(metricCPUTime(null, "zh-CN")).toBe("未提供");
  });
  it("shows seconds with an explicit UTC zone rather than a misleading local time", () => {
    expect(metricTimeText("2026-10-23T12:00:01+08:00", "en")).toContain(
      "04:00:01",
    );
    expect(metricTimeText(metrics.observed_at, "zh-CN")).toContain("UTC");
  });
  it("keeps nanosecond timestamps exact and rejects non-Z offsets", () => {
    const base = metricObservedNanos("2026-10-23T04:00:00Z")!;
    expect(metricObservedNanos("2026-10-23T04:00:00.000000001Z")).toBe(
      base + 1n,
    );
    expect(
      metricObservedNanos("2026-10-23T12:00:00.000000001+08:00"),
    ).toBeNull();
    expect(
      metricObservedNanos("2026-10-23T01:00:00.000000001-03:00"),
    ).toBeNull();
  });
});
