import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { nextTick } from "vue";
import { ApiError } from "../src/api/client";
import { consoleKey } from "../src/context";
import InstanceMetricsPanel from "../src/components/InstanceMetricsPanel.vue";
import StatusBadge from "../src/components/StatusBadge.vue";
import { instance, metrics } from "./fixtures";
import { deferred, mockContext } from "./helpers";

const wrappers: Array<{ unmount: () => void }> = [];
function panel(resolver: Parameters<typeof mockContext>[0]) {
  const result = mockContext(resolver);
  const wrapper = mount(InstanceMetricsPanel, {
    props: { instance: structuredClone(instance) },
    global: { provide: { [consoleKey as symbol]: result.context } },
  });
  wrappers.push(wrapper);
  return { ...result, wrapper };
}
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date", "setTimeout", "clearTimeout"] });
  vi.setSystemTime("2026-10-23T04:00:01Z");
});
afterEach(() => {
  wrappers.splice(0).forEach((wrapper) => wrapper.unmount());
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("manual, read-only instance metrics", () => {
  it("starts unsampled, then makes exactly one GET with accurate counters and no chart", async () => {
    const resolver = vi.fn(() => ({ metrics }));
    const { wrapper, calls } = panel(resolver);
    expect(resolver).not.toHaveBeenCalled();
    expect(wrapper.text()).toContain("未采样");
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(resolver).toHaveBeenCalledExactlyOnceWith(
      "GET",
      `/instances/${instance.id}/metrics`,
      undefined,
      "",
    );
    expect(calls).toHaveLength(0);
    expect(wrapper.text()).toContain("1.000000001 s");
    expect(wrapper.text()).toContain("9,007,199,254,740,993 B");
    expect(wrapper.text()).toContain("18,446,744,073,709,551,615 B");
    expect(wrapper.text()).toContain("0 KiB");
    expect(wrapper.text()).toContain("当前分配内存");
    expect(wrapper.text()).not.toContain("气球实际值");
    expect(wrapper.text()).toContain("未提供");
    expect(wrapper.text()).toContain("网络计数不是账单流量");
    expect(wrapper.text()).toContain("RSS 也不是客户机内存使用率");
    expect(wrapper.find("time").attributes("datetime")).toBe(
      metrics.observed_at,
    );
    expect(wrapper.getComponent(StatusBadge).props("state")).toBe("running");
    expect(wrapper.find("canvas,svg[role=img]").exists()).toBe(false);
    await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
    expect(resolver).toHaveBeenCalledOnce();
    expect(calls).toHaveLength(0);
  });
  it("shows busy feedback, blocks repeated reads and never fabricates zeros while loading", async () => {
    const request = deferred<unknown>(),
      resolver = vi.fn(() => request.promise);
    const { wrapper } = panel(resolver);
    await wrapper.get("button").trigger("click");
    expect(wrapper.attributes("aria-busy")).toBe("true");
    expect(wrapper.get("button").attributes("disabled")).toBeDefined();
    expect(wrapper.text()).toContain("正在读取");
    expect(wrapper.find(".metrics-skeleton").exists()).toBe(true);
    expect(wrapper.find("dl").exists()).toBe(false);
    await wrapper.get("button").trigger("click");
    expect(resolver).toHaveBeenCalledOnce();
    request.resolve({ metrics });
    await flushPromises();
    expect(wrapper.attributes("aria-busy")).toBeUndefined();
    expect(wrapper.find(".metrics-skeleton").exists()).toBe(false);
  });
  it("clears a previous sample before rereading and on failure without a cached-state fallback", async () => {
    const request = deferred<unknown>();
    let first = true;
    const { wrapper } = panel(() => {
      if (first) {
        first = false;
        return { metrics };
      }
      return request.promise;
    });
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(wrapper.find("dl").exists()).toBe(true);
    await wrapper.get("button").trigger("click");
    expect(wrapper.find("dl").exists()).toBe(false);
    request.reject(new ApiError("network"));
    await flushPromises();
    expect(wrapper.get("[role=alert]").text()).toContain("读取失败");
    expect(wrapper.text()).toContain("未采样");
    expect(wrapper.text()).not.toContain("1.000000001 s");
    expect(wrapper.find("dl").exists()).toBe(false);
    expect(wrapper.findComponent(StatusBadge).exists()).toBe(false);
    expect(wrapper.get("button").attributes("disabled")).toBeUndefined();
  });
  it.each([
    ["conflict", "暂时无法采样"],
    ["forbidden", "没有读取实例监控的权限"],
    ["invalid", "无法确认本次监控数据"],
    ["unavailable", "读取失败"],
  ] as const)(
    "keeps %s distinct from empty or successful metrics",
    async (kind, copy) => {
      const { wrapper, calls } = panel(() => {
        throw new ApiError(kind);
      });
      await wrapper.get("button").trigger("click");
      await flushPromises();
      expect(wrapper.get("[role=alert]").text()).toContain(copy);
      expect(wrapper.find("dl").exists()).toBe(false);
      expect(calls).toHaveLength(0);
    },
  );
  it("expires an accepted sample after 60 seconds without making a network request", async () => {
    const resolver = vi.fn(() => ({
      metrics: { ...metrics, observed_at: new Date().toISOString() },
    }));
    const { wrapper } = panel(resolver);
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("本次采样");
    await vi.advanceTimersByTimeAsync(60000);
    expect(wrapper.text()).not.toContain("采样已过期");
    await vi.advanceTimersByTimeAsync(1);
    expect(wrapper.text()).toContain("采样已过期");
    expect(wrapper.text()).toContain("以下为上次采样数据");
    expect(wrapper.find("dl").exists()).toBe(true);
    expect(resolver).toHaveBeenCalledOnce();
  });
  it.each([-60001, 5001])(
    "rejects a newly returned sample outside the freshness window (%i ms)",
    async (offset) => {
      const { wrapper } = panel(() => ({
        metrics: {
          ...metrics,
          observed_at: new Date(Date.now() + offset).toISOString(),
        },
      }));
      await wrapper.get("button").trigger("click");
      await flushPromises();
      expect(wrapper.get("[role=alert]").text()).toContain(
        "无法确认本次监控数据",
      );
      expect(wrapper.find("dl").exists()).toBe(false);
    },
  );
  it.each([-60000, 5000])(
    "accepts the exact freshness boundary (%i ms)",
    async (offset) => {
      const { wrapper } = panel(() => ({
        metrics: {
          ...metrics,
          observed_at: new Date(Date.now() + offset).toISOString(),
        },
      }));
      await wrapper.get("button").trigger("click");
      await flushPromises();
      expect(wrapper.find("[role=alert]").exists()).toBe(false);
      expect(wrapper.find("dl").exists()).toBe(true);
    },
  );
  it.each(["2026-10-23T04:00:06.000000001Z", "2026-10-23T03:59:00.999999999Z"])(
    "does not truncate an out-of-window nanosecond timestamp %s",
    async (observed_at) => {
      const { wrapper } = panel(() => ({
        metrics: { ...metrics, observed_at },
      }));
      await wrapper.get("button").trigger("click");
      await flushPromises();
      expect(wrapper.get("[role=alert]").text()).toContain(
        "无法确认本次监控数据",
      );
      expect(wrapper.find("dl").exists()).toBe(false);
    },
  );
  it.each([
    "instance_id",
    "node_id",
    "owner_ref",
    "hostname",
    "vcpus",
  ] as const)("rejects the wrong bound %s", async (key) => {
    const { wrapper } = panel(() => ({
      metrics: { ...metrics, [key]: key === "vcpus" ? 4 : "other" },
    }));
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(wrapper.get("[role=alert]").text()).toContain(
      "无法确认本次监控数据",
    );
    expect(wrapper.find("dl").exists()).toBe(false);
  });
  it("renders all missing counters as unavailable, never as zeros or a utilization percentage", async () => {
    const { wrapper } = panel(() => ({
      metrics: {
        ...metrics,
        cpu_time_ns: null,
        memory_rss_kib: null,
        memory_actual_kib: null,
        memory_unused_kib: null,
        block_read_bytes: null,
        block_write_bytes: null,
        network_receive_bytes: null,
        network_transmit_bytes: null,
      },
    }));
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(
      wrapper.findAll("dd").filter((item) => item.text() === "未提供"),
    ).toHaveLength(8);
    expect(wrapper.text()).not.toContain("0 KiB");
    expect(wrapper.text()).not.toContain("0 B");
    expect(wrapper.text()).not.toContain("%");
  });
  it("does not calculate rates or differences after counters reset", async () => {
    let first = true;
    const { wrapper } = panel(() => {
      const value = first
        ? metrics
        : {
            ...metrics,
            cpu_time_ns: "0",
            network_receive_bytes: "0",
            block_read_bytes: "0",
          };
      first = false;
      return { metrics: value };
    });
    await wrapper.get("button").trigger("click");
    await flushPromises();
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("0 s");
    expect(wrapper.text()).toContain("0 B");
    expect(wrapper.text()).not.toContain("B/s");
    expect(wrapper.text()).not.toContain("%");
  });
  it("drops late data after identity/route replacement and permits only a fresh explicit read", async () => {
    const oldRequest = deferred<unknown>(),
      newRequest = deferred<unknown>();
    const resolver = vi
      .fn()
      .mockReturnValueOnce(oldRequest.promise)
      .mockReturnValueOnce(newRequest.promise);
    const { wrapper, context } = panel(resolver);
    const get = vi.spyOn(context.api, "get");
    await wrapper.get("button").trigger("click");
    const signal = get.mock.calls[0]![2]!;
    const other = { ...instance, id: "f".repeat(32), node_id: "node-b" };
    await wrapper.setProps({ instance: other });
    expect(signal.aborted).toBe(true);
    expect(wrapper.text()).toContain("未采样");
    expect(resolver).toHaveBeenCalledOnce();
    await wrapper.get("button").trigger("click");
    oldRequest.resolve({ metrics });
    await flushPromises();
    expect(wrapper.text()).toContain("正在读取");
    expect(wrapper.find("dl").exists()).toBe(false);
    newRequest.resolve({
      metrics: {
        ...metrics,
        instance_id: other.id,
        node_id: other.node_id,
        cpu_time_ns: "7",
      },
    });
    await flushPromises();
    expect(wrapper.text()).toContain("0.000000007 s");
    expect(wrapper.text()).not.toContain("1.000000001 s");
  });
  it.each(["owner_ref", "hostname", "resources"] as const)(
    "drops late data if the same instance's %s changes",
    async (field) => {
      const request = deferred<unknown>();
      const { wrapper } = panel(() => request.promise);
      await wrapper.get("button").trigger("click");
      await wrapper.setProps({
        instance: {
          ...instance,
          [field]:
            field === "resources"
              ? { ...instance.resources, cpu_cores: 4 }
              : "changed",
        },
      });
      request.resolve({ metrics });
      await flushPromises();
      expect(wrapper.find("dl").exists()).toBe(false);
      expect(wrapper.find("[role=alert]").exists()).toBe(false);
      expect(wrapper.text()).toContain("未采样");
    },
  );
  it("drops a late old-session error without invalidating a replacement session", async () => {
    const request = deferred<unknown>();
    const { wrapper, context } = panel(() => request.promise);
    const invalidate = vi.spyOn(context.session, "invalidate");
    await wrapper.get("button").trigger("click");
    context.session.epoch.value++;
    request.reject(new ApiError("unauthorized"));
    await flushPromises();
    expect(invalidate).not.toHaveBeenCalled();
    expect(context.session.user.value).not.toBeNull();
    expect(wrapper.text()).toContain("未采样");
    expect(wrapper.find("[role=alert]").exists()).toBe(false);
  });
  it("invalidates a current unauthorized read, clears data and disables further reads", async () => {
    const { wrapper, context } = panel(() => {
      throw new ApiError("unauthorized");
    });
    const invalidate = vi.spyOn(context.session, "invalidate");
    await wrapper.get("button").trigger("click");
    await flushPromises();
    expect(invalidate).toHaveBeenCalledOnce();
    expect(context.session.user.value).toBeNull();
    expect(wrapper.find("dl").exists()).toBe(false);
    expect(wrapper.get("button").attributes("disabled")).toBeDefined();
  });
  it("clears a sample and pending reads immediately when read permission is removed", async () => {
    const resolver = vi.fn(() => ({ metrics }));
    const { wrapper, context } = panel(resolver);
    await wrapper.get("button").trigger("click");
    await flushPromises();
    context.session.user.value = {
      ...context.session.user.value!,
      permissions: [],
    };
    await nextTick();
    expect(wrapper.text()).toContain("未采样");
    expect(wrapper.text()).toContain("没有读取实例监控的权限");
    expect(wrapper.find("dl").exists()).toBe(false);
    await wrapper.get("button").trigger("click");
    expect(resolver).toHaveBeenCalledOnce();
  });
  it("aborts on unmount and ignores the late response", async () => {
    const request = deferred<unknown>();
    const { wrapper, context } = panel(() => request.promise);
    const get = vi.spyOn(context.api, "get");
    await wrapper.get("button").trigger("click");
    const signal = get.mock.calls[0]![2]!;
    wrapper.unmount();
    expect(signal.aborted).toBe(true);
    request.resolve({ metrics });
    await flushPromises();
    expect(vi.getTimerCount()).toBe(0);
  });
  it("switches complete labels and absent values to English without another request", async () => {
    const resolver = vi.fn(() => ({ metrics }));
    const { wrapper, context } = panel(resolver);
    await wrapper.get("button").trigger("click");
    await flushPromises();
    context.prefs.locale.value = "en";
    await nextTick();
    expect(wrapper.text()).toContain("Resource monitoring");
    expect(wrapper.text()).toContain("Cumulative CPU time");
    expect(wrapper.text()).toContain("Resident memory (RSS)");
    expect(wrapper.text()).toContain("Current memory allocation");
    expect(wrapper.text()).toContain("Not reported");
    expect(wrapper.text()).toContain(
      "Network counters are not billed transfer",
    );
    expect(wrapper.text()).not.toContain("未提供");
    expect(resolver).toHaveBeenCalledOnce();
  });
});
