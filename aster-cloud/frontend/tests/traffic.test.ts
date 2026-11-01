import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { consoleKey } from "../src/context";
import InstanceTrafficPanel from "../src/components/InstanceTrafficPanel.vue";
import UiSelect from "../src/components/UiSelect.vue";
import { ApiError } from "../src/api/client";
import {
  trafficCounter,
  trafficGiB,
  validTraffic,
  type TrafficView,
} from "../src/api/traffic";
import { mockContext } from "./helpers";
const wrappers: Array<{ unmount: () => void }> = [];
const view: TrafficView = {
  policy: {
    reset_day: 1,
    direction: "both",
    limit_bytes: "107374182400",
    overage_policy: "none",
  },
  rx_bytes: "9007199254740993",
  tx_bytes: "1073741824",
  reset_day_locked: true,
  period_start: "2026-11-01T00:00:00Z",
  period_end: "2026-12-01T00:00:00Z",
  observed_at: "2026-11-01T02:00:00Z",
  inbound_mbps: 100,
  outbound_mbps: 20,
  accounting_supported: true,
  throttle_supported: false,
  suspend_supported: true,
  enforcement: null,
};
beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  sessionStorage.clear();
});
afterEach(() => {
  wrappers.splice(0).forEach((w) => w.unmount());
  vi.unstubAllGlobals();
  sessionStorage.clear();
});
it("preserves large byte counters and shows unavailable collection explicitly", async () => {
  expect(validTraffic(view)).toBe(true);
  expect(trafficCounter("18446744073709551616")).toBe(false);
  expect(trafficGiB("9007199254740993")).toBe("8388608.00 GiB");
  const fixture = mockContext(() => ({ ...view, observed_at: null }));
  const wrapper = mount(InstanceTrafficPanel, {
    props: { instanceId: "a".repeat(32) },
    global: {
      provide: { [consoleKey as symbol]: fixture.context },
      stubs: { RouterLink: true },
    },
  });
  wrappers.push(wrapper);
  await flushPromises();
  expect(wrapper.text()).toContain("尚无采样");
  expect(wrapper.text()).toContain("此网络不支持动态流量限速");
  expect(fixture.calls).toHaveLength(0);
  await wrapper
    .findAll("button")
    .find((b) => b.text() === "编辑流量策略")!
    .trigger("click");
  expect(wrapper.get('input[max="31"]').attributes("disabled")).toBeDefined();
  expect(
    wrapper
      .findAllComponents(UiSelect)[1]!
      .props("options")
      .find((v) => v.value === "throttle")?.disabled,
  ).toBe(true);
});
it("does not retry an unknown traffic policy write", async () => {
  const fixture = mockContext((method) => {
    if (method === "GET") return view;
    throw new ApiError("unknown");
  });
  const wrapper = mount(InstanceTrafficPanel, {
    props: { instanceId: "b".repeat(32) },
    global: {
      provide: { [consoleKey as symbol]: fixture.context },
      stubs: { RouterLink: true },
    },
  });
  wrappers.push(wrapper);
  await flushPromises();
  await wrapper
    .findAll("button")
    .find((b) => b.text() === "编辑流量策略")!
    .trigger("click");
  wrapper.findAllComponents(UiSelect)[0]!.vm.$emit("update:modelValue", "out");
  await wrapper.get("form").trigger("submit");
  await expect.poll(() => fixture.calls.length).toBe(1);
  await expect
    .poll(() => wrapper.get('button[type="submit"]').attributes("disabled"))
    .toBeDefined();
  await wrapper.get("form").trigger("submit");
  await flushPromises();
  expect(fixture.calls).toHaveLength(1);
  expect(fixture.calls[0]?.body).toEqual({ ...view.policy, direction: "out" });
});
