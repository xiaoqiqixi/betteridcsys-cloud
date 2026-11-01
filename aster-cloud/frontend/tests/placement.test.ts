import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import { consoleKey } from "../src/context";
import PlacementPanel from "../src/components/PlacementPanel.vue";
import AllocationToggle from "../src/components/AllocationToggle.vue";
import UiSelect from "../src/components/UiSelect.vue";
import { mockContext } from "./helpers";
import { node } from "./fixtures";
import { ApiError } from "../src/api/client";
const wrappers: Array<{ unmount: () => void }> = [];
beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  sessionStorage.clear();
});
afterEach(() => {
  wrappers.splice(0).forEach((w) => w.unmount());
  vi.unstubAllGlobals();
  sessionStorage.clear();
});
it("saves an explicit region policy and keeps reads free of writes", async () => {
  let policy = "least_instances";
  const fixture = mockContext((method, path, body) => {
    if (method === "GET") return { items: [{ region_id: "dc-a", policy }] };
    expect(path).toBe("/placement/dc-a");
    policy = (body as { policy: string }).policy;
    return { region_id: "dc-a", policy };
  });
  const wrapper = mount(PlacementPanel, {
    global: { provide: { [consoleKey as symbol]: fixture.context } },
  });
  wrappers.push(wrapper);
  await flushPromises();
  expect(fixture.calls).toHaveLength(0);
  wrapper
    .getComponent(UiSelect)
    .vm.$emit("update:modelValue", "most_free_memory");
  await flushPromises();
  await wrapper
    .findAll("button")
    .find((b) => b.text() === "保存")!
    .trigger("click");
  await expect.poll(() => fixture.calls.length).toBe(1);
  expect(fixture.calls[0]?.body).toEqual({ policy: "most_free_memory" });
  await expect
    .poll(() => wrapper.getComponent(UiSelect).props("modelValue"))
    .toBe("most_free_memory");
});
it("allocation changes never resend an unknown outcome", async () => {
  const fixture = mockContext(() => {
    throw new ApiError("unknown");
  });
  const wrapper = mount(AllocationToggle, {
    props: { node: { ...node, id: "allocation-unknown" } },
    global: { provide: { [consoleKey as symbol]: fixture.context } },
  });
  wrappers.push(wrapper);
  await wrapper.get("button").trigger("click");
  await expect.poll(() => fixture.calls.length).toBe(1);
  await expect
    .poll(() => wrapper.get("button").attributes("disabled"))
    .toBeDefined();
  expect(fixture.calls[0]?.body).toEqual({ allocation_disabled: true });
  await wrapper.get("button").trigger("click");
  await flushPromises();
  expect(fixture.calls).toHaveLength(1);
});
