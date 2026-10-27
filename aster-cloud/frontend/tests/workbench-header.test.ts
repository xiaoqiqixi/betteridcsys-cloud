import { afterEach, describe, expect, it } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import WorkbenchHeader, {
  type WorkbenchHeaderProps,
} from "../src/components/WorkbenchHeader.vue";
import NavLinks from "../src/components/NavLinks.vue";
import { consoleKey } from "../src/context";
import { mockContext } from "./helpers";

const cleanups: Array<() => void> = [];
afterEach(() => {
  cleanups
    .splice(0)
    .reverse()
    .forEach((cleanup) => cleanup());
  document.body.innerHTML = "";
});
const items = [
  { path: "/instances", label: "Instances" },
  { path: "/nodes", label: "Nodes" },
  {
    path: "/networks/overlays",
    matchPath: "/networks",
    label: "Networks & IP",
  },
];
async function fixture(path = "/instances", filtered = false) {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      "/instances",
      "/instances/:id",
      "/nodes",
      "/networks/overlays",
      "/networks/pools",
      "/networks/epochs/:id",
      "/nodes-unrelated",
      "/unmatched",
      "/operations",
      "/audit",
      "/users",
    ].map((path) => ({ path, component: { template: "<div />" } })),
  });
  await router.push(path);
  await router.isReady();
  const props = {
    items,
    activePath: path,
    displayName: "Synthetic operator",
    roleLabel: "Operator",
    localeLabel: "EN",
    busy: false,
  };
  const fake = mockContext(() => {
    throw new Error("View-only header must not call an API");
  });
  fake.context.session.user.value = {
    ...fake.context.session.user.value!,
    role: "viewer",
    permissions: ["instances.read", "nodes.read"],
  };
  const wrapper = filtered
    ? mount(NavLinks, {
        global: {
          plugins: [router],
          provide: { [consoleKey as symbol]: fake.context },
        },
        slots: {
          default: ({ items }: { items: typeof props.items }) => [
            hHeader({ ...props, items }),
          ],
        },
      })
    : mount(WorkbenchHeader, { props, global: { plugins: [router] } });
  cleanups.push(() => wrapper.unmount());
  return { wrapper, router, calls: fake.calls };
}
// Render the supplied permission-filtered slot without creating a second
// session store or importing any synthetic data into the production component.
import { h } from "vue";
const hHeader = (props: WorkbenchHeaderProps) => h(WorkbenchHeader, props);

describe("view-only workbench command rail", () => {
  it("uses actual route anchors and keeps navigation out of button semantics", async () => {
    const { wrapper, router } = await fixture();
    const nav = wrapper.get("nav.aw-rail-nav");
    expect(nav.findAll("button")).toHaveLength(0);
    expect(nav.get('a[href="/nodes"]').attributes("title")).toBe("Nodes");
    await nav.get('a[href="/nodes"]').trigger("click");
    await flushPromises();
    expect(router.currentRoute.value.path).toBe("/nodes");
  });
  it.each([
    { ctrlKey: true },
    { metaKey: true },
    { shiftKey: true },
    { button: 1 },
  ])("keeps native modified navigation available: %j", async (modifier) => {
    const { wrapper, router } = await fixture();
    const link = wrapper.get('nav a[href="/nodes"]');
    let routerPrevented = true;
    link.element.addEventListener(
      "click",
      (event) => {
        routerPrevented = event.defaultPrevented;
        // Stop jsdom's synthetic default activation after observing the real
        // router guard. Only a real browser proves opening a new tab.
        event.preventDefault();
      },
      { once: true },
    );
    link.element.dispatchEvent(
      new MouseEvent("click", { bubbles: true, cancelable: true, ...modifier }),
    );
    await flushPromises();
    expect(routerPrevented).toBe(false);
    expect(router.currentRoute.value.path).toBe("/instances");
    expect(link.attributes("href")).toBe("/nodes");
  });
  it.each(["/networks/pools", "/networks/epochs/abc"])(
    "normalizes network descendants without inventing a different destination: %s",
    async (path) => {
      const { wrapper } = await fixture(path);
      const active = wrapper.findAll('nav a[aria-current="page"]');
      expect(active).toHaveLength(1);
      expect(active[0]!.attributes("href")).toBe("/networks/overlays");
      expect(wrapper.get(".aw-mobile-current-label").text()).toBe(
        "Networks & IP",
      );
    },
  );
  it("does not prefix-match an unrelated route or select the first permitted destination", async () => {
    const { wrapper } = await fixture("/nodes-unrelated");
    expect(wrapper.findAll('nav [aria-current="page"]')).toHaveLength(0);
    expect(wrapper.find(".aw-mobile-context").exists()).toBe(false);
    await wrapper.setProps({ currentPageLabel: "Restricted destination" });
    expect(wrapper.get(".aw-mobile-current-label").text()).toBe(
      "Restricted destination",
    );
    expect(wrapper.findAll('nav [aria-current="page"]')).toHaveLength(0);
  });
  it("reflects the existing permission-filtered NavLinks slot instead of inventing grants", async () => {
    const { wrapper, calls } = await fixture("/instances", true);
    const labels = wrapper.findAll("nav a").map((link) => link.text());
    expect(labels).toEqual(["实例", "节点", "网络与 IP", "操作任务"]);
    expect(wrapper.find('nav a[href="/users"]').exists()).toBe(false);
    expect(wrapper.find('nav a[href="/audit"]').exists()).toBe(false);
    expect(calls).toEqual([]);
  });
  it("exposes a controlled dialog disclosure and prevents duplicate busy logout", async () => {
    const { wrapper } = await fixture();
    expect(wrapper.get(".aw-menu-trigger").attributes("aria-haspopup")).toBe(
      "dialog",
    );
    expect(wrapper.get(".aw-menu-trigger").attributes("aria-expanded")).toBe(
      "false",
    );
    await wrapper.setProps({ navigationOpen: true, busy: true });
    expect(wrapper.get(".aw-menu-trigger").attributes("aria-expanded")).toBe(
      "true",
    );
    expect(
      wrapper.get(".aw-logout-trigger").attributes("disabled"),
    ).toBeDefined();
    await wrapper.get(".aw-logout-trigger").trigger("click");
    expect(wrapper.emitted("logout")).toBeUndefined();
    await wrapper.setProps({ busy: false });
    await wrapper.get(".aw-logout-trigger").trigger("click");
    expect(wrapper.emitted("logout")).toHaveLength(1);
  });
});
