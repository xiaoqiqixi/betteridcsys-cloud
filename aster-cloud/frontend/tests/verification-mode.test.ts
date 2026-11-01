import { defineComponent, h } from "vue";
import { flushPromises, mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { createApiClient, operationResponse } from "../src/api/client";
import { useSession } from "../src/composables/session";
import { useMutation } from "../src/composables/mutation";
import { consoleKey, type ConsoleContext } from "../src/context";
import { usePreferences } from "../src/composables/preferences";
import UsersPage from "../src/pages/UsersPage.vue";
import InstanceDetailPage from "../src/pages/InstanceDetailPage.vue";
import NavLinks from "../src/components/NavLinks.vue";
import { admin, instance } from "./fixtures";
import { deferred, mockContext } from "./helpers";

const response = (verification_mode: unknown) =>
  new Response(
    JSON.stringify({ user: admin, csrf_token: "csrf-test", verification_mode }),
    { status: 200, headers: { "Content-Type": "application/json" } },
  );
afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  sessionStorage.clear();
  localStorage.clear();
});

// Real client/session/pages; only the external HTTP transport is substituted.
async function readOnlyContext(resolver: (path: string) => unknown) {
  vi.stubGlobal("matchMedia", () => ({
    matches: false,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  const requests: { path: string; method: string }[] = [];
  const api = createApiClient(async (input, init) => {
    const path = String(input).replace("/console/v1", "");
    const method = init?.method || "GET";
    requests.push({ path, method });
    const value =
      path === "/auth/me"
        ? { user: admin, csrf_token: "csrf", verification_mode: true }
        : resolver(path);
    return new Response(JSON.stringify(value), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
  const context: ConsoleContext = {
    api,
    session: useSession(api),
    prefs: usePreferences(),
    notify: vi.fn(),
  };
  expect(await context.session.refresh()).toBe(true);
  return { context, requests };
}

describe("migration verification pages use read-only grants", () => {
  it("retains members navigation and member records without exposing enabled editors", async () => {
    const { context, requests } = await readOnlyContext((path) => {
      if (path === "/roles")
        return {
          items: [
            {
              id: "admin",
              name: "Administrator",
              permissions: admin.permissions,
            },
          ],
        };
      if (path === "/users")
        return {
          items: [admin],
          limit: 100,
          truncated_possible: false,
          next_cursor: null,
        };
      throw new Error(`Unexpected read: ${path}`);
    });
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/users", component: UsersPage }],
    });
    await router.push("/users");
    await router.isReady();
    const wrapper = mount(
      defineComponent({
        setup: () => () => h("div", [h(NavLinks), h(UsersPage)]),
      }),
      {
        global: {
          plugins: [router],
          provide: { [consoleKey as symbol]: context },
        },
      },
    );
    try {
      await flushPromises();
      expect(wrapper.get('a[href="/users"]').text()).toContain("成员与权限");
      expect(wrapper.text()).toContain(admin.email);
      const add = wrapper
        .findAll("button")
        .find((b) => b.text().includes("新增成员"));
      expect(add).toBeDefined();
      expect(add!.attributes("disabled")).toBeDefined();
      expect(wrapper.find('[role="dialog"]').exists()).toBe(false);
      expect(requests.map((r) => r.path).sort()).toEqual([
        "/auth/me",
        "/roles",
        "/users",
      ]);
      expect(requests.every((r) => r.method === "GET")).toBe(true);
    } finally {
      wrapper.unmount();
      context.prefs.dispose();
    }
  });
  it("shows saved instance details without live node requests or enabled instance operations", async () => {
    const { context, requests } = await readOnlyContext((path) => {
      if (path === `/instances/${instance.id}`)
        return { instance, artifacts: [], operations: [], migrations: [] };
      throw new Error(`Verification must not query a node: ${path}`);
    });
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/instances/:id", component: InstanceDetailPage }],
    });
    await router.push(`/instances/${instance.id}`);
    await router.isReady();
    const wrapper = mount(InstanceDetailPage, {
      global: {
        plugins: [router],
        provide: { [consoleKey as symbol]: context },
      },
    });
    try {
      await flushPromises();
      expect(wrapper.text()).toContain(instance.hostname);
      for (const label of [
        "启动",
        "关机",
        "重启",
        "迁移",
        "强制关机",
        "删除实例",
      ]) {
        const button = wrapper
          .findAll("button")
          .find((b) => b.text() === label);
        expect(button, label).toBeDefined();
        expect(button!.attributes("disabled"), label).toBeDefined();
      }
      expect(requests.map((r) => r.path)).toEqual([
        "/auth/me",
        `/instances/${instance.id}`,
      ]);
      expect(requests.every((r) => r.method === "GET")).toBe(true);
    } finally {
      wrapper.unmount();
      context.prefs.dispose();
    }
  });
});

describe("server-confirmed migration verification mode", () => {
  it("keeps read access and original grants but denies management actions", async () => {
    const session = useSession(
      createApiClient(vi.fn<typeof fetch>().mockResolvedValue(response(true))),
    );
    expect(await session.refresh()).toBe(true);
    expect(session.verificationMode.value).toBe(true);
    expect(session.can("instances.read")).toBe(true);
    expect(session.canView("users.manage")).toBe(true);
    for (const permission of admin.permissions.filter(
      (p) => !p.endsWith(".read"),
    ))
      expect(session.can(permission)).toBe(false);
    expect(session.user.value?.permissions).toEqual(admin.permissions);
  });
  it.each(["true", 1, null, {}])(
    "rejects malformed mode instead of enabling operations: %j",
    async (value) => {
      const session = useSession(
        createApiClient(
          vi.fn<typeof fetch>().mockResolvedValue(response(value)),
        ),
      );
      expect(await session.refresh()).toBe(false);
      expect(session.user.value).toBeNull();
      expect(session.can("instances.manage")).toBe(false);
    },
  );
  it("mode changes invalidate pending work even when the same user logs in", async () => {
    const late = deferred<Response>();
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(response(false))
      .mockImplementationOnce(() => late.promise)
      .mockResolvedValueOnce(response(true));
    const session = useSession(createApiClient(fetcher));
    await session.refresh();
    const epoch = session.epoch.value;
    const old = session.refresh();
    await session.refresh();
    late.resolve(response(false));
    await old;
    expect(session.verificationMode.value).toBe(true);
    expect(session.epoch.value).toBeGreaterThan(epoch);
    expect(session.can("instances.manage")).toBe(false);
  });
  it("refuses a direct mutation before creating an intent or sending HTTP", async () => {
    vi.stubGlobal("crypto", webcrypto);
    const { context, calls } = mockContext(() => ({
      user: admin,
      csrf_token: "csrf",
      verification_mode: true,
    }));
    await context.session.refresh();
    let mutation!: ReturnType<typeof useMutation>;
    const wrapper = mount(
      defineComponent({
        setup() {
          mutation = useMutation();
          return () => h("div");
        },
      }),
      { global: { provide: { [consoleKey as symbol]: context } } },
    );
    const previous = sessionStorage.getItem("aster.cloud.pending.v1");
    expect(
      await mutation.execute(
        "POST",
        `/instances/${instance.id}/operations`,
        { action: "start" },
        operationResponse,
      ),
    ).toBeNull();
    expect(calls).toHaveLength(0);
    expect(sessionStorage.getItem("aster.cloud.pending.v1")).toBe(previous);
    expect(mutation.error.value).toBe("forbidden");
    wrapper.unmount();
  });
});
