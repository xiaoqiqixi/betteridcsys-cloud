import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import { ApiError, validUsers } from "../src/api/client";
import { consoleKey } from "../src/context";
import UsersPage from "../src/pages/UsersPage.vue";
import { admin } from "./fixtures";
import { deferred, mockContext } from "./helpers";

const cursor =
  "u1.eyJhdCI6IjIwMjYtMTAtMjVUMDA6MDA6MDAuMTIzNDU2WiIsImlkIjoiYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEifQ";
const roles = {
  items: [
    { id: "admin", name: "Administrator", permissions: admin.permissions },
  ],
};
const members = Array.from({ length: 100 }, (_, i) => ({
  ...admin,
  id: (i + 1).toString(16).padStart(32, "0"),
  name: `成员 ${i + 1}`,
  email: `member${i + 1}@example.invalid`,
}));
const first = {
  items: members,
  limit: 100,
  truncated_possible: true,
  next_cursor: cursor,
};
const last = {
  items: [{ ...admin, name: "第101位成员" }],
  limit: 100,
  truncated_possible: false,
  next_cursor: null,
};
const button = (wrapper: ReturnType<typeof mount>, text: string) =>
  wrapper.findAll("button").find((b) => b.text() === text)!;

describe("strict members page response", () => {
  it("requires the new complete-page contract rather than accepting a truncated legacy response", () => {
    expect(validUsers(first)).toBe(true);
    expect(validUsers(last)).toBe(true);
    expect(
      validUsers({ items: [admin], limit: 100, truncated_possible: true }),
    ).toBe(false);
  });
  it("rejects inconsistent next cursor, duplicates, oversized pages and wrong limits", () => {
    for (const bad of [
      { ...first, next_cursor: null },
      { ...last, next_cursor: cursor },
      { ...first, items: [admin] },
      { ...first, next_cursor: "bad cursor" },
      { ...first, items: [...members, admin] },
      { ...last, limit: 50 },
      { ...last, items: [admin, admin] },
      { ...last, next_cursor: "" },
    ])
      expect(validUsers(bad)).toBe(false);
  });
});

describe("members complete pagination", () => {
  it("reaches member 101, returns to page one, and never writes during navigation", async () => {
    const paths: string[] = [];
    const { context, calls } = mockContext((_method, path) => {
      paths.push(path);
      if (path === "/roles") return roles;
      return path.includes("cursor=") ? last : first;
    });
    const wrapper = mount(UsersPage, {
      global: { provide: { [consoleKey as symbol]: context } },
      attachTo: document.body,
    });
    await flushPromises();
    expect(wrapper.text()).toContain("成员 1");
    expect(button(wrapper, "上一页").attributes("disabled")).toBeDefined();
    await button(wrapper, "下一页").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("第101位成员");
    expect(wrapper.text()).toContain("第 2 页");
    expect(document.activeElement).toBe(wrapper.find("h1").element);
    expect(button(wrapper, "下一页").attributes("disabled")).toBeDefined();
    await button(wrapper, "上一页").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("成员 1");
    expect(wrapper.text()).toContain("第 1 页");
    expect(paths).toContain("/users?cursor=" + encodeURIComponent(cursor));
    expect(calls).toEqual([]);
    wrapper.unmount();
  });
  it("does not advance the committed page on a failed next request and retries the intended page", async () => {
    let fail = true;
    const { context } = mockContext((_method, path) => {
      if (path === "/roles") return roles;
      if (path.includes("cursor=")) {
        if (fail) throw new ApiError("network");
        return last;
      }
      return first;
    });
    const wrapper = mount(UsersPage, {
      global: { provide: { [consoleKey as symbol]: context } },
    });
    await flushPromises();
    await button(wrapper, "下一页").trigger("click");
    await flushPromises();
    expect(wrapper.text()).not.toContain("第 2 页");
    expect(wrapper.findAll(".member-row")).toHaveLength(100);
    fail = false;
    await button(wrapper, "重新加载").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("第101位成员");
    wrapper.unmount();
  });
  it("clears rows, navigation and editor when permission disappears and discards late responses", async () => {
    const pending = deferred<unknown>();
    const { context } = mockContext((_method, path) =>
      path === "/roles"
        ? roles
        : path.includes("cursor=")
          ? pending.promise
          : first,
    );
    const wrapper = mount(UsersPage, {
      global: { provide: { [consoleKey as symbol]: context } },
    });
    await flushPromises();
    await button(wrapper, "下一页").trigger("click");
    context.session.user.value = {
      ...admin,
      role: "viewer",
      permissions: ["instances.read"],
    };
    context.session.epoch.value++;
    await flushPromises();
    pending.resolve(last);
    await flushPromises();
    expect(wrapper.text()).not.toContain("第101位成员");
    expect(wrapper.find(".member-row").exists()).toBe(false);
    expect(wrapper.find("nav[aria-label='成员列表分页']").exists()).toBe(false);
    wrapper.unmount();
  });
  it("walks 205 members in three pages, announces English counts, and disables navigation while pending", async () => {
    const pending = deferred<unknown>();
    const cursor2 = cursor + "AA";
    const secondMembers = members.map((u, i) => ({
      ...u,
      id: (i + 101).toString(16).padStart(32, "0"),
      name: `Member ${i + 101}`,
    }));
    const { context, calls } = mockContext((_method, path) =>
      path === "/roles"
        ? roles
        : path.endsWith(cursor2)
          ? {
              ...last,
              items: secondMembers.slice(0, 5).map((u, i) => ({
                ...u,
                id: (i + 201).toString(16).padStart(32, "0"),
                name: `Member ${i + 201}`,
              })),
            }
          : path.includes("cursor=")
            ? pending.promise
            : first,
    );
    context.prefs.locale.value = "en";
    const wrapper = mount(UsersPage, {
      global: { provide: { [consoleKey as symbol]: context } },
    });
    await flushPromises();
    await button(wrapper, "Next").trigger("click");
    expect(button(wrapper, "Next").attributes("disabled")).toBeDefined();
    expect(button(wrapper, "Previous").attributes("disabled")).toBeDefined();
    expect(wrapper.find("[role='status'][aria-label='Loading']").exists()).toBe(
      true,
    );
    pending.resolve({ ...first, items: secondMembers, next_cursor: cursor2 });
    await flushPromises();
    expect(wrapper.text()).toContain("Page 2 · 100 members");
    await button(wrapper, "Next").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("Member 205");
    expect(wrapper.text()).toContain("Page 3 · 5 members");
    expect(button(wrapper, "Next").attributes("disabled")).toBeDefined();
    expect(calls).toEqual([]);
    wrapper.unmount();
  });
  it.each(["unauthorized", "forbidden"] as const)(
    "clears stale rows and cursors on an actual %s response",
    async (kind) => {
      const { context } = mockContext((_method, path) => {
        if (path === "/roles") return roles;
        if (path.includes("cursor=")) throw new ApiError(kind);
        return first;
      });
      const wrapper = mount(UsersPage, {
        global: { provide: { [consoleKey as symbol]: context } },
      });
      await flushPromises();
      await button(wrapper, "下一页").trigger("click");
      await flushPromises();
      expect(wrapper.find(".member-row").exists()).toBe(false);
      expect(wrapper.find(".members-pagination").exists()).toBe(false);
      expect(wrapper.find("[role='alert']").exists()).toBe(true);
      expect(button(wrapper, "新增成员").attributes("disabled")).toBeDefined();
      if (kind === "unauthorized")
        expect(context.session.user.value).toBeNull();
      wrapper.unmount();
    },
  );
  it("starts a different administrator at page one and closes the previous editor", async () => {
    const paths: string[] = [];
    const { context } = mockContext((_method, path) => {
      paths.push(path);
      return path === "/roles"
        ? roles
        : path.includes("cursor=")
          ? last
          : first;
    });
    const wrapper = mount(UsersPage, {
      global: { provide: { [consoleKey as symbol]: context } },
    });
    await flushPromises();
    await button(wrapper, "下一页").trigger("click");
    await flushPromises();
    await wrapper.find(".member-row button").trigger("click");
    await flushPromises();
    expect(wrapper.findComponent({ name: "UserEditor" }).props("open")).toBe(
      true,
    );
    const before = paths.length;
    context.session.user.value = { ...admin, id: "d".repeat(32) };
    context.session.epoch.value++;
    await flushPromises();
    expect(wrapper.text()).toContain("第 1 页");
    expect(wrapper.findComponent({ name: "UserEditor" }).props("open")).toBe(
      false,
    );
    expect(
      paths
        .slice(before)
        .filter((p) => p.startsWith("/users"))
        .every((p) => p === "/users"),
    ).toBe(true);
    wrapper.unmount();
  });
  it("rejects a looping cursor without advancing or showing the returned rows", async () => {
    const { context } = mockContext((_method, path) =>
      path === "/roles" ? roles : first,
    );
    const wrapper = mount(UsersPage, {
      global: { provide: { [consoleKey as symbol]: context } },
    });
    await flushPromises();
    await button(wrapper, "下一页").trigger("click");
    await flushPromises();
    expect(wrapper.text()).not.toContain("第 2 页");
    expect(wrapper.find("[role='alert']").exists()).toBe(true);
    wrapper.unmount();
  });
  it("refreshes from page two back to page one, while editing reloads the current page and creating returns to one", async () => {
    const paths: string[] = [];
    const { context } = mockContext((_method, path) => {
      paths.push(path);
      if (path === "/roles") return roles;
      if (path === "/auth/me") return { user: admin, csrf_token: "csrf" };
      return path.includes("cursor=") ? last : first;
    });
    const wrapper = mount(UsersPage, {
      global: { provide: { [consoleKey as symbol]: context } },
    });
    await flushPromises();
    await button(wrapper, "下一页").trigger("click");
    await flushPromises();
    await button(wrapper, "刷新").trigger("click");
    await flushPromises();
    expect(wrapper.text()).toContain("第 1 页");
    await button(wrapper, "下一页").trigger("click");
    await flushPromises();
    await wrapper.find(".member-row button").trigger("click");
    await flushPromises();
    wrapper.findComponent({ name: "UserEditor" }).vm.$emit("saved");
    wrapper.findComponent({ name: "UserEditor" }).vm.$emit("close");
    await flushPromises();
    expect(wrapper.text()).toContain("第 2 页");
    await button(wrapper, "新增成员").trigger("click");
    await flushPromises();
    wrapper.findComponent({ name: "UserEditor" }).vm.$emit("saved");
    wrapper.findComponent({ name: "UserEditor" }).vm.$emit("close");
    await flushPromises();
    expect(wrapper.text()).toContain("第 1 页");
    expect(paths[paths.length - 1]).toBe("/users");
    wrapper.unmount();
  });
});
