import { beforeEach, afterEach, it, expect, vi } from "vitest";
import { defineComponent, shallowRef } from "vue";
import { mount, flushPromises } from "@vue/test-utils";
import { webcrypto } from "node:crypto";
import UserEditor from "../src/components/UserEditor.vue";
import IdentityEditorFields from "../src/components/IdentityEditorFields.vue";
import UiOverlay from "../src/components/UiOverlay.vue";
import { resetOrphanedOverlayHistory } from "../src/components/overlay-stack";
import { ApiError } from "../src/api/client";
import { consoleKey } from "../src/context";
import { admin } from "./fixtures";
import { mockContext } from "./helpers";
import { identityFixtureResponse } from "./identity-fixtures";

const target = {
  ...admin,
  id: "a".repeat(32),
  email: "target@example.invalid",
  name: "Original member",
  role: "viewer",
  permissions: ["instances.read"],
};
const roles = [
  { id: "viewer", name: "Viewer", permissions: ["instances.read"] },
  { id: "custom", name: "Custom", permissions: [] },
];
const cleanups: (() => void)[] = [];
beforeEach(() => {
  sessionStorage.clear();
  vi.stubGlobal("crypto", webcrypto);
  Element.prototype.scrollIntoView = vi.fn();
  vi.spyOn(history, "back").mockImplementation(() => {});
  vi.spyOn(HTMLElement.prototype, "getClientRects").mockImplementation(
    () => [new DOMRect(0, 0, 100, 44)] as unknown as DOMRectList,
  );
});
afterEach(() => {
  cleanups.splice(0).forEach((f) => f());
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.innerHTML = "";
  history.replaceState(null, "");
});
const byText = (text: string) =>
  [...document.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.textContent?.trim() === text,
  )!;
async function editor(resolver: Parameters<typeof mockContext>[0]) {
  const fake = mockContext(resolver),
    wrapper = mount(UserEditor, {
      props: { open: true, user: target, roles },
      attachTo: document.body,
      global: { provide: { [consoleKey as symbol]: fake.context } },
    });
  cleanups.push(() => wrapper.unmount());
  await flushPromises();
  return { ...fake, wrapper };
}
it("opens the latest account revision, preserves a conflict draft and reloads only explicitly", async () => {
  let revision = 4;
  const { wrapper, calls } = await editor((method, _path, input, key) => {
    if (method === "GET") return { user: { ...target, revision } };
    if (revision === 4)
      throw new ApiError("conflict", "REVISION_CONFLICT", 409);
    return identityFixtureResponse("identity.user_updated", key, input, {
      ...target,
      revision,
    });
  });
  const form = () => document.querySelector<HTMLFormElement>("form")!;
  const name = () =>
    document.querySelector<HTMLInputElement>('input[type="text"]')!;
  const focusedName = name();
  focusedName.focus();
  focusedName.value = "Preserved draft";
  focusedName.dispatchEvent(new Event("input", { bubbles: true }));
  await flushPromises();
  expect(focusedName.isConnected).toBe(true);
  expect(document.activeElement).toBe(focusedName);
  const reason = document.querySelector<HTMLTextAreaElement>("textarea")!;
  reason.value = "Correct member name";
  reason.dispatchEvent(new Event("input", { bubbles: true }));
  await flushPromises();
  form().dispatchEvent(
    new Event("submit", { bubbles: true, cancelable: true }),
  );
  await flushPromises();
  expect(calls).toHaveLength(1);
  expect(calls[0]!.body).toMatchObject({
    revision: 4,
    name: "Preserved draft",
    reason: "Correct member name",
  });
  expect(name().value).toBe("Preserved draft");
  expect(name().disabled).toBe(true);
  expect(document.body.textContent).toContain("资料已有更新");
  expect(
    document.activeElement?.classList.contains("identity-editor-feedback"),
  ).toBe(true);
  expect(Element.prototype.scrollIntoView).toHaveBeenCalledWith({
    block: "start",
    behavior: "instant",
  });
  form().dispatchEvent(
    new Event("submit", { bubbles: true, cancelable: true }),
  );
  await flushPromises();
  expect(calls).toHaveLength(1);
  revision = 5;
  byText("放弃草稿并重新读取").click();
  await flushPromises();
  expect(name().value).toBe(target.name);
  expect(name().disabled).toBe(false);
  expect(wrapper.emitted("saved")).toBeUndefined();
});
it("reveals uncertain revocation feedback only in the interactive confirmation layer", async () => {
  const { calls } = await editor((method) => {
    if (method === "GET") return { user: target };
    throw new ApiError("unavailable", "UNAVAILABLE", 503);
  });
  byText("撤销全部会话").click();
  await flushPromises();
  const reason = document.querySelector<HTMLInputElement>(".aw-reason-input")!;
  reason.value = "Require a fresh sign-in";
  reason.dispatchEvent(new Event("input", { bubbles: true }));
  await flushPromises();
  byText("确认撤销会话").click();
  await flushPromises();
  expect(calls).toHaveLength(1);
  const top = document.querySelector(".aw-revoke-dialog-body")!;
  expect(top.contains(document.activeElement)).toBe(true);
  expect(
    document.activeElement?.classList.contains("identity-editor-feedback"),
  ).toBe(true);
  expect(document.querySelectorAll(".aw-op-notice")).toHaveLength(1);
  expect(document.activeElement?.closest("[inert]")).toBeNull();
  expect(sessionStorage.getItem("aster.cloud.identity.pending.v1")).toContain(
    "Require a fresh sign-in",
  );
});
it("renders fixed-role permissions as read-only and counts complete Unicode code points", async () => {
  const model = {
    name: "Name",
    email: "name@example.invalid",
    password: "",
    role: "viewer",
    enabled: true,
    permissions: ["instances.read"],
    reason: "",
  };
  const w = mount(IdentityEditorFields, {
    props: {
      modelValue: model,
      editing: true,
      self: false,
      disabled: false,
      roleOptions: roles.map((r) => ({ value: r.id, label: r.name })),
      permissionOptions: [{ value: "instances.read", label: "Read instances" }],
      labels: { reasonLabel: "Reason", roleLabel: "Role" },
    },
  });
  cleanups.push(() => w.unmount());
  expect(w.get('[role="checkbox"]').attributes("disabled")).toBeDefined();
  await w.get("textarea").setValue("🙂".repeat(501));
  const emitted = w.emitted("update:modelValue")!.at(-1)![0] as typeof model;
  expect([...emitted.reason]).toHaveLength(500);
  expect(emitted.reason).toBe("🙂".repeat(500));
  expect(model.reason).toBe("");
  const both = mount(
    defineComponent({
      components: { IdentityEditorFields },
      setup() {
        return { props: w.props() };
      },
      template:
        '<div><IdentityEditorFields v-bind="props"/><IdentityEditorFields v-bind="props"/></div>',
    }),
  );
  cleanups.push(() => both.unmount());
  const ids = both.findAll("[id]").map((v) => v.attributes("id"));
  expect(new Set(ids).size).toBe(ids.length);
});
it("keeps only the top nested dialog interactive and restores the parent lock and focus", async () => {
  const parent = shallowRef(true),
    child = shallowRef(false);
  const root = document.createElement("div");
  root.id = "app";
  document.body.append(root);
  const w = mount(
    defineComponent({
      components: { UiOverlay },
      setup() {
        return { parent, child };
      },
      template: `<UiOverlay :open="parent" title="Parent" @close="parent=false"><button id="child-open" @click="child=true">Open child</button><UiOverlay :open="child" title="Child" @close="child=false"><button id="child-action">Action</button></UiOverlay></UiOverlay>`,
    }),
    { attachTo: root },
  );
  cleanups.push(() => w.unmount());
  await flushPromises();
  const open = document.getElementById("child-open")!;
  open.focus();
  open.click();
  await flushPromises();
  const shades = [...document.querySelectorAll<HTMLElement>(".overlay-shade")];
  expect(shades).toHaveLength(2);
  const liveState = structuredClone(history.state);
  resetOrphanedOverlayHistory();
  expect(history.state).toEqual(liveState);
  expect(shades[0]!.inert).toBe(true);
  expect(shades[1]!.inert).toBe(false);
  expect(
    document.activeElement
      ?.closest('[role="dialog"]')
      ?.getAttribute("aria-labelledby"),
  ).toBe(
    shades[1]!
      .querySelector('[role="dialog"]')
      ?.getAttribute("aria-labelledby"),
  );
  document.dispatchEvent(
    new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
  );
  await flushPromises();
  expect(child.value).toBe(false);
  expect(parent.value).toBe(true);
  expect(document.body.style.overflow).toBe("hidden");
  expect(root.inert).toBe(true);
  expect(document.activeElement).toBe(open);
  document.dispatchEvent(
    new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
  );
  await flushPromises();
  expect(parent.value).toBe(false);
  expect(root.inert).toBe(false);
  expect(document.body.style.overflow).not.toBe("hidden");
});
