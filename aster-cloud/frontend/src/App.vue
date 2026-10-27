<script setup lang="ts">
import {
  computed,
  nextTick,
  onBeforeUnmount,
  onMounted,
  provide,
  shallowRef,
  useTemplateRef,
  watch,
} from "vue";
import { RouterView, useRoute } from "vue-router";
import { Server, SlidersHorizontal, LogOut } from "@lucide/vue";
import { createApiClient } from "./api/client";
import { useSession } from "./composables/session";
import { usePreferences } from "./composables/preferences";
import { consoleKey } from "./context";
import { useNotices } from "./composables/notices";
import NavLinks from "./components/NavLinks.vue";
import WorkbenchHeader from "./components/WorkbenchHeader.vue";
import UiOverlay from "./components/UiOverlay.vue";
import UiSelect from "./components/UiSelect.vue";
import UiButton from "./components/UiButton.vue";
import StateBlock from "./components/StateBlock.vue";
import ToastStack from "./components/ToastStack.vue";
import InlineError from "./components/InlineError.vue";
import LoginPage from "./pages/LoginPage.vue";
import { resetOrphanedOverlayHistory } from "./components/overlay-stack";
resetOrphanedOverlayHistory();
const api = createApiClient(),
  session = useSession(api),
  prefs = usePreferences(),
  route = useRoute();
const { tr } = prefs;
const { notices, notify, dismiss, pause, resume } = useNotices(
  prefs.locale,
  session.epoch,
);
const mobileOpen = shallowRef(false),
  preferencesOpen = shallowRef(false);
const commandRail =
    useTemplateRef<InstanceType<typeof WorkbenchHeader>>("commandRail"),
  mainContent = useTemplateRef<HTMLElement>("mainContent");
let navigationMedia: MediaQueryList | undefined,
  lastNavigationFocus: HTMLElement | null = null;
provide(consoleKey, { api, session, prefs, notify });
const pageTitle = computed(() => {
  const section = [
    ["/instances", tr("实例", "Instances")],
    ["/nodes", tr("节点", "Nodes")],
    ["/networks", tr("网络与 IP", "Networks & IP")],
    ["/operations", tr("操作任务", "Tasks")],
    ["/audit", tr("审计记录", "Audit log")],
    ["/users", tr("成员与权限", "Members & access")],
  ].find(([path]) => route.path === path || route.path.startsWith(`${path}/`));
  return section?.[1] || tr("管理控制台", "Console");
});
const navigationElement = () => commandRail.value?.navigationElement();
const navigationTrigger = () => commandRail.value?.menuElement();
const permission = computed(() => route.meta.permission as string | undefined);
const authorized = computed(
  () => !permission.value || session.can(permission.value),
);
const roleText = computed(() =>
  session.user.value?.role === "admin"
    ? tr("管理员", "Administrator")
    : session.user.value?.role === "operator"
      ? tr("操作员", "Operator")
      : session.user.value?.role === "viewer"
        ? tr("只读成员", "Viewer")
        : tr("自定义角色", "Custom role"),
);
const langOptions = [
  { value: "zh-CN", label: "简体中文" },
  { value: "en", label: "English" },
];
const themeOptions = computed(() => [
  { value: "system", label: tr("跟随系统", "System") },
  { value: "light", label: tr("浅色", "Light") },
  { value: "dark", label: tr("深色", "Dark") },
]);
function locale(value: string) {
  if (value === "zh-CN" || value === "en") prefs.locale.value = value;
}
function appearance(value: string) {
  if (value === "system" || value === "light" || value === "dark")
    prefs.appearance.value = value;
}
function focus() {
  if (session.user.value && !session.busy.value) void session.refresh();
}
function skipToContent() {
  mainContent.value?.focus();
}
function revealNavigationLink(target: HTMLElement) {
  if (!target.matches(".aw-rail-nav a[href]")) return;
  void nextTick(() => {
    if (
      !target.isConnected ||
      document.activeElement !== target ||
      !target.matches(":focus-visible")
    )
      return;
    const navigation = target.closest<HTMLElement>(".aw-rail-nav");
    if (!navigation || navigationElement() !== navigation) return;
    const row = target.getBoundingClientRect();
    const region = navigation.getBoundingClientRect();
    if (!row.height || !region.height) return;
    const style = getComputedStyle(navigation);
    const left = region.left + (parseFloat(style.paddingLeft) || 0);
    const right = region.right - (parseFloat(style.paddingRight) || 0);
    // Some browsers reveal only a link's text on focus. Reveal its entire hit
    // area and focus gutter, scrolling this navigation only, never the page.
    if (row.left < left) navigation.scrollLeft += Math.floor(row.left - left);
    else if (row.right > right)
      navigation.scrollLeft += Math.ceil(row.right - right);
  });
}
function rememberNavigationFocus(event: FocusEvent) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  if (navigationElement()?.contains(target) || target === navigationTrigger()) {
    lastNavigationFocus = target;
    revealNavigationLink(target);
  } else if (target !== document.body && target !== document.documentElement)
    lastNavigationFocus = null;
}
function clearNavigationPointerFocus(event: PointerEvent) {
  const target = event.target;
  if (
    target instanceof Node &&
    !navigationElement()?.contains(target) &&
    !navigationTrigger()?.contains(target)
  )
    lastNavigationFocus = null;
}
function navigationViewportChanged(
  event: Pick<MediaQueryListEvent, "matches">,
) {
  // display:none can blur a link to BODY before the media event. Remember
  // only navigation focus, clearing it when the user interacts elsewhere.
  const current = document.activeElement;
  const active =
    (current === document.body || current === document.documentElement) &&
    lastNavigationFocus?.isConnected
      ? lastNavigationFocus
      : current;
  if (event.matches) {
    if (active instanceof Node && navigationElement()?.contains(active))
      void nextTick(() => {
        if (navigationMedia?.matches) navigationTrigger()?.focus();
      });
    return;
  }
  // Consume the drawer's own history/scroll lock through UiOverlay cleanup.
  // Never leave an open modal over the desktop or restore focus to a hidden
  // mobile trigger after crossing the navigation breakpoint.
  if (mobileOpen.value || active === navigationTrigger()) {
    mobileOpen.value = false;
    void nextTick(() => {
      if (navigationMedia && !navigationMedia.matches)
        mainContent.value?.focus({ preventScroll: true });
    });
  }
}
watch(
  () => route.fullPath,
  () => (mobileOpen.value = false),
);
watch(
  () => session.user.value?.id,
  () => {
    mobileOpen.value = false;
    lastNavigationFocus = null;
  },
);
onMounted(() => {
  void session.refresh();
  navigationMedia = matchMedia("(max-width: 1024px)");
  navigationMedia.addEventListener("change", navigationViewportChanged);
  document.addEventListener("focusin", rememberNavigationFocus);
  document.addEventListener("pointerdown", clearNavigationPointerFocus);
  window.addEventListener("focus", focus);
});
onBeforeUnmount(() => {
  prefs.dispose();
  navigationMedia?.removeEventListener("change", navigationViewportChanged);
  navigationMedia = undefined;
  lastNavigationFocus = null;
  document.removeEventListener("focusin", rememberNavigationFocus);
  document.removeEventListener("pointerdown", clearNavigationPointerFocus);
  window.removeEventListener("focus", focus);
});
</script>
<template>
  <a
    v-if="session.user.value"
    class="skip-link"
    href="#main-content"
    @click.prevent="skipToContent"
    >{{ tr("跳到主要内容", "Skip to content") }}</a
  >
  <div v-if="!session.ready.value" class="boot-state">
    <div class="boot-mark"><Server :size="26" aria-hidden="true" />Aster</div>
    <StateBlock loading />
  </div>
  <template v-else-if="!session.user.value"
    ><div class="login-utilities">
      <button
        class="icon-button"
        type="button"
        :aria-label="tr('语言与外观', 'Language & appearance')"
        :title="tr('语言与外观', 'Language & appearance')"
        @click="preferencesOpen = true"
      >
        <SlidersHorizontal :size="19" aria-hidden="true" />
      </button>
    </div>
    <LoginPage
  /></template>
  <div v-else class="console-shell">
    <div class="console-workspace">
      <NavLinks v-slot="{ items }">
        <WorkbenchHeader
          ref="commandRail"
          :items="items"
          :active-path="route.path"
          :current-page-label="pageTitle"
          :display-name="session.user.value.name || session.user.value.email"
          :role-label="roleText"
          :locale-label="prefs.locale.value === 'zh-CN' ? '中文' : 'EN'"
          :busy="session.busy.value || !!session.pendingAuth.value"
          :navigation-open="mobileOpen"
          :brand-label="tr('Aster 云', 'Aster Cloud')"
          :nav-aria-label="tr('主导航', 'Main navigation')"
          :preferences-label="tr('语言与外观', 'Language & appearance')"
          :logout-label="tr('退出登录', 'Sign out')"
          :menu-label="tr('打开导航', 'Open navigation')"
          :busy-label="tr('正在处理会话', 'Session request in progress')"
          @open-navigation="mobileOpen = true"
          @open-preferences="preferencesOpen = true"
          @logout="session.logout"
        />
      </NavLinks>
      <main
        ref="mainContent"
        id="main-content"
        class="main-content"
        tabindex="-1"
      >
        <InlineError
          v-if="session.error.value"
          :error="session.error.value"
        /><StateBlock
          v-if="!authorized"
          error="forbidden"
          @reload="session.refresh"
        /><RouterView v-else :key="session.user.value.id" />
      </main>
      <footer class="workspace-footer">
        <span>Aster</span
        ><span>{{ tr("基础设施管理", "Infrastructure management") }}</span>
      </footer>
    </div>
  </div>
  <UiOverlay
    :open="mobileOpen"
    :title="tr('导航', 'Navigation')"
    drawer
    :close-label="tr('关闭导航', 'Close navigation')"
    @close="mobileOpen = false"
    ><NavLinks tone="surface" @navigate="mobileOpen = false" />
    <template #footer
      ><div v-if="session.user.value" class="navigation-account">
        <strong :title="session.user.value.name || session.user.value.email">{{
          session.user.value.name || session.user.value.email
        }}</strong>
        <span>{{ roleText }}</span>
      </div>
      <UiButton
        :busy="session.busy.value || !!session.pendingAuth.value"
        @click="
          session.logout();
          mobileOpen = false;
        "
        ><LogOut :size="16" aria-hidden="true" />{{
          tr("退出登录", "Sign out")
        }}</UiButton
      ></template
    ></UiOverlay
  ><UiOverlay
    :open="preferencesOpen"
    :title="tr('语言与外观', 'Language & appearance')"
    :close-label="tr('关闭', 'Close')"
    @close="preferencesOpen = false"
    ><div class="preferences-fields">
      <label class="field"
        >{{ tr("界面语言", "Language")
        }}<UiSelect
          :model-value="prefs.locale.value"
          :options="langOptions"
          :label="tr('界面语言', 'Language')"
          @update:model-value="locale" /></label
      ><label class="field"
        >{{ tr("外观", "Appearance")
        }}<UiSelect
          :model-value="prefs.appearance.value"
          :options="themeOptions"
          :label="tr('外观', 'Appearance')"
          @update:model-value="appearance"
      /></label>
    </div>
    <template #footer
      ><UiButton variant="primary" @click="preferencesOpen = false">{{
        tr("完成", "Done")
      }}</UiButton></template
    ></UiOverlay
  ><ToastStack
    :notices="notices"
    :close-label="tr('关闭通知', 'Dismiss notification')"
    @dismiss="dismiss"
    @pause="pause"
    @resume="resume"
  />
</template>
<style scoped>
.boot-state {
  min-height: 100dvh;
  max-width: 500px;
  margin: auto;
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 32px;
  padding: 24px;
}
.boot-mark {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 24px;
  font-weight: 600;
}
.login-utilities {
  position: absolute;
  right: 24px;
  top: 20px;
  z-index: 20;
}
.console-shell {
  min-height: 100dvh;
  min-width: 0;
}
.console-workspace {
  min-width: 0;
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
}
.main-content {
  flex: 1;
  min-width: 0;
  width: 100%;
  outline: none;
}
.workspace-footer {
  padding: 20px 40px;
  display: flex;
  justify-content: space-between;
  gap: 20px;
  font-size: 11px;
  color: var(--secondary);
  border-top: 1px solid var(--border);
}
.workspace-footer span {
  overflow-wrap: anywhere;
}
.preferences-fields {
  display: flex;
  flex-direction: column;
  gap: 24px;
  min-height: 200px;
}
.navigation-account {
  flex: 1;
  min-width: 0;
  align-self: center;
  font-size: 13px;
  line-height: 1.5;
}
.navigation-account strong,
.navigation-account span {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.navigation-account span {
  color: var(--secondary);
  font-size: 12px;
}
@media (max-width: 1024px) {
  .workspace-footer {
    padding: 20px;
  }
  .login-utilities {
    right: 12px;
    top: 12px;
  }
}
</style>
