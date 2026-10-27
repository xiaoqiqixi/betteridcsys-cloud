<script setup lang="ts">
import { computed, useTemplateRef } from "vue";
import { RouterLink } from "vue-router";
import {
  Cloud,
  ChevronRight,
  SlidersHorizontal,
  LogOut,
  Menu,
  Loader2,
  UserCheck,
} from "@lucide/vue";

export interface WorkbenchNavItem {
  path: string;
  label: string;
  matchPath?: string;
}

export interface WorkbenchHeaderProps {
  items: WorkbenchNavItem[];
  activePath: string;
  currentPageLabel?: string;
  navigationOpen?: boolean;
  displayName: string;
  roleLabel: string;
  localeLabel: string;
  busy: boolean;
  brandLabel?: string;
  navAriaLabel?: string;
  preferencesLabel?: string;
  logoutLabel?: string;
  menuLabel?: string;
  busyLabel?: string;
}

const props = withDefaults(defineProps<WorkbenchHeaderProps>(), {
  items: () => [],
  activePath: "",
  currentPageLabel: "",
  navigationOpen: false,
  displayName: "",
  roleLabel: "",
  localeLabel: "",
  busy: false,
  brandLabel: "Aster Cloud",
  navAriaLabel: "Primary Navigation",
  preferencesLabel: "Preferences & Locale",
  logoutLabel: "Log out",
  menuLabel: "Open navigation menu",
  busyLabel: "Synchronizing",
});

const emit = defineEmits<{
  (e: "navigate", path: string): void;
  (e: "open-navigation"): void;
  (e: "open-preferences"): void;
  (e: "logout"): void;
}>();

const navigation = useTemplateRef<HTMLElement>("navigation");
const menu = useTemplateRef<HTMLButtonElement>("menu");
defineExpose({
  navigationElement: () => navigation.value,
  menuElement: () => menu.value,
});

function isItemActive(item: WorkbenchNavItem): boolean {
  const section = item.matchPath ?? item.path;
  return (
    props.activePath === section ||
    (section !== "/" && props.activePath.startsWith(`${section}/`))
  );
}
const activeItem = computed(
  () =>
    props.items
      .filter(isItemActive)
      .sort(
        (a, b) =>
          (b.matchPath ?? b.path).length - (a.matchPath ?? a.path).length,
      )[0],
);
const currentEntryLabel = computed(
  () => props.currentPageLabel || activeItem.value?.label || "",
);
const hasIdentity = computed(() =>
  Boolean(props.displayName.trim() || props.roleLabel.trim()),
);
function logout() {
  if (!props.busy) emit("logout");
}
</script>

<template>
  <header
    class="aw-command-rail"
    :class="{ 'is-busy': busy }"
    :aria-busy="busy ? 'true' : 'false'"
  >
    <!-- Left Zone: Brand & Compact Active Context (<=1024px) -->
    <div class="aw-rail-left">
      <RouterLink class="aw-brand" to="/instances" :title="brandLabel">
        <span class="aw-brand-Glyph" aria-hidden="true">
          <Cloud class="aw-icon-brand" />
        </span>
        <span class="aw-brand-text">{{ brandLabel }}</span>
      </RouterLink>

      <!-- Compact current entry indicator shown on <=1024px -->
      <div
        v-if="currentEntryLabel"
        class="aw-mobile-context"
        :title="currentEntryLabel"
      >
        <ChevronRight class="aw-icon-sep" aria-hidden="true" />
        <span class="aw-mobile-current-label" aria-current="page">
          {{ currentEntryLabel }}
        </span>
      </div>
    </div>

    <!-- Center Zone: Horizontal 6-Entry Navigation (>1024px) -->
    <nav
      ref="navigation"
      class="aw-rail-nav"
      tabindex="-1"
      :aria-label="navAriaLabel"
    >
      <RouterLink
        v-for="item in items"
        :key="item.path"
        :to="item.path"
        custom
        v-slot="{ href, navigate }"
      >
        <a
          :href="href"
          class="aw-nav-item"
          :class="{ 'is-active': isItemActive(item) }"
          :aria-current="isItemActive(item) ? 'page' : undefined"
          :title="item.label"
          @click="navigate"
          ><span class="aw-nav-item-text">{{ item.label }}</span></a
        >
      </RouterLink>
    </nav>

    <!-- Right Zone: Low-interference Account, Locale/Appearance, Logout & Compact Menu -->
    <div class="aw-rail-right">
      <!-- Non-blocking busy status indicator -->
      <span
        v-if="busy"
        class="aw-busy-indicator"
        role="status"
        :title="busyLabel"
        :aria-label="busyLabel"
      >
        <Loader2 class="aw-icon aw-spin" aria-hidden="true" />
      </span>

      <!-- Quiet Account Pill (Desktop >1024px) -->
      <div
        v-if="hasIdentity"
        class="aw-account-pill"
        :title="roleLabel ? `${displayName} (${roleLabel})` : displayName"
      >
        <UserCheck class="aw-icon-subtle" aria-hidden="true" />
        <span v-if="displayName" class="aw-account-name">
          {{ displayName }}
        </span>
        <span v-if="roleLabel" class="aw-account-role">
          {{ roleLabel }}
        </span>
      </div>

      <!-- Preferences / Locale & Appearance Trigger -->
      <button
        type="button"
        class="aw-rail-action aw-pref-trigger"
        :aria-label="preferencesLabel"
        :title="
          localeLabel
            ? `${preferencesLabel} · ${localeLabel}`
            : preferencesLabel
        "
        @click="emit('open-preferences')"
      >
        <SlidersHorizontal class="aw-icon" aria-hidden="true" />
        <span v-if="localeLabel" class="aw-action-badge">
          {{ localeLabel }}
        </span>
      </button>

      <!-- Logout Trigger -->
      <button
        type="button"
        class="aw-rail-action aw-logout-trigger"
        :disabled="busy"
        :aria-label="logoutLabel"
        :title="logoutLabel"
        @click="logout"
      >
        <LogOut class="aw-icon" aria-hidden="true" />
        <span class="aw-logout-label">{{ logoutLabel }}</span>
      </button>

      <!-- Compact Menu Trigger (<=1024px) -->
      <button
        type="button"
        ref="menu"
        class="aw-rail-action aw-menu-trigger"
        :aria-expanded="navigationOpen"
        aria-haspopup="dialog"
        :aria-label="menuLabel"
        :title="menuLabel"
        @click="emit('open-navigation')"
      >
        <Menu class="aw-icon" aria-hidden="true" />
      </button>
    </div>
  </header>
</template>

<style scoped>
.aw-command-rail {
  --aw-rail-bg: var(--surface);
  --aw-rail-border: var(--border);
  --aw-rail-text: var(--text);
  --aw-rail-text-muted: var(--secondary);
  --aw-rail-text-subtle: var(--muted);
  --aw-rail-surface-hover: var(--hover);
  --aw-rail-surface-active: var(--subtle);
  --aw-rail-accent: var(--accent-text);
  --aw-rail-accent-soft: var(--accent-bg);
  --aw-rail-pill-bg: var(--subtle);
  --aw-rail-pill-border: var(--border);
  --aw-rail-danger-hover: var(--danger);
  --aw-rail-danger-bg: var(--danger-bg);
  --aw-rail-focus: var(--accent);

  position: sticky;
  top: 0;
  z-index: 20;
  flex-shrink: 0;
  box-sizing: border-box;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
  max-width: 100%;
  height: 52px;
  min-height: 48px;
  max-height: 56px;
  padding: 0 12px;
  background-color: var(--aw-rail-bg);
  border-bottom: 1px solid var(--aw-rail-border);
  color: var(--aw-rail-text);
  font-family:
    -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC",
    "Microsoft YaHei", sans-serif;
  font-size: 13px;
  line-height: 1.2;
  user-select: none;
  overflow: hidden;
}

/* Left Zone */
.aw-rail-left {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  flex: 0 1 auto;
}

.aw-brand {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  padding: 4px 6px 4px 2px;
  font-weight: 600;
  font-size: 14px;
  letter-spacing: -0.01em;
  text-decoration: none;
  color: var(--aw-rail-text);
}

.aw-brand-Glyph {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border-radius: 6px;
  background-color: var(--aw-rail-accent-soft);
  color: var(--aw-rail-accent);
  flex-shrink: 0;
}

.aw-icon-brand {
  width: 16px;
  height: 16px;
}

.aw-brand-text {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Compact Active Entry (hidden on desktop, visible <=1024px) */
.aw-mobile-context {
  display: none;
  align-items: center;
  gap: 4px;
  min-width: 0;
  flex: 1 1 auto;
}

.aw-icon-sep {
  width: 14px;
  height: 14px;
  color: var(--aw-rail-text-subtle);
  flex-shrink: 0;
}

.aw-mobile-current-label {
  display: inline-block;
  min-width: 0;
  padding: 3px 8px;
  border-radius: 6px;
  background-color: var(--aw-rail-accent-soft);
  color: var(--aw-rail-accent);
  font-weight: 600;
  font-size: 12px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Center Zone: Desktop Horizontal Navigation */
.aw-rail-nav {
  display: flex;
  align-items: center;
  gap: 2px;
  flex: 1 1 auto;
  min-width: 0;
  height: 100%;
  padding: 0 4px;
  overflow-x: auto;
  /* Keep the full 44px focus target inside the fixed 52px rail. The scrollport
     remains wheel/touch/keyboard scrollable without a platform-sized gutter. */
  scrollbar-width: none;
  overscroll-behavior-x: contain;
}
.aw-rail-nav::-webkit-scrollbar {
  display: none;
}

.aw-nav-item {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 44px;
  min-height: 44px;
  padding: 0 11px;
  border: none;
  border-radius: 6px;
  background: transparent;
  color: var(--aw-rail-text-muted);
  font: inherit;
  font-weight: 500;
  cursor: pointer;
  flex: 0 0 auto;
  text-decoration: none;
  transition:
    background-color 0.14s ease,
    color 0.14s ease;
}

.aw-nav-item:hover {
  background-color: var(--aw-rail-surface-hover);
  color: var(--aw-rail-text);
}

.aw-nav-item.is-active {
  color: var(--aw-rail-accent);
  background-color: var(--aw-rail-accent-soft);
  font-weight: 600;
}

.aw-nav-item.is-active::after {
  content: "";
  position: absolute;
  left: 10px;
  right: 10px;
  bottom: 2px;
  height: 2px;
  border-radius: 2px;
  background-color: var(--aw-rail-accent);
}

.aw-nav-item-text {
  display: block;
  max-width: 148px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* Right Zone: Account & Utility Controls */
.aw-rail-right {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-shrink: 0;
  min-width: 0;
}

.aw-busy-indicator {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  color: var(--aw-rail-accent);
  flex-shrink: 0;
}

.aw-account-pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 32px;
  max-width: 240px;
  padding: 0 10px;
  margin-right: 2px;
  border-radius: 999px;
  background-color: var(--aw-rail-pill-bg);
  border: 1px solid var(--aw-rail-pill-border);
  color: var(--aw-rail-text);
  font-size: 12px;
  min-width: 0;
}

.aw-icon-subtle {
  width: 14px;
  height: 14px;
  color: var(--aw-rail-text-subtle);
  flex-shrink: 0;
}

.aw-account-name {
  font-weight: 600;
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.aw-account-role {
  padding: 1px 6px;
  border-radius: 4px;
  background-color: var(--aw-rail-surface-active);
  color: var(--aw-rail-text-muted);
  font-size: 11px;
  font-weight: 500;
  max-width: 88px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.aw-rail-action {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 5px;
  min-width: 44px;
  min-height: 44px;
  padding: 0 10px;
  border: none;
  border-radius: 6px;
  background: transparent;
  color: var(--aw-rail-text-muted);
  font: inherit;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  flex-shrink: 0;
  transition:
    background-color 0.14s ease,
    color 0.14s ease;
}

.aw-rail-action:hover {
  background-color: var(--aw-rail-surface-hover);
  color: var(--aw-rail-text);
}

.aw-logout-trigger:hover {
  background-color: var(--aw-rail-danger-bg);
  color: var(--aw-rail-danger-hover);
}

.aw-action-badge {
  max-width: 72px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.aw-logout-label {
  max-width: 84px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.aw-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.aw-menu-trigger {
  display: none;
}

.aw-rail-action:disabled {
  cursor: wait;
  opacity: 0.55;
}

/* Keyboard Focus Visibility */
.aw-nav-item:focus-visible,
.aw-rail-action:focus-visible {
  outline: 2px solid var(--aw-rail-focus);
  outline-offset: -2px;
}

/* Spin Animation */
@keyframes aw-rail-spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

.aw-spin {
  animation: aw-rail-spin 0.9s linear infinite;
}

/* Compact Mode: <=1024px */
@media (max-width: 1024px) {
  .aw-rail-nav,
  .aw-account-pill,
  .aw-logout-trigger {
    display: none;
  }

  .aw-rail-left {
    flex: 1 1 auto;
    min-width: 0;
  }

  .aw-mobile-context {
    display: inline-flex;
  }

  .aw-menu-trigger {
    display: inline-flex;
  }

  .aw-rail-action {
    padding: 0 8px;
  }
}

/* Ultra-Compact Viewport Safety: <=480px down to 320px */
@media (max-width: 480px) {
  .aw-command-rail {
    padding: 0 6px;
    gap: 4px;
  }

  .aw-brand {
    padding: 2px;
    gap: 6px;
  }

  .aw-brand-text {
    max-width: 86px;
  }

  .aw-action-badge {
    display: none;
  }

  .aw-rail-right {
    gap: 2px;
  }

  .aw-rail-action {
    padding: 0 6px;
  }
}

/* Reduced Motion Preference */
@media (prefers-reduced-motion: reduce) {
  .aw-nav-item,
  .aw-rail-action {
    transition: none;
  }

  .aw-spin {
    animation: none;
  }
}
</style>
