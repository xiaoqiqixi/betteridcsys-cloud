<script setup lang="ts">
import { computed } from "vue";
import {
  RouterLink,
  isNavigationFailure,
  NavigationFailureType,
  useRouter,
} from "vue-router";
import {
  Server,
  Network,
  Waypoints,
  ListChecks,
  ShieldCheck,
  Users,
} from "@lucide/vue";
import { useConsole } from "../context";
const { tone = "sidebar" } = defineProps<{ tone?: "sidebar" | "surface" }>();
const emit = defineEmits<{ navigate: [] }>();
const router = useRouter();
const {
  session,
  prefs: { tr },
} = useConsole();
const links = computed(() =>
  [
    {
      path: "/instances",
      label: tr("实例", "Instances"),
      icon: Server,
      permission: "instances.read",
    },
    {
      path: "/nodes",
      label: tr("节点", "Nodes"),
      icon: Network,
      permission: "nodes.read",
    },
    {
      path: "/networks/overlays",
      matchPath: "/networks",
      label: tr("网络与 IP", "Networks & IP"),
      icon: Waypoints,
      permission: "nodes.read",
    },
    {
      path: "/operations",
      label: tr("操作任务", "Tasks"),
      icon: ListChecks,
      permission: "instances.read",
    },
    {
      path: "/audit",
      label: tr("审计记录", "Audit log"),
      icon: ShieldCheck,
      permission: "audit.read",
    },
    {
      path: "/users",
      label: tr("成员与权限", "Members & access"),
      icon: Users,
      permission: "users.manage",
    },
  ].filter((item) => session.can(item.permission)),
);
function active(item: { path: string; matchPath?: string }) {
  const section = item.matchPath || item.path;
  return (
    router.currentRoute.value.path === section ||
    router.currentRoute.value.path.startsWith(`${section}/`)
  );
}
async function follow(
  event: MouseEvent,
  navigate: (event: MouseEvent) => Promise<unknown>,
  fullPath: string,
) {
  if (event.defaultPrevented) return;
  const result = await navigate(event);
  if (
    event.defaultPrevented &&
    router.currentRoute.value.fullPath === fullPath &&
    (!isNavigationFailure(result) ||
      isNavigationFailure(result, NavigationFailureType.duplicated))
  )
    emit("navigate");
}
</script>
<template>
  <slot :items="links">
    <nav
      class="nav-links"
      :class="`tone-${tone}`"
      :aria-label="tr('主导航', 'Main navigation')"
    >
      <RouterLink
        v-for="link in links"
        :key="link.path"
        :to="link.path"
        :replace="tone === 'surface'"
        custom
        v-slot="{ href, navigate, route }"
        ><a
          :href="href"
          :class="{ 'is-current': active(link) }"
          :aria-current="active(link) ? 'page' : undefined"
          @click="follow($event, navigate, route.fullPath)"
          ><component :is="link.icon" :size="19" aria-hidden="true" /><span>{{
            link.label
          }}</span></a
        ></RouterLink
      >
    </nav>
  </slot>
</template>
<style scoped>
.nav-links {
  --nav-text: var(--sidebar-secondary);
  --nav-hover: var(--sidebar-hover);
  --nav-hover-text: var(--sidebar-text);
  --nav-current-text: var(--sidebar-text);
  --nav-current-bg: var(--sidebar-selected);
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.nav-links.tone-surface {
  --nav-text: var(--secondary);
  --nav-hover: var(--hover);
  --nav-hover-text: var(--text);
  --nav-current-text: var(--accent-text);
  --nav-current-bg: var(--accent-bg);
}
.nav-links a {
  display: flex;
  align-items: center;
  gap: 12px;
  min-height: 46px;
  padding: 12px 14px;
  border-radius: 10px;
  color: var(--nav-text);
  text-decoration: none;
  font-size: 14px;
  font-weight: 500;
  transition:
    background 0.12s,
    color 0.12s;
}
.nav-links a:hover {
  background: var(--nav-hover);
  color: var(--nav-hover-text);
}
.nav-links .is-current {
  color: var(--nav-current-text);
  background: var(--nav-current-bg);
}
.nav-links svg {
  flex-shrink: 0;
}
.nav-links span {
  overflow-wrap: anywhere;
}
</style>
