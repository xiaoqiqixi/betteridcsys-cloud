<script setup lang="ts">
import { computed } from "vue";
import { RouterLink, useRoute } from "vue-router";
import { useConsole } from "../context";
const route = useRoute(),
  {
    prefs: { tr },
  } = useConsole();
const items = computed(() => [
  { path: "/networks/overlays", label: tr("VPC 与路由", "VPC & routing") },
  { path: "/networks/public-ips", label: tr("公网 IP", "Public IPs") },
  { path: "/networks/vpcs", label: tr("节点网络", "Node networks") },
  { path: "/networks/pools", label: tr("IP 地址池", "IP pools") },
  { path: "/networks/leases", label: tr("地址分配", "IP allocations") },
]);
</script>
<template>
  <nav class="network-tabs" :aria-label="tr('网络分类', 'Network sections')">
    <RouterLink
      v-for="item in items"
      :key="item.path"
      :to="item.path"
      :aria-current="
        route.path === item.path ||
        (item.path === '/networks/overlays' &&
          route.path.startsWith('/networks/epochs/'))
          ? 'page'
          : undefined
      "
      >{{ item.label }}</RouterLink
    >
  </nav>
</template>
<style scoped>
.network-tabs {
  display: flex;
  gap: 4px;
  border-bottom: 1px solid var(--border);
  overflow-x: auto;
  margin-bottom: 24px;
}
.network-tabs a {
  display: block;
  flex-shrink: 0;
  padding: 14px 16px;
  color: var(--secondary);
  text-decoration: none;
  font-size: 14px;
  border-bottom: 2px solid transparent;
}
.network-tabs a[aria-current="page"] {
  color: var(--accent-text);
  border-color: var(--accent);
  font-weight: 600;
}
@media (max-width: 420px) {
  .network-tabs a {
    padding-inline: 12px;
  }
}
</style>
