<script setup lang="ts">
import { computed, shallowRef, watch } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { Plus, RefreshCw } from "@lucide/vue";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { networkID, networkPage, type NetworkKind } from "../api/network";
import UiButton from "../components/UiButton.vue";
import StateBlock from "../components/StateBlock.vue";
import NetworkNav from "../components/NetworkNav.vue";
import NetworkCreateDialog from "../components/NetworkCreateDialog.vue";

const route = useRoute(),
  router = useRouter();
const {
  session,
  prefs: { tr },
} = useConsole();
const kind = computed(() => route.params.kind as NetworkKind);
const cursor = computed(() =>
  typeof route.query.cursor === "string" ? route.query.cursor : "",
);
const validQuery = computed(
  () =>
    Object.keys(route.query).every((k) => k === "cursor") &&
    (route.query.cursor === undefined || networkID(route.query.cursor)),
);
const list = useQuery(
  () =>
    validQuery.value
      ? `/networks/${kind.value}${cursor.value ? `?cursor=${cursor.value}` : ""}`
      : "INVALID",
  (v) => networkPage(kind.value)(v),
);
const creating = shallowRef<NetworkKind | null>(null);
// Vue Router reuses this page for /networks/:kind (and cursor changes). Closing
// on the actual route identity disposes the old dialog's generation, so an ACK
// for that page cannot resolve pending intent or report success on the new one.
watch(
  () => route.fullPath,
  () => (creating.value = null),
  { flush: "sync" },
);
const title = computed(() =>
  kind.value === "vpcs"
    ? tr("私有网络", "Private networks")
    : kind.value === "pools"
      ? tr("IP 地址池", "IP pools")
      : tr("地址分配", "IP allocations"),
);
const createLabel = computed(() =>
  kind.value === "vpcs"
    ? tr("新建网络", "New network")
    : kind.value === "pools"
      ? tr("新建地址池", "New IP pool")
      : tr("预留地址", "Reserve address"),
);
function page(value: string | null) {
  void router.push({ path: route.path, query: value ? { cursor: value } : {} });
}
</script>
<template>
  <section class="page">
    <header class="page-heading">
      <div>
        <h1>{{ title }}</h1>
        <p>
          {{
            tr(
              "管理客户网络、可用地址与实例预留。",
              "Manage customer networks, address inventory and instance reservations.",
            )
          }}
        </p>
      </div>
      <div class="network-actions">
        <UiButton :busy="list.loading.value" @click="list.reload"
          ><RefreshCw :size="16" aria-hidden="true" />{{
            tr("刷新", "Refresh")
          }}</UiButton
        ><UiButton
          v-if="session.can('nodes.manage')"
          variant="primary"
          @click="creating = kind"
          ><Plus :size="16" aria-hidden="true" />{{ createLabel }}</UiButton
        >
      </div>
    </header>
    <NetworkNav />
    <p class="network-boundary">
      {{
        tr(
          "网络配置与地址预留不代表已接通。节点应用与连通结果需另行确认；未确认解绑前不会自动回收地址。",
          "Configuration and reservations do not confirm connectivity. Node application is verified separately; addresses are not reclaimed without confirmed detachment.",
        )
      }}
    </p>
    <StateBlock
      :loading="list.loading.value"
      :error="list.error.value"
      :empty="!list.data.value?.items.length"
      :title="tr('暂无记录', 'No records yet')"
      :description="
        tr(
          '完成节点配置后，可新建网络、添加地址池并为实例预留地址。',
          'After configuring a node, create a network, add an IP pool and reserve an address for an instance.',
        )
      "
      @reload="list.reload"
    >
      <div class="network-records">
        <article
          v-for="item in list.data.value?.items"
          :key="item.id"
          class="network-record"
        >
          <header>
            <div>
              <h2>
                {{
                  "name" in item
                    ? item.name
                    : "address" in item
                      ? item.address
                      : ""
                }}
              </h2>
              <code>{{ item.id }}</code>
            </div>
            <span class="network-state">{{
              "state" in item
                ? item.state === "planned"
                  ? tr("待应用", "Not applied")
                  : tr("已预留", "Reserved")
                : item.enabled
                  ? tr("可分配", "Available")
                  : tr("已停用", "Disabled")
            }}</span>
          </header>
          <dl>
            <div>
              <dt>{{ tr("计算节点", "Compute node") }}</dt>
              <dd>{{ item.node_id }}</dd>
            </div>
            <div v-if="'owner_ref' in item">
              <dt>{{ tr("客户归属", "Customer owner") }}</dt>
              <dd class="mono">{{ item.owner_ref }}</dd>
            </div>
            <div v-if="'cidr' in item">
              <dt>{{ tr("网段", "Subnet") }}</dt>
              <dd>{{ item.cidr }}</dd>
            </div>
            <div v-if="'vlan_id' in item">
              <dt>VLAN</dt>
              <dd>{{ item.vlan_id }}</dd>
            </div>
            <div v-if="'gateway' in item">
              <dt>{{ tr("网关", "Gateway") }}</dt>
              <dd>{{ item.gateway }}</dd>
            </div>
            <div v-if="'addresses' in item">
              <dt>{{ tr("池内地址数", "Addresses in pool") }}</dt>
              <dd>{{ item.addresses.length }}</dd>
            </div>
            <div v-if="'vpc_id' in item">
              <dt>{{ tr("所属网络", "Network") }}</dt>
              <dd class="mono">
                {{ item.vpc_id || tr("经典网络", "Classic network") }}
              </dd>
            </div>
            <div v-if="'instance_id' in item">
              <dt>{{ tr("实例", "Instance") }}</dt>
              <dd>
                <RouterLink
                  :to="`/instances/${item.instance_id}`"
                  class="mono"
                  >{{ item.instance_id }}</RouterLink
                >
              </dd>
            </div>
            <div v-if="'pool_id' in item">
              <dt>{{ tr("地址池", "IP pool") }}</dt>
              <dd class="mono">{{ item.pool_id }}</dd>
            </div>
          </dl>
          <details v-if="'addresses' in item">
            <summary>{{ tr("查看地址", "View addresses") }}</summary>
            <p class="address-list">{{ item.addresses.join(" · ") }}</p>
          </details>
        </article>
      </div>
    </StateBlock>
    <footer class="network-pagination">
      <UiButton v-if="cursor" @click="page(null)">{{
        tr("返回首页", "First page")
      }}</UiButton
      ><UiButton
        v-if="list.data.value?.next_cursor"
        @click="page(list.data.value.next_cursor)"
        >{{ tr("下一页", "Next page") }}</UiButton
      >
    </footer>
    <NetworkCreateDialog
      v-if="creating"
      :open="!!creating"
      :kind="creating"
      @close="creating = null"
      @saved="list.reload"
    />
  </section>
</template>
<style scoped>
.network-actions {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
.network-tabs {
  display: flex;
  gap: 4px;
  border-bottom: 1px solid var(--border);
  overflow-x: auto;
}
.network-tabs a {
  display: block;
  flex-shrink: 0;
  padding: 12px 18px;
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
.network-boundary {
  color: var(--secondary);
  font-size: 13px;
  line-height: 1.7;
  margin: 14px 0 20px;
}
.network-records {
  display: block;
  border-top: 1px solid var(--border);
}
.network-record {
  min-width: 0;
  background: var(--surface);
  border: 0;
  border-radius: 0;
  padding: 18px 0;
  border-bottom: 1px solid var(--border);
  display: grid;
  grid-template-columns: minmax(190px, 1fr) minmax(0, 3fr);
  gap: 16px 28px;
}
.network-record header {
  display: flex;
  justify-content: flex-start;
  gap: 12px;
  align-items: flex-start;
  flex-direction: column;
  grid-column: 1;
  grid-row: 1;
}
.network-record h2 {
  font-size: 16px;
  margin: 0 0 6px;
  overflow-wrap: anywhere;
}
.network-record code {
  color: var(--secondary);
  font-size: 12px;
  overflow-wrap: anywhere;
}
.network-state {
  flex-shrink: 0;
  background: var(--subtle);
  color: var(--secondary);
  font-size: 12px;
  border-radius: 4px;
  padding: 5px 8px;
}
.network-record dl {
  display: grid;
  gap: 12px 22px;
  margin: 0;
  font-size: 14px;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  grid-column: 2;
  grid-row: 1;
}
.network-record dl > div {
  display: grid;
  grid-template-columns: 84px minmax(0, 1fr);
  gap: 10px;
  line-height: 1.6;
}
.network-record dt {
  color: var(--secondary);
}
.network-record dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.mono {
  font:
    12px/1.65 ui-monospace,
    monospace;
}
.network-record details {
  margin-top: 0;
  padding-top: 0;
  border-top: 0;
  font-size: 14px;
  grid-column: 2;
}
.network-record summary {
  cursor: pointer;
}
.address-list {
  max-height: 180px;
  overflow: auto;
  line-height: 1.9;
  overflow-wrap: anywhere;
  color: var(--secondary);
}
.network-pagination {
  display: flex;
  justify-content: flex-end;
  gap: 10px;
  margin-top: 24px;
}
@media (max-width: 420px) {
  .network-tabs a {
    padding-inline: 12px;
  }
}
@media (max-width: 900px) {
  .network-record {
    display: block;
    padding: 18px 0;
  }
  .network-record header {
    flex-direction: row;
  }
  .network-record dl {
    margin-top: 16px;
  }
  .network-record details {
    margin-top: 16px;
  }
}
@media (max-width: 600px) {
  .network-record dl {
    grid-template-columns: minmax(0, 1fr);
  }
  .network-record dl > div {
    grid-template-columns: 88px minmax(0, 1fr);
  }
  .network-record {
    padding: 18px 0;
  }
}
</style>
