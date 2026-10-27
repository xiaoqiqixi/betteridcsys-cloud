<script setup lang="ts">
import { computed, shallowRef, watch } from "vue";
import { useRoute, useRouter, RouterLink } from "vue-router";
import { Plus, RefreshCw } from "@lucide/vue";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { usePublicIPMutation } from "../composables/public-ip-mutation";
import {
  publicIPPage,
  validPublicIPOptions,
  type PublicIPAction,
  type PublicIPPool,
  type PublicIPLease,
} from "../api/public-ip";
import { dateText } from "../format";
import { clusterID } from "../api/overlay";
import { networkID } from "../api/network";
import UiButton from "../components/UiButton.vue";
import UiSelect from "../components/UiSelect.vue";
import StateBlock from "../components/StateBlock.vue";
import InlineError from "../components/InlineError.vue";
import NetworkNav from "../components/NetworkNav.vue";
import PublicIPDialog from "../components/PublicIPDialog.vue";
import PublicIPResourcesPanel from "../components/PublicIPResourcesPanel.vue";
const {
    session,
    prefs: { tr, locale },
    notify,
  } = useConsole(),
  route = useRoute(),
  router = useRouter();
const options = useQuery(() => "/public-ips/options", validPublicIPOptions);
const cluster = computed(() =>
  typeof route.query.cluster === "string"
    ? route.query.cluster
    : options.data.value?.clusters[0]?.id || "",
);
const view = computed(() =>
  route.query.view === "resources"
    ? "resources"
    : route.query.view === "leases"
      ? "leases"
      : "pools",
);
const cursor = computed(() =>
  typeof route.query.cursor === "string" ? route.query.cursor : "",
);
const validQuery = computed(
  () =>
    Object.keys(route.query).every((k) =>
      ["cluster", "view", "cursor"].includes(k),
    ) &&
    (route.query.cluster === undefined || clusterID(route.query.cluster)) &&
    (route.query.cursor === undefined || networkID(route.query.cursor)) &&
    (route.query.view === undefined ||
      ["pools", "leases", "resources"].includes(String(route.query.view))),
);
const list = useQuery(
  () =>
    validQuery.value
      ? `/public-ips/${view.value === "resources" ? "pools" : view.value}${cluster.value || cursor.value ? "?" + new URLSearchParams({ ...(cluster.value ? { cluster_id: cluster.value } : {}), ...(cursor.value ? { cursor: cursor.value } : {}) }) : ""}`
      : "INVALID",
  (
    v,
  ): v is {
    items: (PublicIPPool | PublicIPLease)[];
    next_cursor: string | null;
  } =>
    publicIPPage(view.value === "resources" ? "pools" : view.value)(v) &&
    (!cluster.value ||
      v.items.every((item) => item.cluster_id === cluster.value)),
);
const mutation = usePublicIPMutation();
const editing = shallowRef<{
  action: PublicIPAction;
  pool?: PublicIPPool;
  lease?: PublicIPLease;
} | null>(null);
const expanded = shallowRef<string[]>([]);
const canManage = computed(
  () => session.can("nodes.manage") && session.can("instances.manage"),
);
const pools = computed(() =>
  view.value === "pools"
    ? (list.data.value?.items as PublicIPPool[] | undefined)
    : [],
);
const leases = computed(() =>
  view.value === "leases"
    ? (list.data.value?.items as PublicIPLease[] | undefined)
    : [],
);
watch(
  () => route.fullPath,
  () => {
    editing.value = null;
    expanded.value = [];
  },
  { flush: "sync" },
);
function navigate(kind: string, selected = cluster.value, next = "") {
  void router.push({
    path: route.path,
    query: {
      view: kind,
      ...(selected ? { cluster: selected } : {}),
      ...(next ? { cursor: next } : {}),
    },
  });
}
function edit(
  action: PublicIPAction,
  pool?: PublicIPPool,
  lease?: PublicIPLease,
) {
  if (
    canManage.value &&
    !mutation.busy.value &&
    !mutation.pending.value &&
    options.data.value
  ) {
    editing.value = { action, pool, lease };
  }
}
async function submit(
  action: PublicIPAction,
  target: string,
  body: Record<string, unknown>,
) {
  const result = await mutation.execute(action, target, body);
  if (result) {
    editing.value = null;
    notify(tr("已保存公网 IP 配置", "Public IP configuration saved"), "info");
    void list.reload();
  }
}
async function reconcile() {
  const result = await mutation.reconcile();
  if (result) {
    editing.value = null;
    notify(tr("原操作已核实", "Original operation verified"), "info");
    void list.reload();
  }
}
const bindingLabel = (v: string) =>
  v === "bound"
    ? tr("已绑定出口", "Bound to egress")
    : v === "pending"
      ? tr("变更待确认", "Change unconfirmed")
      : v === "release_blocked"
        ? tr("暂不可回收", "Reclamation blocked")
        : v === "released"
          ? tr("已回收", "Reclaimed")
          : tr("已分配，尚未绑定", "Allocated, not bound");
</script>
<template>
  <section class="page">
    <header class="page-heading">
      <div>
        <h1>{{ tr("公网 IP", "Public IPs") }}</h1>
        <p>
          {{
            tr(
              "管理地址池、实例公网地址与共享 NAT 出口。",
              "Manage pools, VM public addresses and shared NAT egress.",
            )
          }}
        </p>
      </div>
      <div class="ip-actions">
        <UiButton
          v-if="view !== 'resources'"
          :busy="list.loading.value"
          @click="list.reload"
          ><RefreshCw :size="16" aria-hidden="true" />{{
            tr("刷新", "Refresh")
          }}</UiButton
        ><UiButton
          v-if="canManage && view === 'pools'"
          variant="primary"
          :disabled="
            !options.data.value ||
            !cluster ||
            !!mutation.pending.value ||
            mutation.busy.value
          "
          @click="edit('pool.create')"
          ><Plus :size="16" aria-hidden="true" />{{
            tr("新建地址池", "New pool")
          }}</UiButton
        >
      </div>
    </header>
    <NetworkNav />
    <div class="ip-toolbar">
      <label class="field ip-cluster"
        >{{ tr("集群", "Cluster")
        }}<UiSelect
          :model-value="cluster"
          :options="
            options.data.value?.clusters.map((c) => ({
              value: c.id,
              label: c.id,
            })) || []
          "
          :disabled="options.loading.value"
          :label="tr('集群', 'Cluster')"
          @update:model-value="navigate(view, $event)"
      /></label>
      <nav
        class="ip-views"
        :aria-label="tr('公网地址视图', 'Public address views')"
      >
        <button
          :aria-current="view === 'pools' ? 'page' : undefined"
          @click="navigate('pools')"
        >
          {{ tr("地址池", "Pools") }}</button
        ><button
          :aria-current="view === 'leases' ? 'page' : undefined"
          @click="navigate('leases')"
        >
          {{ tr("分配记录", "Allocations") }}</button
        ><button
          :aria-current="view === 'resources' ? 'page' : undefined"
          @click="navigate('resources')"
        >
          {{ tr("实例公网地址", "VM public addresses") }}
        </button>
      </nav>
    </div>
    <PublicIPResourcesPanel
      v-if="view === 'resources' && validQuery"
      :key="cluster"
      :cluster="cluster"
      :cursor="cursor"
      @page="navigate('resources', cluster, $event)"
    />
    <template v-else>
      <InlineError v-if="options.error.value" :error="options.error.value" />
      <section v-if="mutation.pending.value" class="ip-pending" role="status">
        <div>
          <strong>{{
            tr("有一项操作等待核实", "An operation needs verification")
          }}</strong>
          <p>
            {{
              tr(
                "在核实结果前不会发起新的地址操作。",
                "New address operations are paused until the result is verified.",
              )
            }}
          </p>
          <code>{{ mutation.pending.value.key }}</code>
        </div>
        <UiButton :busy="mutation.busy.value" @click="reconcile">{{
          tr("核对原操作", "Check original operation")
        }}</UiButton>
      </section>
      <InlineError
        v-if="mutation.error.value && !editing"
        :error="mutation.error.value"
      />
      <StateBlock
        :loading="list.loading.value || options.loading.value"
        :error="list.error.value"
        :empty="!list.data.value?.items.length"
        :title="
          view === 'pools'
            ? tr('暂无公网地址池', 'No public IP pools')
            : tr('暂无分配记录', 'No allocations')
        "
        :description="
          view === 'pools'
            ? tr(
                '添加已配置的公网地址，再为 VPC 分配出口。',
                'Add configured public addresses, then allocate them to VPC egress.',
              )
            : tr(
                '从地址池分配的记录会保留在这里，回收不会删除历史。',
                'Allocation history is retained here, including reclaimed addresses.',
              )
        "
        @reload="list.reload"
      >
        <div class="ip-records">
          <article v-for="pool in pools" :key="pool.id" class="ip-record">
            <header class="ip-record-heading">
              <div>
                <h2>{{ pool.name }}</h2>
                <code>{{ pool.cidr }}</code>
              </div>
              <span class="ip-status">{{
                pool.enabled
                  ? tr("可分配", "Allocatable")
                  : tr("已停用", "Disabled")
              }}</span>
            </header>
            <p class="ip-meta">
              {{ tr("地址数量", "Addresses") }} · {{ pool.addresses.length }}
            </p>
            <div class="ip-addresses">
              <code
                v-for="ip in expanded.includes(pool.id)
                  ? pool.addresses
                  : pool.addresses.slice(0, 8)"
                :key="ip"
                >{{ ip }}</code
              >
            </div>
            <UiButton
              v-if="pool.addresses.length > 8"
              @click="
                expanded = expanded.includes(pool.id)
                  ? expanded.filter((id) => id !== pool.id)
                  : [...expanded, pool.id]
              "
              >{{
                expanded.includes(pool.id)
                  ? tr("收起地址", "Collapse addresses")
                  : tr("查看全部地址", "View all addresses")
              }}</UiButton
            >
            <footer class="ip-record-actions">
              <code class="ip-id">{{ pool.id }}</code>
              <div v-if="canManage" class="ip-actions">
                <UiButton
                  :disabled="
                    !!mutation.pending.value ||
                    mutation.busy.value ||
                    pool.addresses.length >= 4096
                  "
                  @click="edit('pool.extend', pool)"
                  >{{ tr("补充地址", "Add addresses") }}</UiButton
                >
                <UiButton
                  :disabled="!!mutation.pending.value || mutation.busy.value"
                  @click="edit('pool.state', pool)"
                  >{{
                    pool.enabled
                      ? tr("停用分配", "Disable allocations")
                      : tr("启用分配", "Enable allocations")
                  }}</UiButton
                ><UiButton
                  variant="primary"
                  :disabled="
                    !pool.enabled ||
                    !!mutation.pending.value ||
                    mutation.busy.value
                  "
                  @click="edit('lease.allocate', pool)"
                  >{{ tr("分配地址", "Allocate address") }}</UiButton
                >
              </div>
            </footer>
          </article>
          <article v-for="lease in leases" :key="lease.id" class="ip-record">
            <header class="ip-record-heading">
              <div>
                <h2>{{ lease.address }}</h2>
                <span class="ip-meta">{{
                  options.data.value?.vpcs.find((v) => v.id === lease.vpc_id)
                    ?.name || lease.vpc_id
                }}</span>
              </div>
              <span class="ip-status">{{
                bindingLabel(lease.binding_state)
              }}</span>
            </header>
            <dl class="ip-details">
              <div>
                <dt>{{ tr("计算节点", "Compute node") }}</dt>
                <dd>{{ lease.node_id }}</dd>
              </div>
              <div>
                <dt>{{ tr("NAT 出口", "NAT egress") }}</dt>
                <dd>{{ lease.profile_id }}</dd>
              </div>
              <div>
                <dt>{{ tr("客户归属", "Customer owner") }}</dt>
                <dd>{{ lease.owner_ref }}</dd>
              </div>
              <div>
                <dt>{{ tr("分配时间", "Allocated at") }}</dt>
                <dd>{{ dateText(lease.created_at, locale) }}</dd>
              </div>
              <div v-if="lease.state === 'released'">
                <dt>{{ tr("回收时间", "Reclaimed at") }}</dt>
                <dd>{{ dateText(lease.updated_at, locale) }}</dd>
              </div>
            </dl>
            <p
              v-if="!lease.releasable && lease.state !== 'released'"
              class="ip-meta"
            >
              {{
                tr(
                  "先解除 NAT 绑定并确认网络变更完成，才能安全回收。",
                  "Remove the NAT binding and confirm the network change before reclaiming.",
                )
              }}
            </p>
            <footer class="ip-record-actions">
              <code class="ip-id">{{ lease.id }}</code>
              <div class="ip-actions">
                <RouterLink
                  :to="`/networks/overlays?cluster_id=${lease.cluster_id}`"
                  >{{ tr("配置 VPC 出口", "Configure VPC egress") }}</RouterLink
                ><UiButton
                  v-if="canManage && lease.state !== 'released'"
                  :disabled="
                    !lease.releasable ||
                    !!mutation.pending.value ||
                    mutation.busy.value
                  "
                  @click="edit('lease.release', undefined, lease)"
                  >{{ tr("回收地址", "Reclaim address") }}</UiButton
                >
              </div>
            </footer>
          </article>
        </div>
        <footer class="ip-pagination">
          <UiButton v-if="cursor" @click="navigate(view, cluster)">{{
            tr("返回第一页", "First page")
          }}</UiButton
          ><UiButton
            v-if="list.data.value?.next_cursor"
            @click="navigate(view, cluster, list.data.value!.next_cursor!)"
            >{{ tr("下一页", "Next page") }}</UiButton
          >
        </footer>
      </StateBlock>
    </template>
    <PublicIPDialog
      v-if="editing && options.data.value"
      :key="`${editing.action}:${editing.pool?.id || editing.lease?.id || cluster}`"
      :action="editing.action"
      :cluster="cluster"
      :options="options.data.value"
      :pool="editing.pool"
      :lease="editing.lease"
      :busy="mutation.busy.value"
      :pending="!!mutation.pending.value"
      :error="mutation.error.value"
      @close="editing = null"
      @submit="submit"
      @reconcile="reconcile"
    />
  </section>
</template>
<style scoped>
.ip-actions {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}
.ip-toolbar {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 20px;
}
.ip-cluster {
  width: min(100%, 320px);
}
.ip-views {
  display: flex;
  gap: 4px;
  padding: 0;
  background: transparent;
  border: 0;
  border-radius: 0;
  border-bottom: 1px solid var(--border);
}
.ip-views button {
  min-height: 44px;
  border: 0;
  border-radius: 4px;
  background: transparent;
  padding: 8px 14px;
  color: var(--secondary);
  font: inherit;
  font-size: 14px;
  cursor: pointer;
}
.ip-views button[aria-current="page"] {
  background: var(--surface);
  color: var(--text);
  font-weight: 600;
}
.ip-records {
  display: block;
  border-top: 1px solid var(--border);
}
.ip-record {
  padding: 18px 0;
  border: 0;
  border-radius: 0;
  background: var(--surface);
  min-width: 0;
  border-bottom: 1px solid var(--border);
}
.ip-record-heading,
.ip-record-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding-top: 12px;
  margin-top: 12px;
}
.ip-record-heading > div {
  min-width: 0;
}
.ip-record h2 {
  font-size: 17px;
  line-height: 1.4;
  margin: 0 0 6px;
  overflow-wrap: anywhere;
}
.ip-record code {
  font-size: 12px;
  overflow-wrap: anywhere;
  color: var(--secondary);
}
.ip-status {
  font-size: 12px;
  background: var(--subtle);
  padding: 5px 8px;
  border-radius: 4px;
  white-space: nowrap;
}
.ip-meta {
  font-size: 13px;
  line-height: 1.75;
  color: var(--secondary);
}
.ip-addresses {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin: 12px 0;
}
.ip-addresses code {
  padding: 5px 8px;
  background: var(--subtle);
  border-radius: 4px;
  font-size: 13px;
}
.ip-record-actions {
  border-top: 1px solid var(--border);
  padding-top: 16px;
  margin-top: 20px;
}
.ip-id {
  min-width: 0;
}
.ip-details {
  display: grid;
  gap: 12px 24px;
  margin: 16px 0;
  grid-template-columns: repeat(2, minmax(0, 1fr));
}
.ip-details > div {
  display: grid;
  grid-template-columns: 96px minmax(0, 1fr);
  gap: 10px;
  font-size: 14px;
  line-height: 1.6;
}
.ip-details dt {
  color: var(--secondary);
}
.ip-details dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.ip-pagination {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 20px;
}
.ip-pending {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 20px;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--subtle);
}
.ip-pending p,
.ip-pending code {
  font-size: 13px;
  line-height: 1.7;
  overflow-wrap: anywhere;
}
.ip-pending p {
  color: var(--secondary);
}
@media (max-width: 600px) {
  .ip-toolbar,
  .ip-record-heading,
  .ip-record-actions,
  .ip-pending {
    align-items: stretch;
    flex-direction: column;
  }
  .ip-status {
    align-self: flex-start;
  }
  .ip-views {
    align-self: flex-start;
  }
  .ip-actions > .ui-button {
    flex: 1;
  }
  .page-heading > .ip-actions,
  .ip-record-actions .ip-actions {
    width: 100%;
  }
  .ip-cluster {
    width: 100%;
  }
}
@media (max-width: 760px) {
  .ip-details {
    grid-template-columns: minmax(0, 1fr);
  }
}
@media (max-width: 600px) {
  .ip-record {
    padding: 18px 0;
  }
  .ip-views {
    width: 100%;
  }
  .ip-views button {
    flex: 1;
    padding-inline: 10px;
  }
  .ip-details > div {
    grid-template-columns: 86px minmax(0, 1fr);
  }
}
</style>
