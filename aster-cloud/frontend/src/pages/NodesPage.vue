<script setup lang="ts">
import { computed, shallowRef } from "vue";
import { RefreshCw, Server, Wrench } from "@lucide/vue";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { useMutation } from "../composables/mutation";
import { record, validNode, validPage } from "../api/client";
import type { Node, Page } from "../api/types";
import { dateText, sizeMiB } from "../format";
import UiButton from "../components/UiButton.vue";
import UiOverlay from "../components/UiOverlay.vue";
import StateBlock from "../components/StateBlock.vue";
import StatusBadge from "../components/StatusBadge.vue";
import InlineError from "../components/InlineError.vue";
const {
  prefs: { tr, locale },
  session,
  notify,
} = useConsole();
const list = useQuery(
  () => "/nodes",
  (v): v is Page<Node> => validPage(v, validNode),
);
const selected = shallowRef<Node | null>(null),
  confirmation = shallowRef("");
const mutation = useMutation();
const target = computed(() => !selected.value?.maintenance);
function open(node: Node) {
  selected.value = node;
  confirmation.value = "";
  mutation.clearMessage();
}
async function save() {
  if (
    !selected.value ||
    confirmation.value !== selected.value.id ||
    mutation.pendingKey.value
  )
    return;
  const expected = target.value;
  const result = await mutation.execute(
    "POST",
    `/nodes/${encodeURIComponent(selected.value.id)}/maintenance`,
    { enabled: expected },
    (x): x is { maintenance: boolean } =>
      record(x) && x.maintenance === expected,
  );
  if (result && result.maintenance === expected) {
    notify(
      expected
        ? tr("节点已进入维护模式。", "Maintenance mode enabled.")
        : tr("节点已退出维护模式。", "Maintenance mode disabled."),
    );
    selected.value = null;
    await list.reload();
  }
}
</script>
<template>
  <section class="page">
    <header class="page-heading">
      <div>
        <h1>{{ tr("节点", "Nodes") }}</h1>
        <p>
          {{
            tr(
              "查看节点心跳、资源余量与维护状态。",
              "Review node heartbeats, available resources and maintenance state.",
            )
          }}
        </p>
      </div>
      <UiButton :busy="list.loading.value" @click="list.reload"
        ><RefreshCw :size="16" aria-hidden="true" />{{
          tr("刷新", "Refresh")
        }}</UiButton
      >
    </header>
    <StateBlock
      :loading="list.loading.value"
      :error="list.error.value"
      :empty="!list.data.value?.items.length"
      :title="tr('暂无节点', 'No nodes yet')"
      :description="
        tr(
          '节点完成配置并上报心跳后，将在这里显示。',
          'Nodes appear here after configuration and their first heartbeat.',
        )
      "
      @reload="list.reload"
      ><div class="node-ledger-desktop">
        <table class="node-table">
          <caption class="sr-only">
            {{
              tr("节点资源与维护状态", "Node resources and maintenance state")
            }}
          </caption>
          <thead>
            <tr>
              <th scope="col">{{ tr("节点 / 机房", "Node / datacenter") }}</th>
              <th scope="col">{{ tr("状态", "State") }}</th>
              <th scope="col" class="number-column">
                {{ tr("可用 / 已预留 CPU", "Available / reserved CPU")
                }}<span>vCPU</span>
              </th>
              <th scope="col" class="number-column">
                {{ tr("可用 / 已预留内存", "Available / reserved memory") }}
              </th>
              <th scope="col" class="number-column">
                {{ tr("可用 / 已预留磁盘", "Available / reserved disk")
                }}<span>GiB</span>
              </th>
              <th scope="col">{{ tr("最近心跳", "Last heartbeat") }}</th>
              <th scope="col" class="action-column">
                {{ tr("操作", "Actions") }}
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="node in list.data.value?.items" :key="node.id">
              <th scope="row" class="node-identity">
                <strong>{{ node.id }}</strong>
                <span>{{ node.datacenter_id }}</span>
              </th>
              <td>
                <StatusBadge
                  :state="
                    node.maintenance
                      ? 'maintenance'
                      : node.online
                        ? 'online'
                        : 'offline'
                  "
                />
              </td>
              <td class="number-column">
                <strong class="available-value">{{ node.free_cpu }}</strong
                ><span class="capacity-divider"> / </span
                ><span class="reserved-value">{{ node.reserved_cpu }}</span>
              </td>
              <td class="number-column">
                <strong class="available-value">{{
                  sizeMiB(node.free_memory_mib)
                }}</strong
                ><span class="capacity-divider"> / </span
                ><span class="reserved-value">{{
                  sizeMiB(node.reserved_memory_mib)
                }}</span>
              </td>
              <td class="number-column">
                <strong class="available-value">{{ node.free_disk_gib }}</strong
                ><span class="capacity-divider"> / </span
                ><span class="reserved-value">{{
                  node.reserved_disk_gib
                }}</span>
              </td>
              <td class="heartbeat-value">
                {{ dateText(node.heartbeat_at, locale) }}
              </td>
              <td class="action-column">
                <UiButton
                  variant="quiet"
                  :disabled="!session.can('nodes.manage')"
                  @click="open(node)"
                >
                  <Wrench :size="16" aria-hidden="true" />{{
                    tr("维护", "Maintenance")
                  }}
                </UiButton>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="node-ledger-mobile">
        <article
          v-for="node in list.data.value?.items"
          :key="node.id"
          class="node-entry"
        >
          <header class="node-entry-heading">
            <div class="node-entry-identity">
              <Server :size="18" aria-hidden="true" />
              <div>
                <h2>{{ node.id }}</h2>
                <p>{{ node.datacenter_id }}</p>
              </div>
            </div>
            <StatusBadge
              :state="
                node.maintenance
                  ? 'maintenance'
                  : node.online
                    ? 'online'
                    : 'offline'
              "
            />
          </header>
          <div class="capacity-column-labels" aria-hidden="true">
            <span>{{ tr("资源", "Resource") }}</span
            ><span>{{ tr("可用", "Available") }}</span
            ><span>{{ tr("已预留", "Reserved") }}</span>
          </div>
          <dl class="node-budget">
            <div>
              <dt>CPU <span>vCPU</span></dt>
              <dd class="available-value">
                <span class="sr-only">{{ tr("可用", "Available") }}</span
                >{{ node.free_cpu }}
              </dd>
              <dd class="reserved-value">
                <span class="sr-only">{{ tr("已预留", "Reserved") }}</span
                >{{ node.reserved_cpu }}
              </dd>
            </div>
            <div>
              <dt>{{ tr("内存", "Memory") }}</dt>
              <dd class="available-value">
                <span class="sr-only">{{ tr("可用", "Available") }}</span
                >{{ sizeMiB(node.free_memory_mib) }}
              </dd>
              <dd class="reserved-value">
                <span class="sr-only">{{ tr("已预留", "Reserved") }}</span
                >{{ sizeMiB(node.reserved_memory_mib) }}
              </dd>
            </div>
            <div>
              <dt>{{ tr("磁盘", "Disk") }} <span>GiB</span></dt>
              <dd class="available-value">
                <span class="sr-only">{{ tr("可用", "Available") }}</span
                >{{ node.free_disk_gib }}
              </dd>
              <dd class="reserved-value">
                <span class="sr-only">{{ tr("已预留", "Reserved") }}</span
                >{{ node.reserved_disk_gib }}
              </dd>
            </div>
          </dl>
          <footer class="node-entry-footer">
            <div>
              <span>{{ tr("最近心跳", "Last heartbeat") }}</span>
              <p>{{ dateText(node.heartbeat_at, locale) }}</p>
            </div>
            <UiButton
              variant="quiet"
              :disabled="!session.can('nodes.manage')"
              @click="open(node)"
            >
              <Wrench :size="16" aria-hidden="true" />{{
                tr("维护", "Maintenance")
              }}
            </UiButton>
          </footer>
        </article>
      </div></StateBlock
    ><UiOverlay
      :open="!!selected"
      :title="
        target
          ? tr('进入维护模式', 'Enable maintenance')
          : tr('退出维护模式', 'Disable maintenance')
      "
      :description="selected?.id"
      :busy="mutation.busy.value"
      :close-label="tr('关闭', 'Close')"
      @close="selected = null"
      ><p class="secondary">
        {{
          tr(
            "维护模式下，不再向节点分配新的实例。现有实例不会因此自动关机。",
            "Maintenance mode stops new assignments. Existing instances are not automatically shut down.",
          )
        }}
      </p>
      <label class="field"
        >{{ tr("输入节点 ID 以确认", "Type the node ID to confirm")
        }}<input
          v-model="confirmation"
          autocomplete="off"
          :disabled="
            mutation.busy.value || !!mutation.pendingKey.value
          " /></label
      ><InlineError
        :error="mutation.error.value"
        :pending-key="mutation.pendingKey.value"
      /><template #footer
        ><UiButton :disabled="mutation.busy.value" @click="selected = null">{{
          tr("取消", "Cancel")
        }}</UiButton
        ><UiButton
          variant="primary"
          :busy="mutation.busy.value"
          :disabled="
            confirmation !== selected?.id || !!mutation.pendingKey.value
          "
          @click="save"
          >{{ tr("确认更改", "Confirm change") }}</UiButton
        ></template
      ></UiOverlay
    >
  </section>
</template>
<style scoped>
.page-heading {
  align-items: flex-start;
  flex-wrap: nowrap;
}
.page-heading > div {
  flex: 1;
}
.page-heading > .ui-button {
  flex-shrink: 0;
}
.node-ledger-desktop {
  border-top: 1px solid var(--border);
}
.node-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 14px;
  line-height: 1.55;
}
.node-table thead th {
  padding: 12px 14px;
  background: var(--subtle);
  border-bottom: 1px solid var(--border);
  color: var(--secondary);
  text-align: left;
  font-size: 12px;
  font-weight: 500;
}
.node-table thead th > span {
  display: block;
  font-size: 11px;
  margin-top: 2px;
}
.node-table tbody th,
.node-table tbody td {
  padding: 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
}
.node-table tbody tr:hover {
  background: var(--subtle);
}
.node-table .number-column,
.node-table .action-column {
  text-align: right;
}
.node-identity {
  max-width: 200px;
  text-align: left;
  font-weight: 400;
  overflow-wrap: anywhere;
}
.node-identity strong {
  display: block;
  font-size: 15px;
  font-weight: 600;
}
.node-identity > span {
  display: block;
  color: var(--secondary);
  font-size: 12px;
  margin-top: 4px;
}
.number-column {
  font-variant-numeric: tabular-nums;
}
.available-value {
  font-weight: 600;
  color: var(--text);
  font-variant-numeric: tabular-nums;
}
.capacity-divider,
.reserved-value {
  color: var(--secondary);
  font-variant-numeric: tabular-nums;
}
.heartbeat-value {
  max-width: 168px;
  color: var(--secondary);
  overflow-wrap: anywhere;
  font-size: 13px;
  font-variant-numeric: tabular-nums;
}
.node-ledger-mobile {
  display: none;
}
.node-entry {
  padding: 20px 0;
  border-bottom: 1px solid var(--border);
}
.node-entry-heading {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
}
.node-entry-identity {
  display: flex;
  align-items: flex-start;
  gap: 9px;
  min-width: 0;
}
.node-entry-identity > svg {
  flex-shrink: 0;
  margin-top: 2px;
  color: var(--secondary);
}
.node-entry-identity > div {
  min-width: 0;
}
.node-entry-identity h2 {
  font-size: 15px;
  line-height: 1.5;
  margin: 0;
  overflow-wrap: anywhere;
}
.node-entry-identity p {
  color: var(--secondary);
  font-size: 12px;
  margin: 3px 0 0;
  overflow-wrap: anywhere;
}
.node-entry-heading > .status-badge {
  flex-shrink: 0;
}
.capacity-column-labels,
.node-budget > div {
  display: grid;
  grid-template-columns: minmax(74px, 1fr) minmax(0, 1.1fr) minmax(0, 1.1fr);
  gap: 10px;
  align-items: baseline;
}
.capacity-column-labels {
  color: var(--secondary);
  font-size: 12px;
  padding: 20px 0 8px;
  border-bottom: 1px solid var(--border);
}
.capacity-column-labels > span:not(:first-child),
.node-budget dd {
  text-align: right;
}
.node-budget {
  margin: 0;
}
.node-budget > div {
  padding: 11px 0;
  border-bottom: 1px solid var(--border);
  font-size: 14px;
}
.node-budget > div:last-child {
  border-bottom: 0;
}
.node-budget dt {
  color: var(--secondary);
}
.node-budget dt span {
  font-size: 11px;
}
.node-budget dd {
  margin: 0;
  overflow-wrap: anywhere;
  font-size: 15px;
}
.node-entry-footer {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding-top: 8px;
}
.node-entry-footer > div {
  min-width: 0;
}
.node-entry-footer span {
  font-size: 11px;
  color: var(--secondary);
}
.node-entry-footer p {
  font-size: 12px;
  line-height: 1.55;
  color: var(--secondary);
  margin: 4px 0 0;
  overflow-wrap: anywhere;
}
.field {
  margin-top: 24px;
}
@media (max-width: 1100px) {
  .node-ledger-desktop {
    display: none;
  }
  .node-ledger-mobile {
    display: block;
    border-top: 1px solid var(--border);
  }
}
</style>
