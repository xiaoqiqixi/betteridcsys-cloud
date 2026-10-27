<script setup lang="ts">
import { computed, shallowRef } from "vue";
import { Search, RefreshCw, Plus } from "@lucide/vue";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { validInstance, validPage } from "../api/client";
import type { Instance, Page } from "../api/types";
import { sizeMiB } from "../format";
import CreateInstanceDialog from "../components/CreateInstanceDialog.vue";
import StateBlock from "../components/StateBlock.vue";
import InstanceLedger, {
  type InstanceLedgerItem,
} from "../components/InstanceLedger.vue";
import { statusPresentation } from "../presentation";
import UiButton from "../components/UiButton.vue";
const {
  prefs: { tr },
  session,
  notify,
} = useConsole();
const createOpen = shallowRef(false);
const cursor = shallowRef(""),
  search = shallowRef("");
const list = useQuery(
  () =>
    `/instances${cursor.value ? `?cursor=${encodeURIComponent(cursor.value)}` : ""}`,
  (v): v is Page<Instance> => validPage(v, validInstance),
);
const visible = computed(
  () =>
    list.data.value?.items.filter((i) =>
      [i.hostname, i.id, i.node_id].some((v) =>
        v.toLocaleLowerCase().includes(search.value.toLocaleLowerCase()),
      ),
    ) || [],
);
const ledgerItems = computed<InstanceLedgerItem[]>(() =>
  visible.value.map((instance) => {
    const status = statusPresentation(instance.state, tr);
    return {
      id: instance.id,
      href: `#/instances/${encodeURIComponent(instance.id)}`,
      hostname: instance.hostname || instance.id,
      stateLabel: status.label,
      stateTone: status.tone === "good" ? "success" : status.tone,
      cpuLabel: `${instance.resources.cpu_cores} vCPU`,
      memoryLabel: sizeMiB(instance.resources.memory_mib),
      diskLabel: `${instance.resources.system_disk_gib} GiB`,
      nodeLabel: instance.node_id,
    };
  }),
);
const ledgerLabels = computed(() => ({
  colInstance: tr("实例", "Instance"),
  colState: tr("状态", "State"),
  colSpec: tr("CPU / 内存 / 系统盘", "CPU / memory / system disk"),
  colNode: tr("节点", "Node"),
  viewDetails: tr("查看详情", "View details"),
  fullId: tr("实例 ID", "Instance ID"),
  copyId: tr("复制实例 ID", "Copy instance ID"),
  expandId: tr("展开完整 ID", "Show full ID"),
  collapseId: tr("收起完整 ID", "Collapse full ID"),
  emptyText: tr("暂无实例", "No instances yet"),
}));
async function copyInstanceID(id: string) {
  const epoch = session.epoch.value;
  try {
    await navigator.clipboard.writeText(id);
    if (session.epoch.value === epoch)
      notify(tr("实例 ID 已复制。", "Instance ID copied."));
  } catch {
    if (session.epoch.value === epoch)
      notify(
        tr(
          "未能复制，请展开完整 ID 后手动复制。",
          "Could not copy. Expand the full ID and copy it manually.",
        ),
        "error",
      );
  }
}
</script>
<template>
  <section class="page">
    <header class="page-heading">
      <div>
        <h1>{{ tr("实例", "Instances") }}</h1>
        <p>
          {{
            tr(
              "查看服务器状态，管理电源、数据与迁移。",
              "Manage server state, power, data and migrations.",
            )
          }}
        </p>
      </div>
      <div class="heading-actions">
        <UiButton :busy="list.loading.value" @click="list.reload"
          ><RefreshCw :size="16" aria-hidden="true" />{{
            tr("刷新", "Refresh")
          }}</UiButton
        ><UiButton
          v-if="session.can('instances.manage')"
          variant="primary"
          @click="createOpen = true"
          ><Plus :size="16" aria-hidden="true" />{{
            tr("创建实例", "Create instance")
          }}</UiButton
        >
      </div>
    </header>
    <div class="list-toolbar">
      <label class="search-field"
        ><Search :size="18" aria-hidden="true" /><input
          v-model="search"
          :aria-label="tr('搜索当前页实例', 'Search instances on this page')"
          :placeholder="
            tr('搜索名称、实例 ID 或节点', 'Search name, instance ID or node')
          "
          type="search" /></label
      ><span v-if="list.data.value" class="result-count"
        >{{ tr("本页", "This page") }} {{ list.data.value.items.length }}</span
      >
    </div>
    <StateBlock
      :loading="list.loading.value"
      :error="list.error.value"
      :empty="!visible.length"
      :title="
        search
          ? tr('没有匹配的实例', 'No matching instances')
          : tr('暂无实例', 'No instances yet')
      "
      :description="
        search
          ? tr('尝试其他名称或 ID。', 'Try another name or ID.')
          : tr(
              '新开通的服务器将在这里显示。',
              'Newly provisioned servers will appear here.',
            )
      "
      @reload="list.reload"
    >
      <InstanceLedger
        :items="ledgerItems"
        :labels="ledgerLabels"
        @copy-id="copyInstanceID"
      />
    </StateBlock>
    <div v-if="list.data.value" class="pagination">
      <UiButton
        v-if="cursor"
        :disabled="list.loading.value"
        @click="cursor = ''"
        >{{ tr("回到首页", "First page") }}</UiButton
      ><UiButton
        v-if="list.data.value.next_cursor"
        :disabled="list.loading.value"
        @click="cursor = list.data.value!.next_cursor!"
        >{{ tr("下一页", "Next page") }}</UiButton
      >
    </div>
    <CreateInstanceDialog
      v-if="session.can('instances.manage')"
      :open="createOpen"
      @close="createOpen = false"
    />
  </section>
</template>
