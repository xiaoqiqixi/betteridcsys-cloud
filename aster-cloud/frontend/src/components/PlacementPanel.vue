<script setup lang="ts">
import { computed, shallowRef } from "vue";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { useMutation } from "../composables/mutation";
import { record } from "../api/client";
import UiSelect from "./UiSelect.vue";
import UiButton from "./UiButton.vue";
import InlineError from "./InlineError.vue";
import StateBlock from "./StateBlock.vue";
interface Region {
  region_id: string;
  policy: string;
}
const {
  prefs: { tr },
  session,
  notify,
} = useConsole();
const policies = ["least_instances", "most_free_memory", "fill_first"];
const validRegion = (x: unknown): x is Region =>
  record(x) &&
  typeof x.region_id === "string" &&
  typeof x.policy === "string" &&
  policies.includes(x.policy);
const query = useQuery(
  () => "/placement",
  (x): x is { items: Region[] } =>
    record(x) && Array.isArray(x.items) && x.items.every(validRegion),
);
const drafts = shallowRef<Record<string, string>>({});
const mutation = useMutation();
const options = computed(() => [
  { value: "least_instances", label: tr("最少实例", "Fewest instances") },
  { value: "most_free_memory", label: tr("最多空闲内存", "Most free memory") },
  { value: "fill_first", label: tr("按节点顺序填满", "Fill nodes in order") },
]);
function edit(id: string, value: string) {
  drafts.value = { ...drafts.value, [id]: value };
}
async function save(region: Region) {
  const policy = drafts.value[region.region_id];
  if (!policy || policy === region.policy || mutation.pendingKey.value) return;
  const result = await mutation.execute(
    "POST",
    `/placement/${encodeURIComponent(region.region_id)}`,
    { policy },
    (x): x is Region =>
      validRegion(x) && x.region_id === region.region_id && x.policy === policy,
  );
  if (result) {
    notify(tr("放置策略已更新。", "Placement policy updated."));
    drafts.value = {};
    await query.reload();
  }
}
</script>
<template>
  <section class="placement-panel" aria-labelledby="placement-title">
    <h2 id="placement-title">{{ tr("区域放置策略", "Regional placement") }}</h2>
    <p class="secondary">
      {{
        tr(
          "用于已启用区域调度的套餐与产品。指定节点的套餐保持原有位置。",
          "Applies to products approved for regional placement. Presets with a selected node keep that placement.",
        )
      }}
    </p>
    <StateBlock
      :loading="query.loading.value"
      :error="query.error.value"
      :empty="!query.data.value?.items.length"
      :title="tr('暂无区域', 'No regions')"
      @reload="query.reload"
    >
      <div
        v-for="region in query.data.value?.items"
        :key="region.region_id"
        class="placement-row"
      >
        <strong>{{ region.region_id }}</strong>
        <UiSelect
          :label="tr('放置策略', 'Placement policy') + ' · ' + region.region_id"
          :model-value="drafts[region.region_id] ?? region.policy"
          :options="options"
          :disabled="
            !session.can('nodes.manage') ||
            mutation.busy.value ||
            !!mutation.pendingKey.value
          "
          @update:model-value="edit(region.region_id, $event)"
        />
        <UiButton
          :disabled="
            !session.can('nodes.manage') ||
            !drafts[region.region_id] ||
            drafts[region.region_id] === region.policy ||
            !!mutation.pendingKey.value
          "
          :busy="mutation.busy.value"
          @click="save(region)"
          >{{ tr("保存", "Save") }}</UiButton
        >
      </div>
    </StateBlock>
    <InlineError
      :error="mutation.error.value"
      :pending-key="mutation.pendingKey.value"
    />
  </section>
</template>
<style scoped>
.placement-panel {
  border-top: 1px solid var(--border);
  padding-top: 24px;
  margin-top: 24px;
}
.placement-panel h2 {
  font-size: 16px;
}
.placement-row {
  display: grid;
  grid-template-columns: minmax(100px, 1fr) minmax(160px, 2fr) auto;
  align-items: center;
  gap: 12px;
  padding: 12px 0;
}
@media (max-width: 600px) {
  .placement-row {
    grid-template-columns: 1fr auto;
  }
  .placement-row > strong {
    grid-column: 1 / -1;
  }
}
</style>
