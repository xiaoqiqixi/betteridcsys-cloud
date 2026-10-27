<script setup lang="ts">
import { computed, shallowRef, watch } from "vue";
import { RouterLink } from "vue-router";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import {
  publicIPResourcePage,
  type PublicIPResource,
} from "../api/public-ip-resource";
import UiSelect from "./UiSelect.vue";
import UiButton from "./UiButton.vue";
import InlineError from "./InlineError.vue";
const props = defineProps<{
  owner: string;
  node: string;
  modelValue: string;
  disabled: boolean;
}>();
const emit = defineEmits<{
  "update:modelValue": [value: string];
  select: [resource: PublicIPResource | null];
}>();
const {
  prefs: { tr },
} = useConsole();
const cursor = shallowRef("");
const query = useQuery(
  () =>
    `/public-ips/resources?${new URLSearchParams({ owner_ref: props.owner, ...(cursor.value ? { cursor: cursor.value } : {}) })}`,
  (v): v is { items: PublicIPResource[]; next_cursor: string | null } =>
    publicIPResourcePage(v) &&
    v.items.every((r) => r.owner_ref === props.owner),
);
function choose(value: string) {
  emit("update:modelValue", value);
  emit("select", choices.value.find((r) => r.id === value) || null);
}
const choices = computed(() =>
  (query.data.value?.items || []).filter(
    (r) =>
      r.mode === "direct" &&
      r.node_id === props.node &&
      r.state === "reserved" &&
      r.binding_state === "unbound",
  ),
);
watch([() => props.owner, () => props.node], () => {
  cursor.value = "";
  emit("update:modelValue", "");
});
watch(query.data, () => {
  if (!choices.value.some((r) => r.id === props.modelValue))
    emit("update:modelValue", "");
});
</script>
<template>
  <div class="direct-public-choice">
    <label class="field"
      >{{ tr("实例公网地址", "VM public address")
      }}<UiSelect
        :model-value="modelValue"
        :label="tr('选择直绑公网地址', 'Choose direct public address')"
        :options="choices.map((r) => ({ value: r.id, label: r.address }))"
        :placeholder="
          query.loading.value
            ? tr('正在加载地址…', 'Loading addresses…')
            : tr('选择已分配地址', 'Choose an allocated address')
        "
        :disabled="disabled || query.loading.value || !!query.error.value"
        @update:model-value="choose"
      /><span class="field-note">{{
        tr(
          "地址必须属于此客户及节点。创建任务会将该地址真实配置到实例网卡。",
          "The address must belong to this owner and node. The creation task configures it on the VM interface.",
        )
      }}</span></label
    ><InlineError :error="query.error.value" />
    <p v-if="!query.loading.value && !query.error.value && !choices.length">
      {{
        tr(
          "本页没有匹配的未绑定地址。请先分配地址，或查看下一页。",
          "No matching unbound address on this page. Allocate one first, or check the next page.",
        )
      }}
    </p>
    <div class="choice-actions">
      <UiButton
        v-if="query.error.value"
        :busy="query.loading.value"
        @click="query.reload"
        >{{ tr("重新加载地址", "Reload addresses") }}</UiButton
      ><UiButton v-if="cursor" :disabled="disabled" @click="cursor = ''">{{
        tr("地址第一页", "First address page")
      }}</UiButton
      ><UiButton
        v-if="query.data.value?.next_cursor"
        :disabled="disabled"
        @click="cursor = query.data.value.next_cursor"
        >{{ tr("下一页地址", "Next address page") }}</UiButton
      ><RouterLink to="/networks/public-ips?view=resources">{{
        tr("分配公网地址", "Allocate public address")
      }}</RouterLink>
    </div>
  </div>
</template>
<style scoped>
.direct-public-choice {
  display: grid;
  gap: 12px;
  border-top: 1px solid var(--border);
  padding-top: 24px;
}
.direct-public-choice p {
  margin: 0;
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
}
.choice-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  align-items: center;
}
.choice-actions a {
  display: inline-flex;
  align-items: center;
  min-height: 44px;
  font-size: 13px;
}
</style>
