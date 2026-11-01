<script setup lang="ts">
import { useConsole } from "../context";
import { useMutation } from "../composables/mutation";
import { record } from "../api/client";
import type { Node } from "../api/types";
import UiButton from "./UiButton.vue";
import InlineError from "./InlineError.vue";
const props = defineProps<{ node: Node }>();
const emit = defineEmits<{ saved: [] }>();
const {
  prefs: { tr },
  session,
} = useConsole();
const mutation = useMutation();
async function toggle() {
  const expected = !props.node.allocation_disabled;
  const result = await mutation.execute(
    "POST",
    `/nodes/${encodeURIComponent(props.node.id)}/allocation`,
    { allocation_disabled: expected },
    (x): x is { allocation_disabled: boolean } =>
      record(x) && x.allocation_disabled === expected,
  );
  if (result) emit("saved");
}
</script>
<template>
  <div>
    <UiButton
      variant="quiet"
      :aria-pressed="!node.allocation_disabled"
      :aria-label="tr('允许新分配', 'Allow new allocations') + ' · ' + node.id"
      :disabled="!session.can('nodes.manage') || !!mutation.pendingKey.value"
      :busy="mutation.busy.value"
      @click="toggle"
      >{{
        node.allocation_disabled
          ? tr("新分配已禁用", "Allocations disabled")
          : tr("允许新分配", "Allocations enabled")
      }}</UiButton
    >
    <InlineError
      v-if="mutation.error.value || mutation.pendingKey.value"
      :error="mutation.error.value"
      :pending-key="mutation.pendingKey.value"
    />
  </div>
</template>
