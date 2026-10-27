<script setup lang="ts">
import { useConsole } from "../context";
import { failureNames } from "../format";
defineProps<{ error: string; pendingKey?: string }>();
const {
  prefs: { tr },
} = useConsole();
</script>
<template>
  <div v-if="error" class="inline-error" role="alert">
    <p>{{ tr(...(failureNames[error] || failureNames.unavailable)!) }}</p>
    <p v-if="pendingKey" class="pending-reference">
      {{ tr("请求编号", "Request reference") }}<code>{{ pendingKey }}</code>
    </p>
  </div>
</template>
<style scoped>
.inline-error {
  padding: 14px 16px;
  background: var(--danger-bg);
  color: var(--danger);
  border: 1px solid var(--danger-border);
  border-radius: 6px;
  margin: 16px 0;
}
.inline-error p {
  margin: 0;
  line-height: 1.6;
  font-size: 14px;
}
.pending-reference {
  margin-top: 8px !important;
}
.pending-reference code {
  display: block;
  overflow-wrap: anywhere;
  color: inherit;
  font-size: 12px;
}
</style>
