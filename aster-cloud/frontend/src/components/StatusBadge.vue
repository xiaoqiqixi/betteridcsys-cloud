<script setup lang="ts">
import { computed } from "vue";
import { useConsole } from "../context";
import { statusPresentation } from "../presentation";
const props = defineProps<{ state: string }>();
const {
  prefs: { tr },
} = useConsole();
const presentation = computed(() => statusPresentation(props.state, tr));
</script>
<template>
  <span class="status-badge" :class="`tone-${presentation.tone}`"
    ><span class="status-dot" aria-hidden="true" />{{
      presentation.label
    }}</span
  >
</template>
<style scoped>
.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 9px;
  min-height: 28px;
  border-radius: 7px;
  background: var(--hover);
  color: var(--secondary);
  font-size: 12px;
  font-weight: 600;
  line-height: 1.3;
  overflow-wrap: anywhere;
  max-width: 100%;
}
.status-dot {
  width: 5px;
  height: 5px;
  background: currentColor;
  border-radius: 50%;
  flex-shrink: 0;
}
.tone-good {
  color: var(--success);
  background: var(--success-bg);
}
.tone-info {
  color: var(--accent-text);
  background: var(--accent-bg);
}
.tone-warning {
  color: var(--warning);
  background: var(--warning-bg);
}
.tone-danger {
  color: var(--danger);
  background: var(--danger-bg);
}
</style>
