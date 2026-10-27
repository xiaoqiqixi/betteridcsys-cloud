<script setup lang="ts">
withDefaults(
  defineProps<{
    busy?: boolean;
    disabled?: boolean;
    variant?: "primary" | "secondary" | "danger" | "quiet";
    type?: "button" | "submit";
  }>(),
  { variant: "secondary", type: "button" },
);
</script>
<template>
  <button
    :type="type"
    class="ui-button"
    :class="`is-${variant}`"
    :disabled="disabled || busy"
    :aria-busy="busy || undefined"
  >
    <span v-if="busy" class="spinner" aria-hidden="true" /><slot />
  </button>
</template>
<style scoped>
.ui-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  min-height: 44px;
  padding: 0 16px;
  border: 1px solid var(--control-border);
  border-radius: 6px;
  background: var(--surface);
  color: var(--text);
  font-weight: 600;
  line-height: 1.3;
  transition: background 0.14s;
}
.ui-button:not(:disabled):hover {
  background: var(--hover);
}
.is-primary {
  background: var(--accent);
  color: var(--on-accent);
  border-color: var(--accent);
}
.is-primary:not(:disabled):hover {
  background: var(--accent-hover);
}
.is-danger {
  background: var(--danger-bg);
  color: var(--danger);
  border-color: var(--danger-border);
}
.is-danger:not(:disabled):hover {
  background: var(--danger-hover);
}
.is-quiet {
  background: transparent;
  border-color: transparent;
  color: var(--secondary);
}
.ui-button:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.spinner {
  width: 15px;
  height: 15px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
@media (prefers-reduced-motion: reduce) {
  .spinner {
    animation: none;
    border-style: dotted;
  }
}
</style>
