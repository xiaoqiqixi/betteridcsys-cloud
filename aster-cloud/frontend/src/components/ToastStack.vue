<script setup lang="ts">
import { CheckCircle2, X, AlertCircle } from "@lucide/vue";
import type { Notice } from "../context";
defineProps<{ notices: readonly Notice[]; closeLabel: string }>();
const emit = defineEmits<{
  dismiss: [id: number];
  pause: [id: number];
  resume: [id: number];
}>();
function leave(id: number, event: PointerEvent) {
  if (!(event.currentTarget as HTMLElement).contains(document.activeElement))
    emit("resume", id);
}
function blur(id: number, event: FocusEvent) {
  const item = event.currentTarget as HTMLElement;
  const next = event.relatedTarget instanceof Node ? event.relatedTarget : null;
  if (!item.contains(next) && !item.matches(":hover")) emit("resume", id);
}
</script>
<template>
  <div class="toast-stack" aria-live="polite" aria-relevant="additions">
    <TransitionGroup name="toast"
      ><div
        v-for="notice in notices"
        :key="notice.id"
        class="toast-item"
        :class="notice.kind"
        @pointerenter="$emit('pause', notice.id)"
        @pointerleave="leave(notice.id, $event)"
        @focusin="$emit('pause', notice.id)"
        @focusout="blur(notice.id, $event)"
      >
        <AlertCircle
          v-if="notice.kind === 'error'"
          :size="19"
          aria-hidden="true"
        /><CheckCircle2 v-else :size="19" aria-hidden="true" />
        <p>{{ notice.title }}</p>
        <button
          type="button"
          class="icon-button"
          :aria-label="closeLabel"
          @click="$emit('dismiss', notice.id)"
        >
          <X :size="17" aria-hidden="true" />
        </button></div
    ></TransitionGroup>
  </div>
</template>
<style scoped>
.toast-stack {
  position: fixed;
  right: 24px;
  bottom: 24px;
  z-index: 90;
  display: flex;
  flex-direction: column;
  gap: 10px;
  width: min(420px, calc(100vw - 32px));
  pointer-events: none;
}
/* The real overlay makes #app inert. Hide its background notices too: neither
   an old success nor its dismiss button may cover a modal's content or footer. */
:global(#app[inert] .toast-stack),
:global(#app[inert] .toast-item) {
  visibility: hidden;
  pointer-events: none;
}
.toast-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 12px 12px 16px;
  background: var(--surface-raised);
  border: 1px solid var(--control-border);
  border-radius: 8px;
  box-shadow: var(--shadow-popover);
  pointer-events: auto;
}
.toast-item > svg {
  color: var(--success);
  flex-shrink: 0;
}
.toast-item.error > svg {
  color: var(--danger);
}
.toast-item p {
  font-size: 14px;
  line-height: 1.5;
  overflow-wrap: anywhere;
  flex: 1;
  margin: 0;
}
.toast-enter-active,
.toast-leave-active {
  transition:
    opacity 0.15s,
    transform 0.15s;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(8px);
}
@media (max-width: 600px) {
  .toast-stack {
    right: 16px;
    bottom: calc(16px + env(safe-area-inset-bottom));
  }
}
@media (prefers-reduced-motion: reduce) {
  .toast-enter-active,
  .toast-leave-active {
    transition: none;
  }
}
</style>
