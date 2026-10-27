<script setup lang="ts">
import {
  nextTick,
  onBeforeUnmount,
  shallowRef,
  useId,
  useTemplateRef,
  watch,
} from "vue";
import { X } from "@lucide/vue";
import { key32 } from "../api/client";
import {
  enterOverlay,
  leaveOverlay,
  isTopOverlay,
  overlayPopHandled,
  handleOverlayPop,
} from "./overlay-stack";
const props = withDefaults(
  defineProps<{
    open: boolean;
    title: string;
    description?: string;
    busy?: boolean;
    dirty?: boolean;
    drawer?: boolean;
    closeLabel?: string;
    discardLabel?: string;
    continueLabel?: string;
  }>(),
  { closeLabel: "关闭", discardLabel: "放弃更改", continueLabel: "继续编辑" },
);
const emit = defineEmits<{ close: [] }>();
const id = useId(),
  panel = useTemplateRef<HTMLElement>("panel"),
  shade = useTemplateRef<HTMLElement>("shade"),
  discard = shallowRef(false);
let previous: HTMLElement | null = null,
  token = "",
  openedURL = "",
  layerRoot: HTMLElement | null = null,
  mounted = false;
function focusables() {
  return [
    ...(panel.value?.querySelectorAll<HTMLElement>(
      'button:not(:disabled),input:not(:disabled),a[href],textarea:not(:disabled),[tabindex="0"]',
    ) || []),
  ].filter((el) => el.getClientRects().length > 0);
}
function ask() {
  if (props.busy || !isTopOverlay(layerRoot)) return;
  if (props.dirty) {
    discard.value = true;
    void nextTick(() =>
      panel.value
        ?.querySelector<HTMLElement>(".discard-actions button")
        ?.focus(),
    );
    return;
  }
  emit("close");
}
function key(event: KeyboardEvent) {
  if (!props.open || !isTopOverlay(layerRoot)) return;
  if (event.key === "Escape") {
    event.preventDefault();
    if (discard.value) discard.value = false;
    else ask();
  }
  if (event.key === "Tab") {
    const items = focusables();
    if (!items.length) {
      event.preventDefault();
      panel.value?.focus();
      return;
    }
    const first = items[0],
      last = items.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last?.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first?.focus();
    }
  }
}
function pop(event: PopStateEvent) {
  if (
    !props.open ||
    !isTopOverlay(layerRoot) ||
    overlayPopHandled(event) ||
    history.state?.asterOverlay === token
  )
    return;
  handleOverlayPop(event);
  if (props.busy || props.dirty) {
    history.pushState({ ...history.state, asterOverlay: token }, "");
    if (props.dirty && !props.busy) discard.value = true;
    return;
  }
  emit("close");
}
function focus(event: FocusEvent) {
  if (
    props.open &&
    isTopOverlay(layerRoot) &&
    event.target instanceof Node &&
    !panel.value?.contains(event.target)
  )
    panel.value?.focus();
}
function cleanup() {
  if (!mounted) return;
  mounted = false;
  const wasTop = layerRoot ? leaveOverlay(layerRoot) : false;
  layerRoot = null;
  document.removeEventListener("keydown", key);
  document.removeEventListener("focusin", focus);
  window.removeEventListener("popstate", pop);
  if (history.state?.asterOverlay === token) {
    if (location.href === openedURL) history.back();
    else {
      const state = { ...history.state };
      delete state.asterOverlay;
      history.replaceState(state, "");
    }
  }
  if (wasTop && previous?.isConnected && !previous.closest("[inert]"))
    previous.focus();
  discard.value = false;
}
watch(
  () => props.open,
  async (value) => {
    if (!value) {
      cleanup();
      return;
    }
    await nextTick();
    if (!props.open) return;
    previous =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    token = `cloud-${key32()}`;
    openedURL = location.href;
    layerRoot = shade.value;
    if (!layerRoot) return;
    enterOverlay(layerRoot, token, openedURL);
    history.pushState({ ...history.state, asterOverlay: token }, "");
    mounted = true;
    document.addEventListener("keydown", key);
    document.addEventListener("focusin", focus);
    window.addEventListener("popstate", pop);
    (focusables()[0] || panel.value)?.focus();
  },
  { immediate: true },
);
onBeforeUnmount(cleanup);
</script>
<template>
  <Teleport to="body"
    ><Transition name="overlay"
      ><div
        v-if="open"
        ref="shade"
        class="overlay-shade"
        :class="{ 'as-drawer': drawer }"
        @click.self="ask"
      >
        <section
          ref="panel"
          role="dialog"
          aria-modal="true"
          :aria-labelledby="`${id}-title`"
          :aria-describedby="description ? `${id}-description` : undefined"
          tabindex="-1"
          class="overlay-panel"
        >
          <header class="overlay-header">
            <div>
              <h2 :id="`${id}-title`">{{ title }}</h2>
              <p v-if="description" :id="`${id}-description`">
                {{ description }}
              </p>
            </div>
            <button
              type="button"
              class="icon-button"
              :aria-label="closeLabel"
              :disabled="busy"
              @click="ask"
            >
              <X :size="20" aria-hidden="true" />
            </button>
          </header>
          <div class="overlay-body">
            <div v-if="discard" class="discard-box" role="alert">
              <p>{{ discardLabel }}？</p>
              <div class="discard-actions">
                <button
                  type="button"
                  class="text-button"
                  @click="discard = false"
                >
                  {{ continueLabel }}</button
                ><button
                  type="button"
                  class="text-button danger-text"
                  @click="emit('close')"
                >
                  {{ discardLabel }}
                </button>
              </div>
            </div>
            <slot />
          </div>
          <footer v-if="$slots.footer" class="overlay-footer">
            <slot name="footer" :close="ask" />
          </footer>
        </section></div></Transition
  ></Teleport>
</template>
<style scoped>
.overlay-shade {
  position: fixed;
  inset: 0;
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  background: var(--scrim);
  backdrop-filter: blur(3px);
}
.overlay-panel {
  width: min(100%, 560px);
  max-height: calc(100dvh - 48px);
  display: flex;
  flex-direction: column;
  background: var(--surface-raised);
  border: 1px solid var(--border);
  border-radius: 8px;
  box-shadow: var(--shadow-dialog);
  outline: none;
  min-width: 0;
}
.overlay-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 24px;
  border-bottom: 1px solid var(--border);
}
.overlay-header,
.overlay-footer {
  flex-shrink: 0;
}
.overlay-header h2 {
  font-size: 21px;
  letter-spacing: -0.025em;
  line-height: 1.35;
  margin: 0;
  overflow-wrap: anywhere;
}
.overlay-header p {
  font-size: 14px;
  color: var(--secondary);
  line-height: 1.6;
  margin: 8px 0 0;
}
.overlay-body {
  padding: 24px;
  overflow: auto;
  overscroll-behavior: contain;
  min-height: 0;
  scrollbar-gutter: stable;
}
.overlay-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  flex-wrap: wrap;
  padding: 16px 24px;
  border-top: 1px solid var(--border);
}
.as-drawer {
  justify-content: flex-end;
  padding: 12px;
}
.as-drawer .overlay-panel {
  height: 100%;
  max-height: calc(100dvh - 24px);
  width: 560px;
}
.as-drawer .overlay-body {
  flex: 1;
}
.discard-box {
  padding: 16px;
  background: var(--warning-bg);
  color: var(--warning);
  border-radius: 6px;
  margin-bottom: 20px;
}
.discard-box p {
  margin: 0 0 12px;
}
.discard-actions {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}
.overlay-leave-active {
  pointer-events: none;
}
.overlay-enter-active,
.overlay-leave-active {
  transition: opacity 0.16s;
}
.overlay-enter-active .overlay-panel,
.overlay-leave-active .overlay-panel {
  transition: transform 0.16s;
}
.overlay-enter-from,
.overlay-leave-to {
  opacity: 0;
}
.overlay-enter-from .overlay-panel,
.overlay-leave-to .overlay-panel {
  transform: translateY(8px);
}
@media (max-width: 600px) {
  .overlay-shade {
    padding: 12px;
  }
  .overlay-panel {
    max-height: calc(100dvh - 24px);
  }
  .overlay-header {
    padding: 20px;
  }
  .overlay-body {
    padding: 20px;
  }
  .overlay-footer {
    padding: 16px 20px;
  }
  .as-drawer .overlay-panel {
    width: 100%;
  }
}
@media (prefers-reduced-motion: reduce) {
  .overlay-enter-active,
  .overlay-leave-active,
  .overlay-enter-active .overlay-panel,
  .overlay-leave-active .overlay-panel {
    transition: none;
  }
}
</style>
