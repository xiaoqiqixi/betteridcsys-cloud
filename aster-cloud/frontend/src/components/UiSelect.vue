<script setup lang="ts">
import {
  computed,
  nextTick,
  onBeforeUnmount,
  shallowRef,
  useId,
  useTemplateRef,
} from "vue";
import { Check, ChevronDown } from "@lucide/vue";
export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}
const props = defineProps<{
  modelValue: string;
  options: SelectOption[];
  label: string;
  disabled?: boolean;
  placeholder?: string;
}>();
const emit = defineEmits<{ "update:modelValue": [value: string] }>();
const id = useId(),
  open = shallowRef(false),
  active = shallowRef(-1),
  root = useTemplateRef<HTMLElement>("root"),
  button = useTemplateRef<HTMLButtonElement>("button");
let search = "",
  searchTimer: ReturnType<typeof setTimeout> | undefined;
const selected = computed(() =>
  props.options.find((v) => v.value === props.modelValue),
);
const enabled = computed(() =>
  props.options.map((v, i) => (v.disabled ? -1 : i)).filter((i) => i >= 0),
);
function scroll() {
  void nextTick(() =>
    document
      .getElementById(`${id}-${active.value}`)
      ?.scrollIntoView({ block: "nearest" }),
  );
}
function show() {
  if (props.disabled) return;
  open.value = true;
  const i = props.options.findIndex(
    (v) => v.value === props.modelValue && !v.disabled,
  );
  active.value = i >= 0 ? i : (enabled.value[0] ?? -1);
  scroll();
}
function close() {
  open.value = false;
}
function choose(i: number) {
  const option = props.options[i];
  if (!option || option.disabled) return;
  emit("update:modelValue", option.value);
  close();
  button.value?.focus();
}
function key(event: KeyboardEvent) {
  if (event.key === "Escape" && open.value) {
    event.preventDefault();
    event.stopPropagation();
    close();
    return;
  }
  if (event.key === "Tab") {
    close();
    return;
  }
  if (
    ["ArrowDown", "ArrowUp", "Home", "End", "Enter", " "].includes(event.key)
  ) {
    event.preventDefault();
    if (!open.value) {
      show();
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      choose(active.value);
      return;
    }
    const indexes = enabled.value;
    const position = indexes.indexOf(active.value);
    active.value =
      event.key === "Home"
        ? (indexes[0] ?? -1)
        : event.key === "End"
          ? (indexes.at(-1) ?? -1)
          : (indexes[
              (position + (event.key === "ArrowUp" ? -1 : 1) + indexes.length) %
                indexes.length
            ] ?? -1);
    scroll();
  } else if (
    event.key.length === 1 &&
    !event.ctrlKey &&
    !event.metaKey &&
    !event.altKey
  ) {
    if (!open.value) show();
    search += event.key.toLocaleLowerCase();
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => (search = ""), 700);
    const match = props.options.findIndex(
      (v) => !v.disabled && v.label.toLocaleLowerCase().startsWith(search),
    );
    if (match >= 0) {
      active.value = match;
      scroll();
    }
  }
}
function outside(event: PointerEvent) {
  if (event.target instanceof Node && !root.value?.contains(event.target))
    close();
}
document.addEventListener("pointerdown", outside);
onBeforeUnmount(() => {
  document.removeEventListener("pointerdown", outside);
  clearTimeout(searchTimer);
});
</script>
<template>
  <div ref="root" class="ui-select">
    <button
      :id="`${id}-trigger`"
      ref="button"
      type="button"
      role="combobox"
      class="select-trigger"
      :disabled="disabled"
      :aria-label="label"
      :aria-expanded="open"
      :aria-controls="`${id}-list`"
      aria-haspopup="listbox"
      :aria-activedescendant="
        open && active >= 0 ? `${id}-${active}` : undefined
      "
      @click="open ? close() : show()"
      @keydown="key"
      @blur="close"
    >
      <span>{{ selected?.label || placeholder || "—" }}</span
      ><ChevronDown :size="16" aria-hidden="true" />
    </button>
    <ul
      v-if="open"
      :id="`${id}-list`"
      role="listbox"
      :aria-label="label"
      class="select-menu"
    >
      <li
        v-for="(option, index) in options"
        :id="`${id}-${index}`"
        :key="option.value"
        role="option"
        :aria-selected="option.value === modelValue"
        :aria-disabled="option.disabled || undefined"
        :class="{ active: active === index, unavailable: option.disabled }"
        @pointerdown.prevent="choose(index)"
        @pointermove="!option.disabled && (active = index)"
      >
        <span>{{ option.label }}</span
        ><Check
          v-if="option.value === modelValue"
          :size="16"
          aria-hidden="true"
        />
      </li>
      <li v-if="!options.length" class="select-empty" role="presentation">—</li>
    </ul>
  </div>
</template>
<style scoped>
.ui-select {
  position: relative;
  min-width: 0;
}
.select-trigger {
  width: 100%;
  min-height: 44px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 12px;
  border: 1px solid var(--control-border);
  border-radius: 6px;
  background: var(--surface);
  color: var(--text);
  text-align: left;
}
.select-trigger span {
  min-width: 0;
  overflow-wrap: anywhere;
}
.select-trigger svg {
  flex-shrink: 0;
}
.select-trigger:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
.select-menu {
  position: absolute;
  z-index: 30;
  top: calc(100% + 6px);
  left: 0;
  right: 0;
  max-height: min(260px, 40dvh);
  overflow: auto;
  padding: 5px;
  list-style: none;
  background: var(--surface-raised);
  border: 1px solid var(--control-border);
  border-radius: 8px;
  box-shadow: var(--shadow-popover);
  margin: 0;
}
.select-menu li {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  min-height: 44px;
  padding: 10px;
  border-radius: 7px;
  cursor: pointer;
  overflow-wrap: anywhere;
}
.select-menu .active {
  background: var(--accent-bg);
  color: var(--accent-text);
}
.select-menu .unavailable {
  color: var(--muted);
  cursor: not-allowed;
}
.select-menu svg {
  flex-shrink: 0;
}
.select-empty {
  color: var(--muted);
}
</style>
