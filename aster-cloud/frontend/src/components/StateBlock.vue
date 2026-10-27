<script setup lang="ts">
import { AlertCircle, Inbox } from "@lucide/vue";
import UiButton from "./UiButton.vue";
import { useConsole } from "../context";
import { failureNames } from "../format";
defineProps<{
  loading?: boolean;
  error?: string;
  empty?: boolean;
  title?: string;
  description?: string;
}>();
defineEmits<{ reload: [] }>();
const {
  prefs: { tr },
} = useConsole();
</script>
<template>
  <div
    v-if="loading"
    class="state-block loading"
    role="status"
    :aria-label="tr('正在加载', 'Loading')"
  >
    <span v-for="n in 4" :key="n" class="skeleton-row" /><span
      class="sr-only"
      >{{ tr("正在加载", "Loading") }}</span
    >
  </div>
  <div v-else-if="error" class="state-block error" role="alert">
    <AlertCircle :size="28" aria-hidden="true" />
    <h2>{{ tr("暂时无法加载", "Unable to load") }}</h2>
    <p>
      {{
        error === "invalid"
          ? tr(
              "内容暂时无法显示，请重新加载。",
              "The content could not be displayed. Try reloading.",
            )
          : tr(...(failureNames[error] || failureNames.unavailable)!)
      }}
    </p>
    <UiButton @click="$emit('reload')">{{ tr("重新加载", "Reload") }}</UiButton>
  </div>
  <div v-else-if="empty" class="state-block">
    <Inbox :size="30" aria-hidden="true" />
    <h2>{{ title || tr("暂无记录", "No records yet") }}</h2>
    <p v-if="description">{{ description }}</p>
    <slot name="empty" />
  </div>
  <slot v-else />
</template>
<style scoped>
.state-block {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  gap: 12px;
  min-height: 260px;
  padding: 32px 20px;
  background: var(--surface);
  border: 0;
  border-radius: 0;
  color: var(--secondary);
  border-block: 1px solid var(--border);
}
.state-block h2 {
  font-size: 17px;
  color: var(--text);
  margin: 4px 0 0;
}
.state-block p {
  margin: 0;
  max-width: 440px;
  line-height: 1.6;
}
.loading {
  align-items: stretch;
  gap: 18px;
}
.skeleton-row {
  height: 42px;
  border-radius: 8px;
  background: var(--skeleton);
  animation: breathe 1.5s ease-in-out infinite;
}
.skeleton-row:nth-child(2) {
  width: 85%;
}
.skeleton-row:nth-child(3) {
  width: 92%;
}
@keyframes breathe {
  50% {
    opacity: 0.45;
  }
}
@media (prefers-reduced-motion: reduce) {
  .skeleton-row {
    animation: none;
  }
}
</style>
