<script setup lang="ts">
import { computed } from "vue";
import { RouterLink, useRoute } from "vue-router";
import { ArrowLeft } from "@lucide/vue";
import { useConsole } from "../context";
import OperationRecord from "../components/OperationRecord.vue";
const route = useRoute();
const {
  prefs: { tr },
} = useConsole();
const id = computed(() =>
  typeof route.params.id === "string" ? route.params.id : "",
);
const valid = computed(() => /^[a-f0-9]{32}$/.test(id.value));
</script>
<template>
  <section class="page">
    <RouterLink to="/operations" class="back-link"
      ><ArrowLeft :size="16" aria-hidden="true" />{{
        tr("全部任务", "All tasks")
      }}</RouterLink
    >
    <OperationRecord v-if="valid" :key="id" :id="id" />
    <div v-else class="invalid-task" role="alert">
      <h1>{{ tr("任务编号无效", "Invalid task reference") }}</h1>
      <p>
        {{
          tr(
            "请使用 32 位小写十六进制任务 ID 查找原任务。",
            "Use the original 32-character lowercase hexadecimal task ID.",
          )
        }}
      </p>
      <p>
        {{
          tr(
            "未能读取任务不代表操作未执行，请勿重新派发。",
            "A task that cannot be read may still have executed. Do not dispatch it again.",
          )
        }}
      </p>
    </div>
  </section>
</template>
<style scoped>
.invalid-task {
  margin-top: 24px;
  padding: 20px 0;
  border: 0;
  background: var(--surface);
  border-radius: 0;
  border-block: 1px solid var(--border);
}
.invalid-task h1 {
  font-size: 24px;
  line-height: 1.4;
  margin: 0 0 16px;
}
.invalid-task p {
  color: var(--secondary);
  line-height: 1.7;
  margin: 12px 0 0;
}
</style>
