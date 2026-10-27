<script setup lang="ts">
import { shallowRef } from "vue";
import { RouterLink, useRouter } from "vue-router";
import { RefreshCw, ArrowUpRight, Search } from "@lucide/vue";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { validOperation, validPage } from "../api/client";
import type { Operation, Page } from "../api/types";
import { actionNames, dateText } from "../format";
import UiButton from "../components/UiButton.vue";
import StatusBadge from "../components/StatusBadge.vue";
import StateBlock from "../components/StateBlock.vue";
import OperationActions from "../components/OperationActions.vue";
const {
  prefs: { tr, locale },
} = useConsole();
const router = useRouter();
const cursor = shallowRef("");
const lookup = shallowRef("");
const lookupError = shallowRef(false);
const list = useQuery(
  () =>
    `/operations${cursor.value ? `?cursor=${encodeURIComponent(cursor.value)}` : ""}`,
  (v): v is Page<Operation> => validPage(v, validOperation),
);
function findTask() {
  if (!/^[a-f0-9]{32}$/.test(lookup.value)) {
    lookupError.value = true;
    return;
  }
  lookupError.value = false;
  void router.push(`/operations/${lookup.value}`);
}
function updated(operation: Operation) {
  if (list.data.value)
    list.data.value = {
      ...list.data.value,
      items: list.data.value.items.map((item) =>
        item.id === operation.id ? operation : item,
      ),
    };
}
</script>
<template>
  <section class="page">
    <header class="page-heading">
      <div>
        <h1>{{ tr("操作任务", "Tasks") }}</h1>
        <p>
          {{
            tr(
              "任务受理后需明确派发；结果不确定时，只核实状态。",
              "Dispatch accepted tasks explicitly. Reconcile uncertain results instead of resending.",
            )
          }}
        </p>
      </div>
      <UiButton :busy="list.loading.value" @click="list.reload"
        ><RefreshCw :size="16" aria-hidden="true" />{{
          tr("刷新", "Refresh")
        }}</UiButton
      >
    </header>
    <form class="task-lookup" @submit.prevent="findTask">
      <label class="lookup-field" for="task-lookup"
        >{{ tr("按任务 ID 查找", "Find a task by ID") }}
        <div class="lookup-input">
          <Search :size="18" aria-hidden="true" /><input
            id="task-lookup"
            v-model="lookup"
            :aria-label="tr('任务 ID', 'Task ID')"
            :aria-invalid="lookupError || undefined"
            :aria-describedby="lookupError ? 'task-lookup-error' : undefined"
            :placeholder="
              tr('输入任务或请求编号', 'Enter a task or request reference')
            "
            maxlength="32"
            autocomplete="off"
            spellcheck="false"
            @input="lookupError = false"
          />
        </div>
      </label>
      <UiButton type="submit" :disabled="!lookup">{{
        tr("查找任务", "Find task")
      }}</UiButton>
      <p
        v-if="lookupError"
        id="task-lookup-error"
        class="lookup-error"
        role="alert"
      >
        {{
          tr(
            "请输入 32 位小写十六进制任务 ID。",
            "Enter a 32-character lowercase hexadecimal task ID.",
          )
        }}
      </p>
    </form>
    <StateBlock
      :loading="list.loading.value"
      :error="list.error.value"
      :empty="!list.data.value?.items.length"
      :title="tr('暂无操作任务', 'No tasks yet')"
      :description="
        tr(
          '实例操作的进度与结果会保存在这里。',
          'Instance operations and their results will appear here.',
        )
      "
      @reload="list.reload"
      ><div class="resource-list">
        <article
          v-for="op in list.data.value?.items"
          :key="op.id"
          class="operation-row"
        >
          <div class="operation-main">
            <div class="operation-name">
              <strong>{{
                actionNames[op.action]
                  ? tr(...actionNames[op.action]!)
                  : op.action
              }}</strong
              ><StatusBadge :state="op.state" />
            </div>
            <RouterLink
              class="operation-reference"
              :to="`/operations/${encodeURIComponent(op.id)}`"
              :aria-label="tr(`查看任务 ${op.id}`, `View task ${op.id}`)"
              ><code>{{ op.id }}</code></RouterLink
            >
            <div class="operation-context">
              <RouterLink
                :to="`/instances/${encodeURIComponent(op.instance_id)}`"
                >{{ op.instance_id
                }}<ArrowUpRight :size="13" aria-hidden="true" /></RouterLink
              ><span>{{ dateText(op.created_at, locale) }}</span>
            </div>
          </div>
          <OperationActions :operation="op" @updated="updated" />
        </article></div
    ></StateBlock>
    <div v-if="list.data.value" class="pagination">
      <UiButton v-if="cursor" @click="cursor = ''">{{
        tr("回到首页", "First page")
      }}</UiButton
      ><UiButton
        v-if="list.data.value.next_cursor"
        @click="cursor = list.data.value!.next_cursor!"
        >{{ tr("下一页", "Next page") }}</UiButton
      >
    </div>
  </section>
</template>
<style scoped>
.operation-row {
  padding: 16px 0;
  display: flex;
  align-items: center;
  gap: 20px;
  border-bottom: 1px solid var(--border);
}
.operation-row:last-child {
  border-bottom: 0;
}
.operation-main {
  min-width: 0;
  flex: 1;
  display: grid;
  grid-template-columns: minmax(150px, 1fr) minmax(180px, 1.4fr);
  gap: 8px 20px;
}
.operation-name {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.operation-name strong {
  font-size: 15px;
}
.operation-reference {
  display: block;
  color: var(--secondary);
  font-size: 13px;
  overflow-wrap: anywhere;
  margin-top: 0;
  text-decoration: none;
  align-self: center;
  grid-column: 2;
  grid-row: 1;
}
.operation-context {
  display: flex;
  gap: 16px;
  align-items: center;
  flex-wrap: wrap;
  margin-top: 0;
  font-size: 13px;
  color: var(--secondary);
  grid-column: 1 / -1;
}
.operation-context a {
  display: flex;
  align-items: center;
  gap: 4px;
  color: var(--accent-text);
  overflow-wrap: anywhere;
}
.operation-context a svg {
  flex-shrink: 0;
}
.task-lookup {
  display: flex;
  align-items: flex-end;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}
.lookup-field {
  display: flex;
  flex-direction: column;
  gap: 7px;
  font-size: 14px;
  color: var(--secondary);
  flex: 1;
  min-width: min(100%, 240px);
  max-width: 480px;
}
.lookup-input {
  display: flex;
  align-items: center;
  gap: 10px;
  padding-left: 12px;
  border: 1px solid var(--control-border);
  border-radius: 6px;
  background: var(--surface);
}
.lookup-input svg {
  flex-shrink: 0;
}
.lookup-input input {
  min-width: 0;
  width: 100%;
  min-height: 44px;
  padding: 10px 12px 10px 0;
  border: 0;
  border-radius: 6px;
  background: transparent;
  font-size: 14px;
}
.lookup-error {
  flex-basis: 100%;
  margin: 0;
  color: var(--danger);
  font-size: 13px;
  line-height: 1.6;
}
.operation-reference:hover {
  text-decoration: underline;
  color: var(--accent-text);
}
@media (max-width: 600px) {
  .operation-row {
    padding: 20px;
    align-items: flex-start;
    flex-direction: column;
    gap: 16px;
  }
  .task-lookup {
    align-items: stretch;
  }
  .lookup-field {
    max-width: none;
    flex-basis: 100%;
  }
  .operation-context {
    gap: 8px;
  }
}
@media (max-width: 760px) {
  .operation-row {
    padding: 16px 0;
    align-items: flex-start;
    flex-direction: column;
    gap: 12px;
  }
  .operation-main {
    display: block;
    width: 100%;
  }
  .operation-reference {
    margin-top: 8px;
  }
  .operation-context {
    margin-top: 8px;
    gap: 8px 14px;
  }
}
</style>
