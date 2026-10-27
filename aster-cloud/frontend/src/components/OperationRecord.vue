<script setup lang="ts">
import { computed } from "vue";
import { RouterLink } from "vue-router";
import { RefreshCw } from "@lucide/vue";
import { operationResponse } from "../api/client";
import type { Operation } from "../api/types";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { actionNames, dateText } from "../format";
import OperationActions from "./OperationActions.vue";
import StateBlock from "./StateBlock.vue";
import StatusBadge from "./StatusBadge.vue";
import UiButton from "./UiButton.vue";
const props = defineProps<{ id: string }>();
const {
  session,
  prefs: { tr, locale },
} = useConsole();
// The route parent validates and keys this component by ID. Capture its request
// binding so a late response can never be validated against a different route.
const requestID = props.id;
const detail = useQuery(
  () => `/operations/${requestID}`,
  (value): value is { operation: Operation } =>
    operationResponse(value) && value.operation.id === requestID,
);
const operation = computed(() => detail.data.value?.operation);
const explanation = computed(() => {
  switch (operation.value?.state) {
    case "accepted":
      return tr(
        "任务已受理，等待明确派发。",
        "The task has been accepted and awaits explicit dispatch.",
      );
    case "sending":
      return tr(
        "正在派发，请核对原任务进度，不要再次派发。",
        "Dispatch is in progress. Check this task instead of dispatching again.",
      );
    case "dispatched":
      return tr(
        "节点已受理，处理结果仍待核对。",
        "The node has accepted the task. Reconcile its progress to confirm the result.",
      );
    case "uncertain":
      return tr(
        "结果尚未确认。请核对原任务，不要重复派发。",
        "The result is uncertain. Reconcile the original task; do not dispatch again.",
      );
    case "succeeded":
      return tr("任务已完成。", "The task has completed.");
    case "rejected":
      return tr(
        "任务已被拒绝。请检查实例与节点状态。",
        "The task was rejected. Review the instance and node state.",
      );
    default:
      return tr(
        "当前状态尚无法确认，请核对原任务，不要重复派发。",
        "The current state is unconfirmed. Check the original task; do not dispatch again.",
      );
  }
});
function updated(value: Operation) {
  if (value.id === requestID) detail.data.value = { operation: value };
}
</script>
<template>
  <header class="page-heading task-heading">
    <div>
      <h1>{{ tr("任务详情", "Task details") }}</h1>
      <p class="task-reference">{{ id }}</p>
    </div>
    <UiButton :busy="detail.loading.value" @click="detail.reload"
      ><RefreshCw :size="16" aria-hidden="true" />{{
        tr("刷新", "Refresh")
      }}</UiButton
    >
  </header>
  <StateBlock
    :loading="detail.loading.value"
    :error="detail.error.value"
    @reload="detail.reload"
  >
    <template v-if="operation">
      <article class="task-record">
        <header class="task-summary">
          <h2>
            {{
              actionNames[operation.action]
                ? tr(...actionNames[operation.action]!)
                : operation.action
            }}
          </h2>
          <StatusBadge :state="operation.state" />
        </header>
        <p
          class="task-explanation"
          :class="{
            'needs-review': ['sending', 'dispatched', 'uncertain'].includes(
              operation.state,
            ),
          }"
        >
          {{ explanation }}
        </p>
        <dl class="task-fields">
          <div>
            <dt>{{ tr("任务 ID", "Task ID") }}</dt>
            <dd>{{ operation.id }}</dd>
          </div>
          <div>
            <dt>{{ tr("实例", "Instance") }}</dt>
            <dd>
              <RouterLink
                :to="`/instances/${encodeURIComponent(operation.instance_id)}`"
                >{{ operation.instance_id }}</RouterLink
              >
            </dd>
          </div>
          <div>
            <dt>{{ tr("执行节点", "Execution node") }}</dt>
            <dd>{{ operation.node_id || "—" }}</dd>
          </div>
          <div>
            <dt>{{ tr("目标节点", "Target node") }}</dt>
            <dd>{{ operation.target_node_id || "—" }}</dd>
          </div>
          <div>
            <dt>{{ tr("制品或迁移 ID", "Artifact or migration ID") }}</dt>
            <dd>{{ operation.artifact_id || "—" }}</dd>
          </div>
          <div>
            <dt>{{ tr("创建者", "Created by") }}</dt>
            <dd>{{ operation.actor_id || "—" }}</dd>
          </div>
          <div>
            <dt>{{ tr("创建时间", "Created") }}</dt>
            <dd>{{ dateText(operation.created_at, locale) }}</dd>
          </div>
          <div>
            <dt>{{ tr("最后更新", "Last updated") }}</dt>
            <dd>{{ dateText(operation.updated_at, locale) }}</dd>
          </div>
        </dl>
        <p class="creator-note">
          {{
            tr(
              "创建者不一定是实际派发或核对任务的成员。",
              "The creator may differ from the member who dispatches or reconciles this task.",
            )
          }}
          <RouterLink
            v-if="session.can('audit.read')"
            :to="{ path: '/audit', query: { target: operation.id } }"
            >{{ tr("查看相关审计", "View related audit") }}</RouterLink
          >
        </p>
        <OperationActions :operation="operation" @updated="updated" />
      </article>
    </template>
  </StateBlock>
  <p v-if="detail.error.value" class="task-read-warning">
    {{
      tr(
        "未找到或暂不可读取任务，不代表节点未执行。请保留原任务编号，不要重复派发。",
        "A missing or unreadable task does not prove the node did not execute it. Keep the original reference and do not dispatch again.",
      )
    }}
  </p>
</template>
<style scoped>
.task-heading {
  margin-top: 24px;
}
.task-reference {
  overflow-wrap: anywhere;
  font-variant-numeric: tabular-nums;
}
.task-record {
  padding: 20px 0;
  border: 0;
  border-radius: 0;
  background: var(--surface);
  min-width: 0;
  border-block: 1px solid var(--border);
}
.task-summary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 16px;
}
.task-summary h2 {
  font-size: 18px;
  line-height: 1.5;
  margin: 0;
  overflow-wrap: anywhere;
}
.task-explanation {
  color: var(--secondary);
  line-height: 1.7;
  margin: 16px 0 22px;
  font-size: 14px;
}
.needs-review {
  color: var(--warning);
  background: var(--warning-bg);
  padding: 14px 16px;
  border-radius: 6px;
}
.task-fields {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 20px 28px;
  margin: 0;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--border);
}
.task-fields dt {
  color: var(--secondary);
  font-size: 12px;
  margin-bottom: 8px;
  line-height: 1.5;
}
.task-fields dd {
  font-size: 14px;
  line-height: 1.6;
  margin: 0;
  overflow-wrap: anywhere;
  font-variant-numeric: tabular-nums;
}
.creator-note {
  color: var(--secondary);
  line-height: 1.7;
  font-size: 12px;
  margin: 20px 0;
}
.creator-note a {
  white-space: nowrap;
}
.task-read-warning {
  color: var(--warning);
  line-height: 1.7;
  padding: 16px;
  background: var(--warning-bg);
  border-radius: 6px;
}
@media (max-width: 600px) {
  .task-record {
    padding: 20px;
  }
  .task-fields {
    grid-template-columns: minmax(0, 1fr);
    gap: 22px;
  }
}
@media (max-width: 600px) {
  .task-record {
    padding: 18px 0;
  }
}
</style>
