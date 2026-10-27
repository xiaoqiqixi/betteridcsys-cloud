<script setup lang="ts">
import { computed, onScopeDispose, shallowRef, watch } from "vue";
import { RouterLink, useRoute } from "vue-router";
import { ApiError, operationResponse } from "../api/client";
import type { Operation } from "../api/types";
import { useConsole } from "../context";
import { acknowledgeOperations, useMutation } from "../composables/mutation";
import { actionPermission } from "../permissions";
import { actionNames } from "../format";
import UiButton from "./UiButton.vue";
import UiOverlay from "./UiOverlay.vue";
import InlineError from "./InlineError.vue";

const props = defineProps<{ operation: Operation }>();
const emit = defineEmits<{ updated: [operation: Operation] }>();
const {
  api,
  session,
  notify,
  prefs: { tr },
} = useConsole();
const route = useRoute(),
  mutation = useMutation();
const selected = shallowRef<Operation | null>(null),
  mode = shallowRef<"dispatch" | "reconcile">("dispatch"),
  confirmation = shallowRef(""),
  reading = shallowRef(false),
  readError = shallowRef(""),
  actionError = shallowRef("");
let generation = 0,
  readRevision = 0,
  abort: AbortController | undefined;
const displayName = computed(
  () =>
    selected.value &&
    (actionNames[selected.value.action]
      ? tr(...actionNames[selected.value.action]!)
      : selected.value.action),
);
function sameBinding(value: Operation, expected: Operation) {
  return [
    "id",
    "instance_id",
    "node_id",
    "action",
    "artifact_id",
    "target_node_id",
    "actor_id",
  ].every(
    (key) => value[key as keyof Operation] === expected[key as keyof Operation],
  );
}
function allowed(
  action: "dispatch" | "reconcile",
  operation = props.operation,
) {
  return (
    /^[a-f0-9]{32}$/.test(operation.id) &&
    session.can(actionPermission(operation.action)) &&
    (!["public_adopt", "public_detach"].includes(operation.action) ||
      (session.can("nodes.read") && session.can("nodes.manage"))) &&
    (action === "dispatch"
      ? operation.state === "accepted"
      : ["sending", "dispatched", "uncertain"].includes(operation.state))
  );
}
// Router params are decoded; raw paths may differ only by encoding or a trailing
// slash. Match the task record too, so an instance with the same ID is distinct.
const isCurrentTask = computed(
  () =>
    route.matched.at(-1)?.path === "/operations/:id" &&
    route.params.id === selected.value?.id,
);
const canDispatch = computed(() => allowed("dispatch"));
const canReconcile = computed(() => allowed("reconcile"));
function reset() {
  generation++;
  readRevision++;
  abort?.abort();
  reading.value = false;
  readError.value = "";
  actionError.value = "";
  selected.value = null;
  confirmation.value = "";
  mutation.clearMessage();
}
// A refreshed record invalidates any older confirmation, even when its ID is unchanged.
watch([() => props.operation, () => session.epoch.value], reset);
onScopeDispose(reset);
async function readOperation(closeOnSuccess = false) {
  if (
    reading.value ||
    mutation.busy.value ||
    !/^[a-f0-9]{32}$/.test(props.operation.id)
  )
    return;
  const expected = { ...props.operation },
    identity = session.epoch.value,
    ticket = ++readRevision,
    lifetime = generation;
  abort?.abort();
  abort = new AbortController();
  reading.value = true;
  readError.value = "";
  try {
    const result = await api.get(
      `/operations/${expected.id}`,
      (value): value is { operation: Operation } =>
        operationResponse(value) && sameBinding(value.operation, expected),
      abort.signal,
    );
    if (
      ticket !== readRevision ||
      lifetime !== generation ||
      identity !== session.epoch.value
    )
      return;
    acknowledgeOperations(session.user.value?.id || "", [result.operation]);
    if (closeOnSuccess) selected.value = null;
    emit("updated", result.operation);
  } catch (cause) {
    if (
      ticket !== readRevision ||
      lifetime !== generation ||
      identity !== session.epoch.value
    )
      return;
    readError.value = cause instanceof ApiError ? cause.kind : "network";
    if (cause instanceof ApiError && cause.kind === "unauthorized")
      session.invalidate();
  } finally {
    if (ticket === readRevision) reading.value = false;
  }
}
function open(action: "dispatch" | "reconcile") {
  if (!allowed(action) || mutation.busy.value || reading.value) return;
  selected.value = { ...props.operation };
  mode.value = action;
  confirmation.value = "";
  actionError.value = "";
  mutation.clearMessage();
}
async function submit() {
  const op = selected.value,
    action = mode.value;
  if (!op || confirmation.value !== op.id) return;
  if (!sameBinding(props.operation, op) || !allowed(action)) {
    actionError.value = session.can(actionPermission(op.action))
      ? "conflict"
      : "forbidden";
    return;
  }
  const lifetime = generation,
    identity = session.epoch.value;
  const result = await mutation.execute(
    "POST",
    `/operations/${op.id}/${action}`,
    {},
    (value): value is { operation: Operation } =>
      operationResponse(value) && sameBinding(value.operation, op),
    {
      key: op.id,
      expectedStatus: 202,
      allowUncertainReconcile: action === "reconcile",
      bindOperation: {
        instanceId: op.instance_id,
        nodeId: op.node_id,
        actorId: op.actor_id,
        action: op.action,
        artifactId: op.artifact_id,
        targetNodeId: op.target_node_id,
      },
    },
  );
  if (!result || lifetime !== generation || identity !== session.epoch.value)
    return;
  selected.value = null;
  notify(
    result.operation.state === "succeeded"
      ? tr("任务已完成。", "Task completed.")
      : result.operation.state === "uncertain"
        ? tr(
            "结果仍待核实，请勿重复派发。",
            "The result remains uncertain. Do not dispatch again.",
          )
        : tr("任务状态已更新。", "Task state updated."),
  );
  emit("updated", result.operation);
}
</script>
<template>
  <div class="operation-controls">
    <div class="operation-buttons">
      <UiButton
        variant="quiet"
        :busy="reading"
        :disabled="mutation.busy.value"
        @click="readOperation()"
        >{{ tr("读取状态", "Read state") }}</UiButton
      >
      <UiButton
        v-if="canDispatch"
        :disabled="reading || mutation.busy.value"
        @click="open('dispatch')"
        >{{ tr("派发任务", "Dispatch") }}</UiButton
      >
      <UiButton
        v-if="canReconcile"
        :disabled="reading || mutation.busy.value"
        @click="open('reconcile')"
        >{{
          tr(
            operation.state === "uncertain" ? "核对结果" : "核对进度",
            operation.state === "uncertain"
              ? "Reconcile result"
              : "Check progress",
          )
        }}</UiButton
      >
    </div>
    <InlineError :error="readError" />
    <UiOverlay
      :open="!!selected"
      :title="
        mode === 'dispatch'
          ? tr('派发任务', 'Dispatch task')
          : tr('核对任务进度', 'Check task progress')
      "
      :description="displayName || ''"
      :busy="mutation.busy.value"
      :close-label="tr('关闭', 'Close')"
      @close="selected = null"
    >
      <p class="secondary">
        {{
          mode === "dispatch"
            ? tr(
                "将向节点发送一次此任务。确认后，请勿重复派发。",
                "Send this task to the node once. Do not dispatch it again.",
              )
            : tr(
                "只查询节点已有操作的结果，不会重新执行任务。",
                "Query the existing node operation. The task will not be executed again.",
              )
        }}
      </p>
      <dl class="detail-pairs">
        <div>
          <dt>{{ tr("实例", "Instance") }}</dt>
          <dd>{{ selected?.instance_id }}</dd>
        </div>
        <div>
          <dt>{{ tr("任务 ID", "Task ID") }}</dt>
          <dd>{{ selected?.id }}</dd>
        </div>
      </dl>
      <label class="field confirmation-field"
        >{{ tr("输入任务 ID 以确认", "Type the task ID to confirm")
        }}<input
          v-model="confirmation"
          autocomplete="off"
          :disabled="
            mutation.busy.value ||
            (!!mutation.pendingKey.value && mode !== 'reconcile')
          "
      /></label>
      <InlineError
        :error="readError || actionError || mutation.error.value"
        :pending-key="mutation.pendingKey.value"
      />
      <template
        v-if="
          selected &&
          mutation.error.value === 'unknown' &&
          mutation.pendingKey.value === selected.id
        "
      >
        <UiButton
          v-if="isCurrentTask"
          variant="quiet"
          class="pending-task-link"
          :busy="reading"
          :disabled="mutation.busy.value"
          @click="readOperation(true)"
          >{{ tr("读取原任务", "Read original task") }}</UiButton
        >
        <RouterLink
          v-else
          class="pending-task-link"
          :replace="true"
          :to="`/operations/${selected.id}`"
          >{{ tr("查看原任务", "View original task") }}</RouterLink
        >
      </template>
      <template #footer>
        <UiButton :disabled="mutation.busy.value" @click="selected = null">{{
          tr("取消", "Cancel")
        }}</UiButton>
        <UiButton
          variant="primary"
          :busy="mutation.busy.value"
          :disabled="
            confirmation !== selected?.id ||
            (!!mutation.pendingKey.value && mode !== 'reconcile')
          "
          @click="submit"
          >{{
            mode === "dispatch"
              ? tr("确认派发", "Confirm dispatch")
              : tr("核对进度", "Check progress")
          }}</UiButton
        >
      </template>
    </UiOverlay>
  </div>
</template>
<style scoped>
.operation-controls {
  min-width: 0;
}
.operation-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.confirmation-field {
  margin-top: 24px;
}
.pending-task-link {
  display: inline-block;
  padding-block: 10px;
  overflow-wrap: anywhere;
}
</style>
