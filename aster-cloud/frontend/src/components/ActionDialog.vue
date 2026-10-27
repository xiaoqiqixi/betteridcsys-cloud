<script setup lang="ts">
import { computed, shallowRef, watch } from "vue";
import { RouterLink } from "vue-router";
import type { Action, Instance, OperationInput } from "../api/types";
import { useConsole } from "../context";
import { useMutation } from "../composables/mutation";
import { operationResponse } from "../api/client";
import { actionNames } from "../format";
import UiOverlay from "./UiOverlay.vue";
import UiButton from "./UiButton.vue";
import InlineError from "./InlineError.vue";
const props = defineProps<{
  open: boolean;
  instance: Instance;
  action: Action;
  artifactId?: string;
  targetNodeId?: string;
}>();
const emit = defineEmits<{ close: []; accepted: [] }>();
const {
  prefs: { tr },
  notify,
} = useConsole();
const mutation = useMutation(),
  confirmation = shallowRef(""),
  accepted = shallowRef(false),
  acceptedID = shallowRef("");
const name = computed(() => props.instance.hostname || props.instance.id),
  label = computed(() => tr(...actionNames[props.action]!));
const destructive = computed(
  () =>
    !["start", "snapshot_create", "backup_create", "backup_verify"].includes(
      props.action,
    ),
);
watch(
  () => props.open,
  (value) => {
    if (value) {
      confirmation.value = "";
      accepted.value = false;
      acceptedID.value = "";
      mutation.clearMessage();
    }
  },
);
async function submit() {
  if (
    confirmation.value !== props.instance.id ||
    accepted.value ||
    mutation.pendingKey.value
  )
    return;
  const body: OperationInput = {
    action: props.action,
    confirmation: confirmation.value,
    ...(props.artifactId ? { artifact_id: props.artifactId } : {}),
    ...(props.targetNodeId ? { target_node_id: props.targetNodeId } : {}),
  };
  const result = await mutation.execute(
    "POST",
    `/instances/${encodeURIComponent(props.instance.id)}/operations`,
    body,
    operationResponse,
    {
      expectedStatus: 202,
      bindOperation: {
        action: props.action,
        instanceId: props.instance.id,
        ...(props.artifactId ? { artifactId: props.artifactId } : {}),
        ...(props.targetNodeId ? { targetNodeId: props.targetNodeId } : {}),
      },
    },
  );
  if (result) {
    accepted.value = true;
    acceptedID.value = result.operation.id;
    notify(
      tr(
        "操作已受理，可在任务中查看并继续。",
        "Operation accepted. Review and continue in Tasks.",
      ),
    );
    emit("accepted");
  }
}
</script>
<template>
  <UiOverlay
    :open="open"
    :title="label"
    :description="name"
    :busy="mutation.busy.value"
    :close-label="tr('关闭', 'Close')"
    @close="emit('close')"
    ><div v-if="accepted" class="accepted-message" role="status">
      <h3>{{ tr("操作已受理", "Operation accepted") }}</h3>
      <p>
        {{
          tr(
            "任务尚未执行。请到任务页面核对，再手动派发。",
            "The task has not run yet. Review it in Tasks, then dispatch explicitly.",
          )
        }}
      </p>
      <RouterLink
        class="task-link"
        :replace="true"
        :to="`/operations/${acceptedID}`"
        >{{ tr("查看原任务", "View original task") }}</RouterLink
      >
    </div>
    <template v-else
      ><p class="action-description">
        {{
          destructive
            ? tr(
                "此操作可能中断服务或覆盖数据，请先确认相关备份。",
                "This action may interrupt service or overwrite data. Confirm that your backups are ready.",
              )
            : tr(
                "将为此实例创建操作任务。",
                "An operation task will be created for this instance.",
              )
        }}
      </p>
      <label class="field"
        >{{ tr("输入实例 ID 以确认", "Type the instance ID to confirm")
        }}<strong class="confirmation-name">{{ instance.id }}</strong
        ><input
          v-model="confirmation"
          autocomplete="off"
          :disabled="mutation.busy.value || !!mutation.pendingKey.value"
          :aria-label="tr('确认实例 ID', 'Confirm instance ID')" /></label
      ><InlineError
        :error="mutation.error.value"
        :pending-key="mutation.pendingKey.value"
      />
      <RouterLink
        v-if="mutation.error.value === 'unknown' && mutation.pendingKey.value"
        class="task-link"
        :replace="true"
        :to="`/operations/${mutation.pendingKey.value}`"
        >{{ tr("查看原任务", "View original task") }}</RouterLink
      ></template
    ><template #footer
      ><UiButton @click="emit('close')" :disabled="mutation.busy.value">{{
        accepted ? tr("完成", "Done") : tr("取消", "Cancel")
      }}</UiButton
      ><UiButton
        v-if="!accepted"
        :variant="destructive ? 'danger' : 'primary'"
        :busy="mutation.busy.value"
        :disabled="confirmation !== instance.id || !!mutation.pendingKey.value"
        @click="submit"
        >{{ tr("创建任务", "Create task") }}</UiButton
      ></template
    ></UiOverlay
  >
</template>
<style scoped>
.action-description {
  color: var(--secondary);
  line-height: 1.7;
  margin: 0 0 24px;
}
.confirmation-name {
  display: block;
  font-weight: 600;
  overflow-wrap: anywhere;
  color: var(--text);
}
.accepted-message h3 {
  font-size: 18px;
  margin: 0 0 12px;
}
.accepted-message p {
  line-height: 1.7;
  color: var(--secondary);
}
.task-link {
  display: inline-flex;
  align-items: center;
  min-height: 44px;
  overflow-wrap: anywhere;
}
</style>
