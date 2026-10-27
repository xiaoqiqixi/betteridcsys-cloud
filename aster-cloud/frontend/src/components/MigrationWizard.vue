<script setup lang="ts">
import { computed, shallowRef, watch } from "vue";
import { RouterLink } from "vue-router";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { useMutation } from "../composables/mutation";
import { operationResponse } from "../api/client";
import { validMigrationTargets } from "../api/migration-targets";
import type { Instance, Migration } from "../api/types";
import UiOverlay from "./UiOverlay.vue";
import UiSelect from "./UiSelect.vue";
import UiButton from "./UiButton.vue";
import StateBlock from "./StateBlock.vue";
import InlineError from "./InlineError.vue";
const props = defineProps<{
  open: boolean;
  instance: Instance;
  migrations: Migration[];
}>();
const emit = defineEmits<{ close: []; accepted: [] }>();
const {
  prefs: { tr },
  notify,
} = useConsole();
const nodes = useQuery(
  () => `/instances/${props.instance.id}/migration-targets`,
  validMigrationTargets,
);
const mutation = useMutation(),
  target = shallowRef(""),
  confirmation = shallowRef(""),
  accepted = shallowRef(false),
  acceptedID = shallowRef(""),
  phaseAtOpen = shallowRef("");
const existing = computed(() =>
  props.migrations.find((m) => !["active", "rejected"].includes(m.phase)),
);
const stage = computed(() =>
  existing.value?.phase === "imported"
    ? 3
    : existing.value?.phase === "transferred"
      ? 2
      : existing.value?.phase === "prepared"
        ? 1
        : 0,
);
const names = computed(() => [
  tr("准备源实例", "Prepare"),
  tr("安全传输", "Transfer"),
  tr("导入目标", "Import"),
  tr("激活目标", "Activate"),
]);
const allowed = computed(() =>
  (existing.value?.phase || "new") !== phaseAtOpen.value
    ? false
    : existing.value
      ? ["prepared", "transferred", "imported"].includes(existing.value.phase)
      : props.instance.state === "shutoff",
);
const options = computed(() =>
  (nodes.data.value?.items || [])
    .filter((n) => n.node_id !== props.instance.node_id)
    .map((n) => ({
      value: n.node_id,
      label: n.eligible
        ? n.node_id
        : `${n.node_id} · ${tr("不符合迁移条件", "Not eligible for migration")}`,
      disabled: !n.eligible,
    })),
);
const name = computed(() => props.instance.hostname || props.instance.id);
watch(
  () => props.open,
  (open) => {
    if (open) {
      phaseAtOpen.value = existing.value?.phase || "new";
      target.value = existing.value?.target_node_id || "";
      confirmation.value = "";
      accepted.value = false;
      acceptedID.value = "";
      mutation.clearMessage();
    }
  },
);
async function submit() {
  if (
    !allowed.value ||
    !target.value ||
    (stage.value === 0 &&
      !nodes.data.value?.items.some(
        (n) => n.node_id === target.value && n.eligible,
      )) ||
    confirmation.value !== props.instance.id ||
    mutation.pendingKey.value
  )
    return;
  const action =
    stage.value === 3
      ? "migrate_activate"
      : stage.value === 2
        ? "migrate_import"
        : stage.value === 1
          ? "migrate_transfer"
          : "migrate_prepare";
  const result = await mutation.execute(
    "POST",
    `/instances/${encodeURIComponent(props.instance.id)}/operations`,
    {
      action,
      confirmation: confirmation.value,
      ...(stage.value === 0
        ? { target_node_id: target.value }
        : { artifact_id: existing.value?.id }),
    },
    operationResponse,
    {
      expectedStatus: 202,
      bindOperation: {
        action,
        instanceId: props.instance.id,
        ...(stage.value === 0
          ? { targetNodeId: target.value }
          : { artifactId: existing.value?.id }),
      },
    },
  );
  if (result) {
    accepted.value = true;
    acceptedID.value = result.operation.id;
    notify(tr("迁移任务已受理。", "Migration task accepted."));
    emit("accepted");
  }
}
</script>
<template>
  <UiOverlay
    :open="open"
    :title="tr('迁移实例', 'Migrate instance')"
    :description="name"
    :busy="mutation.busy.value"
    :close-label="tr('关闭', 'Close')"
    @close="emit('close')"
    ><ol class="wizard-steps">
      <li
        v-for="(label, index) in names"
        :key="index"
        :class="{ current: index === stage, past: index < stage }"
        :aria-current="index === stage ? 'step' : undefined"
      >
        <span>{{ index + 1 }}</span
        >{{ label }}
      </li>
    </ol>
    <div v-if="accepted" class="callout" role="status">
      {{
        tr(
          "本阶段任务已受理。请在任务中核对并派发，完成后再继续下一阶段。",
          "This stage has been accepted. Review and dispatch the task, then return after it completes.",
        )
      }}
      <RouterLink
        class="task-link"
        :replace="true"
        :to="`/operations/${acceptedID}`"
        >{{ tr("查看原任务", "View original task") }}</RouterLink
      >
    </div>
    <template v-else
      ><p class="wizard-explanation">
        {{
          stage === 0
            ? tr(
                "先准备源实例并隔离，避免源与目标同时启动。",
                "Prepare and fence the source first to prevent simultaneous activation.",
              )
            : stage === 1
              ? tr(
                  "将准备好的迁移数据安全传输到目标节点，完整校验后才能导入。传输不会启动目标实例。",
                  "Transfer prepared data to the target and verify it before import. Transfer does not start the target instance.",
                )
              : stage === 2
                ? tr(
                    "将已准备的数据导入目标节点。源实例继续保持隔离。",
                    "Import prepared data to the target. The source remains fenced.",
                  )
                : tr(
                    "确认目标已就绪后再激活。此操作不会自动解除源实例隔离。",
                    "Activate only after the target is ready. The source will not be unfenced automatically.",
                  )
        }}
      </p>
      <div v-if="!allowed" class="callout">
        {{
          tr(
            "当前迁移仍在处理中，请先查看相关任务。",
            "A migration is still in progress. Check its task before continuing.",
          )
        }}
      </div>
      <StateBlock
        v-if="stage === 0 && !existing"
        :loading="nodes.loading.value"
        :error="nodes.error.value"
        @reload="nodes.reload"
        ><label class="field"
          >{{ tr("目标节点", "Target node")
          }}<UiSelect
            v-model="target"
            :label="tr('选择目标节点', 'Choose target node')"
            :options="options"
            :placeholder="tr('选择兼容节点', 'Choose a compatible node')"
            :disabled="mutation.busy.value || !!mutation.pendingKey.value"
        /></label>
        <p v-if="!nodes.loading.value && !nodes.error.value" class="field-note">
          {{
            tr(
              "仅可选择后端已核验网络、容量和迁移条件的节点；公网直绑必须保留原地址与 MAC。",
              "Only nodes verified for network, capacity and migration compatibility are selectable. A direct public address and MAC must remain unchanged.",
            )
          }}
        </p></StateBlock
      >
      <dl v-else class="detail-pairs">
        <div>
          <dt>{{ tr("目标节点", "Target node") }}</dt>
          <dd>{{ target }}</dd>
        </div>
      </dl>
      <label class="field confirmation-field"
        >{{ tr("输入实例 ID 以确认", "Type the instance ID to confirm")
        }}<strong class="break-anywhere">{{ instance.id }}</strong
        ><input
          v-model="confirmation"
          autocomplete="off"
          :disabled="
            !allowed || mutation.busy.value || !!mutation.pendingKey.value
          " /></label
      ><InlineError
        :error="mutation.error.value"
        :pending-key="mutation.pendingKey.value"
      /><RouterLink
        v-if="mutation.error.value === 'unknown' && mutation.pendingKey.value"
        class="task-link"
        :replace="true"
        :to="`/operations/${mutation.pendingKey.value}`"
        >{{ tr("查看原任务", "View original task") }}</RouterLink
      ></template
    ><template #footer
      ><UiButton :disabled="mutation.busy.value" @click="emit('close')">{{
        tr("关闭", "Close")
      }}</UiButton
      ><UiButton
        v-if="!accepted"
        variant="primary"
        :busy="mutation.busy.value"
        :disabled="
          !allowed ||
          !target ||
          (stage === 0 &&
            !nodes.data.value?.items.some(
              (n) => n.node_id === target && n.eligible,
            )) ||
          confirmation !== instance.id ||
          !!mutation.pendingKey.value
        "
        @click="submit"
        >{{ tr("创建本阶段任务", "Create task for this stage") }}</UiButton
      ></template
    ></UiOverlay
  >
</template>
<style scoped>
.wizard-steps {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  list-style: none;
  gap: 12px;
  margin: 0 0 24px;
  padding: 0;
}
.wizard-steps li {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 10px;
  font-size: 12px;
  color: var(--secondary);
  line-height: 1.5;
}
.wizard-steps li > span {
  width: 28px;
  height: 28px;
  display: grid;
  place-items: center;
  border: 1px solid var(--control-border);
  border-radius: 50%;
  font-size: 12px;
}
.wizard-steps .current {
  color: var(--accent-text);
  font-weight: 600;
}
.wizard-steps .current > span {
  color: var(--on-accent);
  background: var(--accent);
  border-color: var(--accent);
}
.wizard-steps .past > span {
  background: var(--accent-bg);
  color: var(--accent-text);
}
.wizard-explanation {
  line-height: 1.7;
  color: var(--secondary);
  margin: 0 0 24px;
}
.confirmation-field {
  margin-top: 24px;
}
.task-link {
  display: flex;
  align-items: center;
  min-height: 44px;
  overflow-wrap: anywhere;
}
</style>
