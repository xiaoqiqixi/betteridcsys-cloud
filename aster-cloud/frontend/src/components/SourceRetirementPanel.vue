<script setup lang="ts">
import { computed, onScopeDispose, shallowRef } from "vue";
import { RouterLink } from "vue-router";
import { useConsole } from "../context";
import { useMutation } from "../composables/mutation";
import { operationResponse } from "../api/client";
import type { Instance, Migration } from "../api/types";
import UiButton from "./UiButton.vue";
import UiOverlay from "./UiOverlay.vue";
import InlineError from "./InlineError.vue";
const props = defineProps<{ instance: Instance; migration: Migration }>();
const {
  session,
  prefs: { tr },
  notify,
} = useConsole();
const mutation = useMutation();
const selected = shallowRef<Migration | null>(null),
  instanceConfirmation = shallowRef(""),
  migrationConfirmation = shallowRef(""),
  consent = shallowRef(false),
  acceptedID = shallowRef("");
let alive = true;
onScopeDispose(() => {
  alive = false;
});
const operationID = computed(
  () =>
    mutation.pendingKey.value ||
    acceptedID.value ||
    props.migration.source_retirement_operation_id,
);
const canPlan = computed(
  () =>
    session.can("migration.manage") &&
    props.migration.phase === "active" &&
    props.migration.source_retirement_state === "required" &&
    !mutation.pendingKey.value &&
    (!acceptedID.value ||
      (props.migration.source_retirement_operation_id === acceptedID.value &&
        props.migration.source_retirement_state === "required")) &&
    !mutation.busy.value,
);
const stateLabel = computed(() =>
  props.migration.source_retirement_state === "succeeded"
    ? tr("源实例已退役", "Source retired")
    : props.migration.source_retirement_state === "blocked"
      ? tr("退役结果需核实", "Retirement needs review")
      : props.migration.source_retirement_state === "pending" ||
          mutation.pendingKey.value ||
          (acceptedID.value &&
            !(
              props.migration.source_retirement_operation_id ===
                acceptedID.value &&
              props.migration.source_retirement_state === "required"
            ))
        ? tr(
            "退役任务待执行或核实",
            "Retirement awaiting execution or verification",
          )
        : tr(
            "目标已激活 · 源实例待退役",
            "Target active · source retirement required",
          ),
);
const confirmed = computed(
  () =>
    !!selected.value &&
    canPlan.value &&
    selected.value.id === props.migration.id &&
    selected.value.source_node_id === props.migration.source_node_id &&
    selected.value.target_node_id === props.migration.target_node_id &&
    instanceConfirmation.value === props.instance.id &&
    migrationConfirmation.value === selected.value.id &&
    consent.value,
);
function open() {
  if (canPlan.value) {
    selected.value = { ...props.migration };
    instanceConfirmation.value = "";
    migrationConfirmation.value = "";
    consent.value = false;
    mutation.clearMessage();
  }
}
async function submit() {
  if (!confirmed.value || !selected.value) return;
  const current = selected.value,
    instance = props.instance.id,
    epoch = session.epoch.value;
  const result = await mutation.execute(
    "POST",
    `/instances/${instance}/operations`,
    {
      action: "migrate_retire_source",
      confirmation: instance,
      artifact_id: current.id,
    },
    operationResponse,
    {
      expectedStatus: 202,
      bindOperation: {
        action: "migrate_retire_source",
        instanceId: instance,
        artifactId: current.id,
      },
      isCurrent: () =>
        alive &&
        epoch === session.epoch.value &&
        session.can("migration.manage") &&
        current.id === props.migration.id,
    },
  );
  if (result) {
    acceptedID.value = result.operation.id;
    selected.value = null;
    notify(
      tr(
        "源退役任务已受理，请核对并派发。",
        "Source retirement accepted. Review and dispatch its task.",
      ),
    );
  }
}
</script>
<template>
  <section
    class="retirement-panel"
    :aria-label="tr('迁移源退役', 'Migration source retirement')"
  >
    <header>
      <h2>{{ tr("5. 退役迁移源", "5. Retire migration source") }}</h2>
      <span>{{ stateLabel }}</span>
    </header>
    <p>
      {{
        tr(
          "目标激活后，源实例仍保持隔离。只有明确执行退役任务，才会清理旧源实例并释放其迁移预留；不会自动删除目标实例。",
          "After target activation the source remains fenced. Only an explicitly executed retirement task cleans up the old source and releases its reservations. The target is not deleted.",
        )
      }}
    </p>
    <dl>
      <div>
        <dt>{{ tr("源节点", "Source node") }}</dt>
        <dd>{{ migration.source_node_id }}</dd>
      </div>
      <div>
        <dt>{{ tr("目标节点", "Target node") }}</dt>
        <dd>{{ migration.target_node_id }}</dd>
      </div>
      <div>
        <dt>{{ tr("迁移记录", "Migration") }}</dt>
        <dd>{{ migration.id }}</dd>
      </div>
    </dl>
    <div class="retirement-actions">
      <RouterLink v-if="operationID" :to="`/operations/${operationID}`">{{
        tr("查看源退役任务", "View source retirement task")
      }}</RouterLink>
      <RouterLink
        v-if="
          migration.source_retirement_operation_id &&
          migration.source_retirement_operation_id !== operationID
        "
        :to="`/operations/${migration.source_retirement_operation_id}`"
        >{{
          tr("查看上次源退役任务", "View previous source retirement task")
        }}</RouterLink
      >
      <UiButton
        v-if="session.can('migration.manage')"
        variant="danger"
        :disabled="!canPlan"
        @click="open"
        >{{
          migration.source_retirement_state === "succeeded"
            ? tr("已退役", "Retired")
            : tr("退役迁移源", "Retire migration source")
        }}</UiButton
      >
    </div>
    <InlineError v-if="!selected" :error="mutation.error.value" />
    <UiOverlay
      :open="!!selected"
      :title="tr('退役迁移源', 'Retire migration source')"
      :busy="mutation.busy.value"
      :close-label="tr('关闭', 'Close')"
      @close="selected = null"
      ><p class="retirement-warning">
        {{
          tr(
            "这是独立的清理操作，不是再次激活目标。源节点上的旧实例将永久退役，不能再作为回退实例启动。请先确认目标与备份。",
            "This is a separate cleanup operation, not another target activation. The old source is permanently retired and cannot be restarted as a fallback. Verify the target and your backups first.",
          )
        }}
      </p>
      <form
        id="retire-source"
        class="retirement-form"
        novalidate
        @submit.prevent="submit"
      >
        <label class="field"
          >{{ tr("确认实例 ID", "Confirm instance ID")
          }}<code>{{ instance.id }}</code
          ><input
            v-model="instanceConfirmation"
            autocomplete="off"
            spellcheck="false"
            :disabled="
              mutation.busy.value || !!mutation.pendingKey.value
            " /></label
        ><label class="field"
          >{{ tr("确认迁移 ID", "Confirm migration ID")
          }}<code>{{ selected?.id }}</code
          ><input
            v-model="migrationConfirmation"
            autocomplete="off"
            spellcheck="false"
            :disabled="
              mutation.busy.value || !!mutation.pendingKey.value
            " /></label
        ><label class="retirement-consent"
          ><input
            v-model="consent"
            type="checkbox"
            :disabled="mutation.busy.value || !!mutation.pendingKey.value"
          /><span>{{
            tr(
              "确认永久退役源实例，保留当前目标实例",
              "Confirm permanent source retirement while retaining the active target",
            )
          }}</span></label
        ><InlineError
          :error="mutation.error.value"
          :pending-key="mutation.pendingKey.value"
        /><RouterLink
          v-if="mutation.pendingKey.value"
          :to="`/operations/${mutation.pendingKey.value}`"
          >{{
            tr(
              "读取原退役任务，不重复提交",
              "Read the original retirement task; do not resubmit",
            )
          }}</RouterLink
        >
      </form>
      <template #footer
        ><UiButton :disabled="mutation.busy.value" @click="selected = null">{{
          tr("取消", "Cancel")
        }}</UiButton
        ><UiButton
          variant="danger"
          type="submit"
          form="retire-source"
          :busy="mutation.busy.value"
          :disabled="!confirmed || !!mutation.pendingKey.value"
          >{{ tr("创建源退役任务", "Create source retirement task") }}</UiButton
        ></template
      ></UiOverlay
    >
  </section>
</template>
<style scoped>
.retirement-panel {
  margin-top: 24px;
  padding: 20px 0;
  border: 0;
  border-radius: 0;
  background: var(--surface);
  min-width: 0;
  border-block: 1px solid var(--border);
}
.retirement-panel header {
  display: flex;
  gap: 16px;
  justify-content: space-between;
  flex-wrap: wrap;
  align-items: center;
}
.retirement-panel h2 {
  font-size: 17px;
  margin: 0;
}
.retirement-panel header span,
.retirement-panel p {
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
}
.retirement-panel dl {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  margin: 18px 0;
}
.retirement-panel dt {
  font-size: 13px;
  color: var(--secondary);
  margin-bottom: 8px;
}
.retirement-panel dd {
  font-size: 14px;
  overflow-wrap: anywhere;
  margin: 0;
}
.retirement-actions {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
.retirement-actions a {
  min-height: 44px;
  display: inline-flex;
  align-items: center;
}
.retirement-form {
  display: grid;
  gap: 24px;
}
.retirement-form code {
  overflow-wrap: anywhere;
  color: var(--secondary);
}
.retirement-warning {
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
  margin: 0 0 24px;
}
.retirement-consent {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  font-size: 13px;
  line-height: 1.7;
  padding: 12px 0;
}
.retirement-consent input {
  appearance: none;
  flex: 0 0 20px;
  width: 20px;
  height: 20px;
  min-height: 20px;
  padding: 0;
  margin: 2px 0 0;
  border: 1px solid var(--control-border);
  border-radius: 5px;
  background: var(--surface);
}
.retirement-consent input:checked {
  background: var(--accent);
  border-color: var(--accent);
  box-shadow: inset 0 0 0 4px var(--surface-raised);
}
@media (max-width: 600px) {
  .retirement-panel {
    padding: 16px;
  }
  .retirement-panel dl {
    grid-template-columns: minmax(0, 1fr);
  }
}
@media (max-width: 600px) {
  .retirement-panel {
    padding: 18px 0;
  }
}
</style>
