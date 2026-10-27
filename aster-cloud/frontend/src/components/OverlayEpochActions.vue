<script setup lang="ts">
import { computed, onScopeDispose, shallowRef, watch } from "vue";
import { useRoute } from "vue-router";
import { epochResponse, type OverlayEpoch } from "../api/overlay";
import { useOverlayMutation } from "../composables/overlay-mutation";
import { useConsole } from "../context";
import UiButton from "./UiButton.vue";
import UiOverlay from "./UiOverlay.vue";
import InlineError from "./InlineError.vue";
const props = defineProps<{
    epoch: OverlayEpoch;
    latest: boolean;
    recoverable?: boolean;
  }>(),
  emit = defineEmits<{ updated: []; recover: [] }>();
const {
    session,
    notify,
    prefs: { tr },
  } = useConsole(),
  route = useRoute();
const mode = shallowRef<"advance" | "reconcile">("advance"),
  open = shallowRef(false),
  confirmation = shallowRef("");
const advance = useOverlayMutation(() => `advance:${props.epoch.id}`),
  reconcile = useOverlayMutation(() => `reconcile:${props.epoch.id}`);
const mutation = computed(() =>
  mode.value === "advance" ? advance : reconcile,
);
const allowed = computed(
  () => session.can("nodes.manage") && session.can("instances.manage"),
);
let generation = 0;
watch(
  [() => route.fullPath, session.epoch, () => props.epoch.snapshot_sha256],
  () => {
    generation++;
    open.value = false;
  },
  { flush: "sync" },
);
onScopeDispose(() => generation++);
function actionAllowed(value: "advance" | "reconcile") {
  return (
    allowed.value &&
    props.latest &&
    (value === "advance"
      ? props.epoch.state === "pending"
      : ["pending", "uncertain"].includes(props.epoch.state))
  );
}
function choose(value: "advance" | "reconcile") {
  if (!actionAllowed(value)) return;
  mode.value = value;
  mutation.value.load();
  confirmation.value = "";
  open.value = true;
}
async function submit() {
  if (
    !actionAllowed(mode.value) ||
    !open.value ||
    confirmation.value !== props.epoch.id
  )
    return;
  const expected = { ...props.epoch },
    action = mode.value,
    ticket = generation,
    identity = session.epoch.value;
  const isCurrent = () =>
    ticket === generation &&
    identity === session.epoch.value &&
    open.value &&
    props.epoch.id === expected.id &&
    props.epoch.snapshot_sha256 === expected.snapshot_sha256 &&
    actionAllowed(action);
  const result = await mutation.value.execute(
    `/overlays/epochs/${expected.id}/${action}`,
    {},
    (v): v is { epoch: OverlayEpoch } =>
      epochResponse(v) &&
      v.epoch.id === expected.id &&
      v.epoch.cluster_id === expected.cluster_id &&
      v.epoch.snapshot_sha256 === expected.snapshot_sha256,
    isCurrent,
    { key: expected.id, status: 202 },
  );
  if (!result || !isCurrent()) return;
  open.value = false;
  notify(
    action === "advance"
      ? tr(
          "已申请继续执行，请刷新查看各节点进度。",
          "Execution requested. Refresh to review per-node progress.",
        )
      : tr(
          "已核对节点回执，请查看最新状态。",
          "Node receipts checked. Review the updated state.",
        ),
  );
  emit("updated");
}
</script>
<template>
  <div v-if="allowed" class="epoch-controls">
    <UiButton
      v-if="latest && epoch.state === 'pending'"
      :disabled="
        advance.busy.value || reconcile.busy.value || !!advance.pendingKey.value
      "
      @click="choose('advance')"
      >{{ tr("继续执行", "Continue execution") }}</UiButton
    ><UiButton
      v-if="latest && ['pending', 'uncertain'].includes(epoch.state)"
      :disabled="
        advance.busy.value ||
        reconcile.busy.value ||
        !!reconcile.pendingKey.value
      "
      @click="choose('reconcile')"
      >{{ tr("核对节点回执", "Check node receipts") }}</UiButton
    ><UiButton
      v-if="latest && recoverable !== false && epoch.state !== 'superseded'"
      :disabled="advance.busy.value || reconcile.busy.value"
      @click="emit('recover')"
      >{{ tr("恢复网络", "Recover network") }}</UiButton
    >
  </div>
  <p
    v-if="advance.pendingKey.value || reconcile.pendingKey.value"
    class="pending-hint"
  >
    {{
      tr(
        "上一次请求结果未确认。请先刷新此变更；不会自动再次派发。",
        "The previous request is unconfirmed. Refresh this change first; it will not be redispatched automatically.",
      )
    }}
  </p>
  <UiOverlay
    :open="open"
    :title="
      mode === 'advance'
        ? tr('继续执行网络变更', 'Continue network change')
        : tr('核对节点回执', 'Check node receipts')
    "
    :busy="mutation.busy.value"
    :close-label="tr('关闭', 'Close')"
    @close="open = false"
    ><p class="secondary">
      {{
        mode === "advance"
          ? tr(
              "仅推进尚未派发的阶段。已发送但未确认的任务不会重复执行。",
              "Advance only phases not yet sent. Sent tasks with unconfirmed results will not be repeated.",
            )
          : tr(
              "读取节点已有任务的回执，不重新执行网络命令。",
              "Read receipts for existing node tasks without rerunning network commands.",
            )
      }}
    </p>
    <label class="field confirm-id"
      >{{ tr("输入变更 ID 以确认", "Type the change ID to confirm")
      }}<code>{{ epoch.id }}</code
      ><input
        v-model="confirmation"
        :disabled="mutation.busy.value || !!mutation.pendingKey.value"
        autocomplete="off"
        spellcheck="false" /></label
    ><InlineError
      :error="mutation.error.value"
      :pending-key="mutation.pendingKey.value"
    /><template #footer
      ><UiButton :disabled="mutation.busy.value" @click="open = false">{{
        tr("取消", "Cancel")
      }}</UiButton
      ><UiButton
        variant="primary"
        :busy="mutation.busy.value"
        :disabled="
          confirmation !== epoch.id || !!mutation.pendingKey.value || !allowed
        "
        @click="submit"
        >{{
          mode === "advance"
            ? tr("确认继续", "Confirm continuation")
            : tr("核对回执", "Check receipts")
        }}</UiButton
      ></template
    ></UiOverlay
  >
</template>
<style scoped>
.epoch-controls {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}
.confirm-id {
  margin-top: 24px;
}
.confirm-id code {
  overflow-wrap: anywhere;
  color: var(--secondary);
}
.pending-hint {
  font-size: 13px;
  line-height: 1.7;
  color: var(--warning);
  background: var(--warning-bg);
  padding: 14px;
  border-radius: 6px;
  margin: 16px 0 0;
}
</style>
