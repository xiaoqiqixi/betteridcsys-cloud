<script setup lang="ts">
import { computed, onScopeDispose, shallowRef, watch } from "vue";
import { RouterLink, useRoute } from "vue-router";
import { ApiError, record } from "../api/client";
import {
  canonicalSelection,
  epochDetail,
  matchesEpoch,
  matchesRecovery,
  validSelection,
  type OverlayEpoch,
  type OverlayOptions,
  type OverlaySelection,
  type OverlayVPC,
} from "../api/overlay";
import { useConsole } from "../context";
import { useOverlayMutation } from "../composables/overlay-mutation";
import UiButton from "./UiButton.vue";
import UiOverlay from "./UiOverlay.vue";
import UiSelect from "./UiSelect.vue";
import InlineError from "./InlineError.vue";
import OverlaySelectionEditor from "./OverlaySelectionEditor.vue";
const props = defineProps<{
    cluster: string;
    options: OverlayOptions;
    vpcs: OverlayVPC[];
    recover?: OverlayEpoch;
  }>(),
  emit = defineEmits<{ close: []; saved: [epoch: OverlayEpoch] }>();
const {
    api,
    session,
    notify,
    prefs: { tr },
  } = useConsole(),
  route = useRoute();
const original = props.recover || props.options.latest_epoch;
const source = canonicalSelection(
  original?.snapshot || { members: [], gateways: [], nat_policies: [] },
);
const draft = shallowRef<OverlaySelection>(structuredClone(source)),
  recoveryMode = shallowRef("same"),
  publicConfirmed = shallowRef(false),
  confirmation = shallowRef(""),
  error = shallowRef(""),
  reading = shallowRef(false);
const mutation = useOverlayMutation(
  () => `epoch:${props.cluster}:${original?.epoch || 0}`,
);
let generation = 0;
const initial = JSON.stringify(draft.value);
const allowed = computed(
  () =>
    session.can("nodes.manage") &&
    session.can("instances.manage") &&
    (!props.recover ||
      !props.options.profile_migration_required ||
      props.options.profile_migration_approved),
);
const blocked = computed(
  () =>
    mutation.busy.value ||
    !!mutation.pendingKey.value ||
    reading.value ||
    !allowed.value,
);
const dirty = computed(
  () => !mutation.pendingKey.value && JSON.stringify(draft.value) !== initial,
);
const replacement = computed(
  () => !props.recover || recoveryMode.value === "replace",
);
const desired = computed(() =>
  replacement.value ? canonicalSelection(draft.value) : source,
);
const publicPolicies = computed(() =>
  (desired.value.nat_policies || []).filter((p) => p.internet_egress_enabled),
);
watch(
  () => JSON.stringify(publicPolicies.value),
  () => (publicConfirmed.value = false),
  { flush: "sync" },
);
function current(ticket: number, identity: number) {
  return (
    ticket === generation && identity === session.epoch.value && allowed.value
  );
}
watch(
  [() => route.fullPath, session.epoch],
  () => {
    generation++;
    emit("close");
  },
  { flush: "sync" },
);
onScopeDispose(() => generation++);
// A reopened unknown intent remains immutable and inspectable. Its whole payload
// was persisted before dispatch, so changing draft controls cannot produce a retry.
const pendingBody = mutation.pending.value?.body;
if (record(pendingBody)) {
  if (props.recover && record(pendingBody.replacement)) {
    recoveryMode.value = "replace";
    draft.value = structuredClone(
      pendingBody.replacement,
    ) as unknown as OverlaySelection;
  } else if (
    !props.recover &&
    Array.isArray(pendingBody.members) &&
    Array.isArray(pendingBody.gateways)
  )
    draft.value = structuredClone(pendingBody) as unknown as OverlaySelection;
}
const expectedConfirmation = computed(() =>
  props.recover ? props.recover.id : props.cluster,
);
function matching(value: unknown, key: string) {
  return props.recover
    ? matchesRecovery(value, key, props.recover, desired.value)
    : matchesEpoch(value, key, {
        cluster_id: props.cluster,
        expected_epoch: original?.epoch || 0,
        ...desired.value,
      });
}
async function save() {
  if (
    blocked.value ||
    confirmation.value !== expectedConfirmation.value ||
    (publicPolicies.value.length > 0 && !publicConfirmed.value)
  )
    return;
  error.value = "";
  if (
    replacement.value &&
    !validSelection(desired.value, props.options, !!props.recover)
  ) {
    error.value = "invalid";
    return;
  }
  const ticket = generation,
    identity = session.epoch.value;
  const body = props.recover
    ? {
        expected_snapshot_sha256: props.recover.snapshot_sha256,
        ...(replacement.value ? { replacement: desired.value } : {}),
      }
    : {
        cluster_id: props.cluster,
        expected_epoch: original?.epoch || 0,
        ...desired.value,
      };
  const path = props.recover
    ? `/overlays/epochs/${props.recover.id}/recover`
    : "/overlays/epochs";
  const result = await mutation.execute(
    path,
    body,
    (v, key): v is { epoch: OverlayEpoch } =>
      record(v) && matching(v.epoch, key),
    () => current(ticket, identity),
    { status: 202 },
  );
  if (!result || !current(ticket, identity)) return;
  notify(
    tr(
      "网络变更已受理，请在变更详情中查看各节点进度。",
      "Network change accepted. Review per-node progress in the change details.",
    ),
  );
  emit("saved", result.epoch);
  emit("close");
}
async function inspect() {
  const key = mutation.pendingKey.value,
    ticket = generation,
    identity = session.epoch.value;
  if (!key || reading.value) return;
  reading.value = true;
  error.value = "";
  try {
    const result = await api.get(
      `/overlays/epochs/${key}`,
      (
        v,
      ): v is {
        epoch: OverlayEpoch;
        tasks: import("../api/overlay").OverlayTask[];
      } => epochDetail(v) && matching(v.epoch, key),
    );
    if (
      !current(ticket, identity) ||
      !mutation.acknowledge(key, () => current(ticket, identity))
    )
      return;
    notify(
      tr(
        "已核对原变更，无需重新提交。",
        "Original change confirmed. Do not submit it again.",
      ),
    );
    emit("saved", result.epoch);
    emit("close");
  } catch (cause) {
    if (current(ticket, identity)) {
      error.value = cause instanceof ApiError ? cause.kind : "network";
      if (cause instanceof ApiError && cause.kind === "unauthorized")
        session.invalidate();
    }
  } finally {
    if (ticket === generation) reading.value = false;
  }
}
</script>
<template>
  <UiOverlay
    :open="true"
    :title="
      recover
        ? tr('恢复网络', 'Recover network')
        : tr('配置 VPC 网络', 'Configure VPC networking')
    "
    :busy="mutation.busy.value || reading"
    :dirty="dirty"
    :close-label="tr('关闭', 'Close')"
    :discard-label="tr('放弃更改', 'Discard changes')"
    :continue-label="tr('继续编辑', 'Keep editing')"
    @close="emit('close')"
  >
    <div class="change-summary">
      <strong>{{ cluster }}</strong
      ><span
        >{{ tr("基于版本", "Based on version") }}
        {{ original?.epoch || 0 }}</span
      >
    </div>
    <p class="secondary">
      {{
        recover
          ? tr(
              "恢复将创建新的网络版本，先隔离相关实例，再重新应用配置。原操作与回执保留，不会把未知结果改成成功。",
              "Recovery creates a new network version, fences affected instances and reapplies configuration. Original operations and receipts remain unchanged.",
            )
          : tr(
              "本次提交包含完整成员、路由和 NAT 配置。所有节点准备并确认后才会放行网络，期间可能短暂中断。",
              "This change contains the complete member, route and NAT selection. Traffic is released only after every node confirms preparation and configuration; a brief interruption is possible.",
            )
      }}
    </p>
    <label v-if="recover" class="field recovery-mode"
      >{{ tr("恢复方式", "Recovery mode")
      }}<UiSelect
        v-model="recoveryMode"
        :disabled="blocked"
        :options="[
          {
            value: 'same',
            label: tr('按原配置恢复', 'Restore original configuration'),
          },
          {
            value: 'replace',
            label: tr('修正配置后恢复', 'Correct configuration and recover'),
          },
        ]"
        :label="tr('恢复方式', 'Recovery mode')"
    /></label>
    <OverlaySelectionEditor
      v-if="replacement"
      v-model="draft"
      :options="options"
      :recovering="!!recover"
      :vpcs="vpcs"
      :disabled="blocked"
    />
    <dl v-else class="recovery-summary">
      <div>
        <dt>{{ tr("保留实例", "Preserved members") }}</dt>
        <dd>{{ source.members.length }}</dd>
      </div>
      <div>
        <dt>{{ tr("路由网关", "Routing gateways") }}</dt>
        <dd>{{ source.gateways.length }}</dd>
      </div>
      <div>
        <dt>{{ tr("NAT 策略", "NAT policies") }}</dt>
        <dd>{{ source.nat_policies?.length || 0 }}</dd>
      </div>
      <div
        v-for="policy in source.nat_policies || []"
        :key="policy.id"
        class="recovery-policy"
      >
        <dt>{{ policy.profile_id }} · {{ tr("出口范围", "Egress scope") }}</dt>
        <dd>
          {{
            policy.internet_egress_enabled
              ? tr("公网 IPv4", "Public IPv4 Internet")
              : tr("仅指定网段", "Selected prefixes only")
          }}
        </dd>
      </div>
    </dl>
    <form id="overlay-change-form" @submit.prevent="save">
      <label v-if="publicPolicies.length" class="public-consent">
        <input v-model="publicConfirmed" type="checkbox" :disabled="blocked" />
        <span
          ><strong>{{
            tr(
              "允许所选 VPC 访问公网 IPv4",
              "Allow the selected VPCs to access the IPv4 Internet",
            )
          }}</strong>
          <span>{{
            tr(
              "实例将共用所选出口地址访问公网。请确认出口容量与使用范围；私有网段、管理地址及端口映射限制仍然保留。",
              "Instances will share the selected egress address for Internet access. Confirm the egress capacity and intended scope. Private networks, management addresses and port-mapping restrictions remain protected.",
            )
          }}</span>
        </span>
      </label>
      <label class="field confirmation"
        ><span>{{
          recover
            ? tr(
                "输入原变更 ID 以确认恢复",
                "Type the original change ID to confirm recovery",
              )
            : tr(
                "输入集群名称以确认应用",
                "Type the cluster name to confirm application",
              )
        }}</span
        ><code>{{ expectedConfirmation }}</code
        ><input
          v-model="confirmation"
          :disabled="blocked"
          autocomplete="off"
          spellcheck="false"
      /></label>
    </form>
    <InlineError
      :error="error || mutation.error.value"
      :pending-key="mutation.pendingKey.value"
    />
    <div v-if="mutation.pendingKey.value" class="pending-actions">
      <UiButton :busy="reading" @click="inspect">{{
        tr("只读核对原变更", "Read original change")
      }}</UiButton
      ><RouterLink
        :replace="true"
        :to="`/networks/epochs/${mutation.pendingKey.value}`"
        >{{ tr("查看原变更", "View original change") }}</RouterLink
      >
    </div>
    <template #footer="{ close }"
      ><UiButton :disabled="mutation.busy.value || reading" @click="close">{{
        tr("取消", "Cancel")
      }}</UiButton
      ><UiButton
        variant="primary"
        form="overlay-change-form"
        type="submit"
        :busy="mutation.busy.value"
        :disabled="
          blocked ||
          confirmation !== expectedConfirmation ||
          (publicPolicies.length > 0 && !publicConfirmed)
        "
        >{{
          recover
            ? tr("提交恢复", "Submit recovery")
            : tr("应用网络配置", "Apply configuration")
        }}</UiButton
      ></template
    >
  </UiOverlay>
</template>
<style scoped>
.change-summary {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  padding: 14px 16px;
  border-radius: 6px;
  background: var(--subtle);
  font-size: 13px;
  overflow-wrap: anywhere;
}
.change-summary span {
  color: var(--secondary);
}
.recovery-mode {
  margin: 24px 0;
}
.confirmation {
  padding-top: 24px;
  margin-top: 24px;
  border-top: 1px solid var(--border);
}
.public-consent {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 16px;
  margin-top: 24px;
  border: 1px solid var(--control-border);
  border-radius: 6px;
  background: var(--subtle);
  cursor: pointer;
  min-height: 44px;
}
.public-consent input {
  appearance: none;
  width: 18px;
  height: 18px;
  flex-shrink: 0;
  margin: 2px 0 0;
  padding: 0;
  display: grid;
  place-content: center;
  background: var(--surface);
  border: 1px solid var(--control-border);
  border-radius: 4px;
  cursor: pointer;
}
.public-consent input::before {
  content: "";
  width: 9px;
  height: 5px;
  border-left: 2px solid var(--on-accent);
  border-bottom: 2px solid var(--on-accent);
  transform: translateY(-1px) rotate(-45deg);
  opacity: 0;
}
.public-consent input:checked {
  background: var(--accent);
  border-color: var(--accent);
}
.public-consent input:checked::before {
  opacity: 1;
}
.public-consent > span {
  display: grid;
  gap: 8px;
  min-width: 0;
  font-size: 13px;
  line-height: 1.7;
}
.public-consent strong {
  font-weight: 600;
}
.public-consent > span > span {
  color: var(--secondary);
}
.confirmation code {
  color: var(--secondary);
  overflow-wrap: anywhere;
}
.recovery-summary {
  display: grid;
  gap: 14px;
  padding: 20px;
  background: var(--subtle);
  border-radius: 6px;
}
.recovery-summary > div {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  font-size: 14px;
}
.recovery-summary dt,
.recovery-summary dd {
  min-width: 0;
  overflow-wrap: anywhere;
}
.recovery-summary dt {
  color: var(--secondary);
}
.recovery-summary dd {
  margin: 0;
}
.recovery-policy > dd {
  flex-shrink: 0;
  white-space: nowrap;
}
.pending-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 16px;
}
.pending-actions a {
  font-size: 14px;
  min-height: 44px;
  display: inline-flex;
  align-items: center;
}
@media (max-width: 600px) {
  .recovery-summary > .recovery-policy {
    flex-direction: column;
    align-items: flex-start;
    gap: 8px;
  }
}
</style>
