<script setup lang="ts">
import { computed, shallowRef, watch } from "vue";
import { RouterLink } from "vue-router";
import { RefreshCw } from "@lucide/vue";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { usePublicIngressMutation } from "../composables/public-ingress-mutation";
import {
  publicIngressPolicyResponse,
  type PublicIngressPolicy,
  type PublicIngressRequest,
} from "../api/public-ingress";
import type { Instance } from "../api/types";
import UiButton from "./UiButton.vue";
import StateBlock from "./StateBlock.vue";
import InlineError from "./InlineError.vue";
import PublicIngressDialog from "./PublicIngressDialog.vue";
const props = defineProps<{ instance: Instance }>();
const emit = defineEmits<{ changed: [] }>();
const {
  session,
  prefs: { tr },
  notify,
} = useConsole();
const query = useQuery(
  () => `/instances/${props.instance.id}/public-ingress`,
  (v): v is { policy: PublicIngressPolicy } =>
    publicIngressPolicyResponse(v) &&
    v.policy.instance_id === props.instance.id &&
    v.policy.owner_ref === props.instance.owner_ref,
);
const mutation = usePublicIngressMutation(),
  editing = shallowRef<PublicIngressPolicy | null>(null),
  accepted = shallowRef<PublicIngressPolicy | null>(null);
const policy = computed(() => query.data.value?.policy);
const canManage = computed(
  () =>
    session.can("nodes.read") &&
    session.can("nodes.manage") &&
    session.can("instances.manage"),
);
const canEdit = computed(
  () =>
    !!policy.value &&
    policy.value.supported &&
    policy.value.revision < Number.MAX_SAFE_INTEGER &&
    ["default", "active"].includes(policy.value.state) &&
    canManage.value &&
    !mutation.busy.value &&
    !mutation.pending.value,
);
const label = computed(() =>
  policy.value?.legacy_unrestricted
    ? tr("旧绑定尚未应用入站规则", "Legacy binding without ingress rules")
    : policy.value?.state === "pending"
      ? tr("规则变更待执行", "Policy change awaiting execution")
      : policy.value?.state === "blocked"
        ? tr("规则变更待核实", "Policy change needs verification")
        : !policy.value?.rules.length
          ? tr("默认拒绝公网新入站", "New public ingress denied by default")
          : tr("已保存允许规则", "Allow rules saved"),
);
const taskPolicy = computed(() =>
  policy.value?.epoch_id
    ? policy.value
    : accepted.value?.epoch_id
      ? accepted.value
      : null,
);
function edit() {
  if (canEdit.value && policy.value) {
    mutation.clearMessage();
    editing.value = {
      ...policy.value,
      rules: policy.value.rules.map((r) => ({ ...r })),
    };
  }
}
watch(
  () => props.instance.id,
  () => {
    editing.value = null;
    accepted.value = null;
  },
);
async function submit(request: PublicIngressRequest) {
  if (
    !editing.value ||
    editing.value.instance_id !== props.instance.id ||
    editing.value.owner_ref !== props.instance.owner_ref ||
    !canManage.value
  )
    return;
  const op = await mutation.execute(props.instance.id, request);
  emit("changed");
  if (op) {
    accepted.value = op.result.policy;
    editing.value = null;
    notify(
      tr(
        op.result.policy.state === "pending"
          ? "规则变更已记录，请完成关联网络任务。"
          : "入站规则已保存。",
        op.result.policy.state === "pending"
          ? "Policy change recorded. Complete its linked network task."
          : "Ingress rules saved.",
      ),
    );
    await query.reload();
  } else if (mutation.error.value === "conflict") {
    // Refresh by GET, but keep the stale editor frozen and disabled. Opening a
    // new draft after closing uses this fresh policy, never a silent rebase.
    await query.reload();
  }
}
async function reconcile() {
  const op = await mutation.reconcile();
  emit("changed");
  if (op) {
    accepted.value = op.result.policy;
    editing.value = null;
    notify(
      tr(
        "原规则操作已核实，请查看当前生效状态。",
        "Original policy operation verified. Review its current effective state.",
      ),
    );
    await query.reload();
  }
}
const ports = (r: PublicIngressPolicy["rules"][number]) =>
  r.protocol === "icmp"
    ? tr("ICMP 回显", "ICMP echo")
    : `${r.protocol.toUpperCase()} ${r.port_start === r.port_end ? r.port_start : `${r.port_start}–${r.port_end}`}`;
</script>
<template>
  <section
    class="public-ingress-panel"
    :data-instance-id="instance.id"
    :aria-label="tr('实例公网入站规则', 'Instance public ingress rules')"
  >
    <header class="ingress-heading">
      <div>
        <h2>{{ tr("公网入站规则", "Public ingress rules") }}</h2>
        <p>
          {{
            tr(
              "地址绑定与访问授权分开管理。规则属于本实例，不会随浮动 IP 转移。",
              "Manage address binding separately from access permissions. These rules belong to this instance and do not move with a floating IP.",
            )
          }}
        </p>
      </div>
      <UiButton :busy="query.loading.value" @click="query.reload"
        ><RefreshCw :size="16" aria-hidden="true" />{{
          tr("刷新入站规则", "Refresh ingress rules")
        }}</UiButton
      >
    </header>
    <InlineError
      :error="mutation.error.value"
      :pending-key="mutation.pending.value?.key"
    />
    <UiButton
      v-if="mutation.pending.value"
      :busy="mutation.busy.value"
      @click="reconcile"
      >{{ tr("核对原规则操作", "Verify original policy operation") }}</UiButton
    >
    <StateBlock
      :loading="query.loading.value"
      :error="query.error.value"
      @reload="query.reload"
    >
      <template v-if="policy">
        <div class="ingress-policy-state">
          <strong>{{ label }}</strong
          ><span
            >{{ tr("保存版本", "Saved revision") }} {{ policy.revision }} ·
            {{ tr("已确认生效版本", "Confirmed effective revision") }}
            {{
              policy.effective_revision === null
                ? tr("未确认", "Unconfirmed")
                : policy.effective_revision
            }}</span
          >
        </div>
        <p v-if="policy.legacy_unrestricted" class="ingress-warning">
          {{
            tr(
              "旧绑定仍使用原有全端口映射，尚未由平台入站规则限制。保存规则并完成关联网络任务后，规则才会生效。",
              "The legacy binding still uses unrestricted mapping. Save the rules and complete their linked network task to apply them.",
            )
          }}
        </p>
        <p v-if="!policy.supported" class="ingress-warning">
          {{
            policy.unsupported_reason === "UPGRADE_REQUIRED"
              ? tr(
                  "当前节点版本不支持公网入站规则，请先升级相关节点。",
                  "The current node versions do not support public ingress rules. Upgrade the participating nodes first.",
                )
              : tr(
                  "当前网络尚未就绪。请核对相关节点的在线和心跳状态，以及当前网络配置与批准设置。",
                  "Public ingress is not ready. Check participating nodes’ online status and heartbeats, and the current network configuration and approvals.",
                )
          }}
        </p>
        <p
          v-if="['pending', 'blocked'].includes(policy.state)"
          class="ingress-note"
        >
          {{
            tr(
              "下列是已记录的目标规则，不代表已生效。请先执行或核对原网络任务，结果未知时不要重复提交。",
              "The rules below are the recorded desired policy, not proof that it is active. Execute or verify its original network task; do not resubmit an unknown change.",
            )
          }}
        </p>
        <p v-if="!policy.rules.length" class="ingress-empty">
          {{
            tr(
              "没有允许规则。此版本生效后，仅保留实例主动发起连接的正常回包，不接受公网新入站连接。",
              "No allow rules. Once this revision is effective, legitimate replies to connections initiated by the instance still pass, while new public inbound connections are denied.",
            )
          }}
        </p>
        <div v-else class="ingress-rule-list">
          <div v-for="r in policy.rules" :key="r.id" class="ingress-rule">
            <strong>{{ ports(r) }}</strong
            ><span
              >{{ tr("允许来源", "Allowed source") }} {{ r.source_cidr }}</span
            >
          </div>
        </div>
        <div class="ingress-actions">
          <UiButton v-if="canManage" :disabled="!canEdit" @click="edit">{{
            tr("编辑入站规则", "Edit ingress rules")
          }}</UiButton
          ><RouterLink
            v-if="taskPolicy?.epoch_id"
            :to="`/networks/epochs/${taskPolicy.epoch_id}`"
            >{{
              tr("查看规则网络任务", "View policy network task")
            }}</RouterLink
          >
        </div>
        <p class="ingress-scope">
          {{
            tr(
              "当前只限制 VPC 浮动 IP 的公网入站；不修改内网规则，也不替代实例防火墙或完整安全组。",
              "This currently restricts public ingress through VPC floating IPs only. It does not change private-network rules or replace the guest firewall or a complete security group.",
            )
          }}
        </p>
      </template>
    </StateBlock>
    <PublicIngressDialog
      v-if="editing"
      :policy="editing"
      :busy="mutation.busy.value"
      :pending="!!mutation.pending.value"
      :error="mutation.error.value"
      @close="editing = null"
      @submit="submit"
      @reconcile="reconcile"
    />
  </section>
</template>
<style scoped>
.public-ingress-panel {
  margin: 0 0 28px;
  padding: 20px 0;
  background: var(--surface);
  border: 0;
  border-radius: 0;
  min-width: 0;
  border-block: 1px solid var(--border);
}
.ingress-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 20px;
  margin-bottom: 18px;
}
.ingress-heading h2 {
  font-size: 17px;
  margin: 0 0 8px;
  line-height: 1.5;
}
.ingress-heading p,
.ingress-note,
.ingress-empty,
.ingress-scope,
.ingress-warning {
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
  margin: 0 0 16px;
}
.ingress-warning {
  color: var(--danger);
}
.ingress-policy-state {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 16px;
  font-size: 14px;
  line-height: 1.6;
}
.ingress-policy-state span {
  font-size: 13px;
  color: var(--secondary);
}
.ingress-rule-list {
  display: grid;
  gap: 0;
  margin-bottom: 20px;
}
.ingress-rule {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  border-bottom: 1px solid var(--border);
  padding: 12px 0;
  font-size: 14px;
  line-height: 1.6;
  overflow-wrap: anywhere;
}
.ingress-rule span {
  color: var(--secondary);
}
.ingress-actions {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
  margin: 20px 0;
}
.ingress-actions a {
  font-size: 13px;
  min-height: 44px;
  display: inline-flex;
  align-items: center;
}
.ingress-scope {
  margin-bottom: 0;
}
@media (max-width: 600px) {
  .public-ingress-panel {
    padding: 16px;
  }
  .ingress-heading {
    flex-direction: column;
    gap: 14px;
  }
  .ingress-rule {
    align-items: flex-start;
    flex-direction: column;
    gap: 4px;
  }
}
@media (max-width: 600px) {
  .public-ingress-panel {
    padding: 18px 0;
  }
}
</style>
