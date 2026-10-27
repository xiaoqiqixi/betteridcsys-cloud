<script setup lang="ts">
import { computed, watch } from "vue";
import { RouterLink } from "vue-router";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import {
  publicIngressPolicyResponse,
  type PublicIngressPolicy,
} from "../api/public-ingress";
import StateBlock from "./StateBlock.vue";
const props = defineProps<{ instanceId: string; ownerRef: string }>();
const emit = defineEmits<{ ready: [policy: PublicIngressPolicy | null] }>();
const {
  prefs: { tr },
} = useConsole();
const query = useQuery(
  () => `/instances/${props.instanceId}/public-ingress`,
  (v): v is { policy: PublicIngressPolicy } =>
    publicIngressPolicyResponse(v) &&
    v.policy.instance_id === props.instanceId &&
    v.policy.owner_ref === props.ownerRef,
);
const policy = computed(() => query.data.value?.policy);
watch(
  [query.data, query.loading, query.error],
  () => {
    const p = query.data.value?.policy;
    emit(
      "ready",
      !query.loading.value &&
        !query.error.value &&
        p &&
        p.supported &&
        ["default", "active"].includes(p.state)
        ? { ...p, rules: p.rules.map((r) => ({ ...r })) }
        : null,
    );
  },
  { immediate: true },
);
const ports = (r: PublicIngressPolicy["rules"][number]) =>
  r.protocol === "icmp"
    ? tr("ICMP 回显", "ICMP echo")
    : `${r.protocol.toUpperCase()} ${r.port_start === r.port_end ? r.port_start : `${r.port_start}–${r.port_end}`}`;
</script>
<template>
  <section
    class="binding-ingress"
    :aria-label="
      tr('所选实例的公网入站规则', 'Selected instance public ingress rules')
    "
  >
    <h3>{{ tr("公网入站规则", "Public ingress rules") }}</h3>
    <StateBlock
      :loading="query.loading.value"
      :error="query.error.value"
      @reload="query.reload"
    >
      <template v-if="policy">
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
          v-else-if="['pending', 'blocked'].includes(policy.state)"
          class="ingress-warning"
        >
          {{
            tr(
              "该实例的规则变更尚未确认。请先完成或核对原任务，再绑定公网 IP。",
              "This instance has an unconfirmed policy change. Complete or verify its original task before binding a public IP.",
            )
          }}
        </p>
        <p v-else-if="policy.legacy_unrestricted" class="ingress-warning">
          {{
            tr(
              "现有旧绑定尚未由平台入站规则限制。本次绑定将使用下列目标版本；只有关联网络任务完成后才确认生效。",
              "The legacy binding is not yet restricted by platform ingress rules. This binding will use the target revision below, confirmed only after its linked network task completes.",
            )
          }}
        </p>
        <p v-if="!policy.rules.length">
          {{
            tr(
              "尚无允许规则。绑定后默认拒绝公网新入站连接，实例主动发起连接的正常回包仍可通过。",
              "No allow rules are configured. New public inbound connections are denied after binding; legitimate replies to connections initiated by the instance still pass.",
            )
          }}
        </p>
        <ul v-else class="binding-rule-list">
          <li v-for="r in policy.rules" :key="r.id">
            <strong>{{ ports(r) }}</strong
            ><span>{{ tr("来源", "Source") }} {{ r.source_cidr }}</span>
          </li>
        </ul>
        <p class="binding-policy-version">
          {{ tr("规则版本", "Policy revision") }} {{ policy.revision }} ·
          {{
            tr(
              "规则属于所选实例，不会随公网 IP 从原实例搬来。",
              "Rules belong to the selected instance, not to the public IP or its previous target.",
            )
          }}
        </p>
        <RouterLink :to="`/instances/${instanceId}?tab=public`">{{
          tr(
            "管理该实例的公网入站规则",
            "Manage this instance’s public ingress rules",
          )
        }}</RouterLink>
      </template>
    </StateBlock>
  </section>
</template>
<style scoped>
.binding-ingress {
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--surface-raised);
  min-width: 0;
}
.binding-ingress h3 {
  font-size: 14px;
  margin: 0 0 10px;
  line-height: 1.5;
}
.binding-ingress p {
  font-size: 13px;
  line-height: 1.7;
  margin: 0 0 10px;
  color: var(--secondary);
}
.binding-rule-list {
  list-style: none;
  padding: 0;
  margin: 0 0 12px;
  display: grid;
  gap: 10px;
  max-height: 200px;
  overflow: auto;
}
.binding-rule-list li {
  display: flex;
  gap: 12px;
  justify-content: space-between;
  flex-wrap: wrap;
  font-size: 13px;
  line-height: 1.6;
  overflow-wrap: anywhere;
}
.binding-rule-list li span {
  color: var(--secondary);
}
.binding-ingress a {
  font-size: 13px;
  display: inline-flex;
  align-items: center;
  min-height: 44px;
  line-height: 1.6;
}
.binding-ingress .ingress-warning {
  color: var(--danger);
}
@media (max-width: 600px) {
  .binding-rule-list li {
    flex-direction: column;
    gap: 2px;
  }
}
</style>
