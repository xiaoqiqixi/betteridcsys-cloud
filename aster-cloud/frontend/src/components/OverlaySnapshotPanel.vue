<script setup lang="ts">
import { RouterLink } from "vue-router";
import type {
  NATPolicy,
  NATProfile,
  OverlaySnapshot,
  OverlayVPC,
} from "../api/overlay";
import { useConsole } from "../context";
import StatusBadge from "./StatusBadge.vue";
const props = defineProps<{
  snapshot: OverlaySnapshot;
  vpcs?: OverlayVPC[];
  natProfiles?: NATProfile[];
}>();
const {
  prefs: { tr },
} = useConsole();
const name = (id: string) =>
  props.vpcs?.find((v) => v.id === id)?.name ||
  props.snapshot.vpcs.find((v) => v.id === id)?.cidr ||
  id;
const egressIPv4 = (policy: NATPolicy) =>
  policy.public_ipv4 ||
  props.natProfiles?.find(
    (profile) =>
      profile.node_id === policy.node_id &&
      profile.vpc_id === policy.vpc_id &&
      profile.gateway_instance_id === policy.gateway_instance_id &&
      profile.profile_id === policy.profile_id &&
      profile.profile_sha256 === policy.profile_sha256,
  )?.public_ipv4;
</script>
<template>
  <div class="snapshot-panel">
    <section>
      <h2>{{ tr("实例成员", "Instance members") }}</h2>
      <p v-if="!snapshot.members.length" class="empty-line">
        {{
          tr("此版本没有实例成员。", "This version has no instance members.")
        }}
      </p>
      <div v-else class="snapshot-rows">
        <article
          v-for="member in snapshot.members"
          :key="member.instance_id"
          class="snapshot-row"
        >
          <div>
            <RouterLink :to="`/instances/${member.instance_id}`">{{
              member.ipv4
            }}</RouterLink
            ><span>{{ member.node_id }} · {{ name(member.vpc_id) }}</span
            ><code>{{ member.instance_id }}</code
            ><span v-if="member.reserved">{{
              tr("预留成员", "Reserved member")
            }}</span>
          </div>
          <StatusBadge :state="member.enabled ? 'enabled' : 'disabled'" />
        </article>
      </div>
    </section>
    <section>
      <h2>{{ tr("路由", "Routes") }}</h2>
      <p v-if="!snapshot.gateways.length" class="empty-line">
        {{ tr("未设置跨网段路由。", "No inter-subnet routes configured.") }}
      </p>
      <article
        v-for="gateway in snapshot.gateways"
        :key="gateway.vpc_id"
        class="route-row"
      >
        <div>
          <strong>{{ name(gateway.vpc_id) }}</strong
          ><span
            >{{ tr("下一跳", "Next hop") }} {{ gateway.ipv4 }} ·
            {{ gateway.node_id }}</span
          >
        </div>
        <ul class="prefix-list">
          <li v-for="prefix in gateway.allowed_prefixes" :key="prefix">
            {{ prefix }}
          </li>
        </ul>
        <p v-if="!gateway.allowed_prefixes.length" class="field-note">
          {{
            tr(
              "未添加指定网段；公网访问由出口范围单独控制。",
              "No specific destination prefixes. Internet access is controlled separately by the egress scope.",
            )
          }}
        </p>
      </article>
    </section>
    <section>
      <h2>{{ tr("NAT 与端口转发", "NAT & port forwarding") }}</h2>
      <p v-if="!snapshot.nat_policies?.length" class="empty-line">
        {{ tr("此版本未启用 NAT。", "NAT is not enabled in this version.") }}
      </p>
      <article
        v-for="policy in snapshot.nat_policies"
        :key="policy.id"
        class="nat-summary"
      >
        <header>
          <div>
            <strong>{{ name(policy.vpc_id) }}</strong
            ><span>{{ policy.node_id }} · {{ policy.profile_id }}</span>
          </div>
          <StatusBadge
            :state="policy.snat_enabled ? 'enabled' : 'disabled'"
          /><span class="sr-only">SNAT</span>
        </header>
        <p class="field-note">
          {{
            policy.snat_enabled
              ? tr("出站地址转换已选择", "Outbound translation selected")
              : tr("出站地址转换关闭", "Outbound translation off")
          }}
        </p>
        <p class="egress-summary">
          {{
            policy.internet_egress_enabled
              ? tr(
                  "公网 IPv4 出口已选择",
                  "Public IPv4 Internet egress selected",
                )
              : tr(
                  "公网出口关闭 · 仅指定网段",
                  "Internet egress off · selected prefixes only",
                )
          }}
        </p>
        <p v-if="egressIPv4(policy)" class="field-note">
          {{ tr("出口配置 IPv4", "Configured egress IPv4") }}
          <code>{{ egressIPv4(policy) }}</code>
        </p>
        <p v-else-if="policy.internet_egress_enabled" class="field-note">
          {{
            tr(
              "此版本的出口地址暂不可确认，请核对节点出口配置。",
              "The egress address for this version cannot be confirmed. Review the node egress configuration.",
            )
          }}
        </p>
        <div
          v-for="rule in policy.forwardings"
          :key="rule.id"
          class="forward-summary"
        >
          <strong
            >{{ rule.protocol.toUpperCase() }} {{ rule.public_port }} →
            {{ rule.target_port }}</strong
          ><RouterLink :to="`/instances/${rule.target_instance_id}`">{{
            snapshot.members.find(
              (m) => m.instance_id === rule.target_instance_id,
            )?.ipv4 || rule.target_instance_id
          }}</RouterLink
          ><span
            >{{ tr("允许来源", "Allowed source") }} {{ rule.source_cidr }}</span
          >
        </div>
      </article>
    </section>
  </div>
</template>
<style scoped>
.snapshot-panel {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 24px;
}
.snapshot-panel > section {
  min-width: 0;
}
.snapshot-panel > section:first-child {
  grid-column: 1/-1;
}
.snapshot-panel h2 {
  font-size: 17px;
  margin: 0 0 16px;
}
.empty-line {
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
  padding: 16px 0;
  border: 0;
  border-radius: 0;
  margin: 0;
  border-block: 1px solid var(--border);
}
.snapshot-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  padding: 16px 0;
  border-bottom: 1px solid var(--border);
}
.snapshot-row > div {
  display: grid;
  gap: 7px;
  min-width: 0;
}
.snapshot-row a {
  font-size: 14px;
  font-weight: 600;
}
.snapshot-row span,
.snapshot-row code,
.route-row span,
.nat-summary header span {
  font-size: 12px;
  color: var(--secondary);
  overflow-wrap: anywhere;
}
.route-row,
.nat-summary {
  padding: 16px 0;
  border: 0;
  border-radius: 0;
  margin-top: 0;
  border-top: 1px solid var(--border);
}
.route-row > div,
.nat-summary header > div {
  display: grid;
  gap: 8px;
  min-width: 0;
}
.route-row strong,
.nat-summary strong {
  font-size: 14px;
  overflow-wrap: anywhere;
}
.prefix-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  list-style: none;
  padding: 0;
  margin: 16px 0 0;
}
.prefix-list li {
  font-size: 13px;
  background: var(--subtle);
  padding: 5px 8px;
  border-radius: 4px;
  overflow-wrap: anywhere;
}
.nat-summary header {
  display: flex;
  justify-content: space-between;
  gap: 12px;
}
.nat-summary header > .status-badge {
  flex-shrink: 0;
  align-self: flex-start;
  white-space: nowrap;
}
.forward-summary {
  display: grid;
  gap: 8px;
  border-top: 1px solid var(--border);
  padding-top: 14px;
  margin-top: 14px;
  font-size: 13px;
}
.egress-summary {
  font-size: 13px;
  line-height: 1.7;
  font-weight: 500;
  overflow-wrap: anywhere;
}
.forward-summary span {
  font-size: 12px;
  color: var(--secondary);
}
.forward-summary a {
  overflow-wrap: anywhere;
}
@media (max-width: 700px) {
  .snapshot-panel {
    grid-template-columns: 1fr;
  }
  .snapshot-row {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
