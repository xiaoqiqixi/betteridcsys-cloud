<script setup lang="ts">
import { computed } from "vue";
import { Plus, Trash2 } from "@lucide/vue";
import { key32 } from "../api/client";
import { publicIPv4 } from "../api/overlay";
import type {
  NATForwarding,
  NATPolicy,
  NATProfile,
  OverlayGateway,
  OverlayInstanceOption,
  OverlayMemberInput,
  OverlayVPC,
} from "../api/overlay";
import { useConsole } from "../context";
import UiButton from "./UiButton.vue";
import UiSelect from "./UiSelect.vue";
import type { PublicIPLease } from "../api/public-ip";
const props = defineProps<{
  modelValue: NATPolicy[];
  profiles: NATProfile[];
  members: OverlayMemberInput[];
  instances: OverlayInstanceOption[];
  gateways: OverlayGateway[];
  vpcs: OverlayVPC[];
  leases?: PublicIPLease[];
  disabled?: boolean;
}>();
const emit = defineEmits<{ "update:modelValue": [value: NATPolicy[]] }>();
const {
  prefs: { tr },
} = useConsole();
const profileKey = (p: NATProfile) =>
  `${p.node_id}:${p.profile_id}:${p.vpc_id}`;
const policyFor = (p: NATProfile) =>
  props.modelValue.find(
    (v) =>
      v.node_id === p.node_id &&
      v.profile_id === p.profile_id &&
      v.vpc_id === p.vpc_id,
  );
const gatewayPresent = (p: NATProfile) =>
  props.gateways.some(
    (g) =>
      g.node_id === p.node_id &&
      g.instance_id === p.gateway_instance_id &&
      g.vpc_id === p.vpc_id,
  );
const targets = (p: NATProfile) =>
  props.members
    .filter((m) => m.vpc_id === p.vpc_id && m.enabled)
    .map((m) => ({
      value: m.instance_id,
      label:
        props.instances.find((i) => i.instance_id === m.instance_id)
          ?.hostname || m.instance_id,
    }));
const name = (id: string) => props.vpcs.find((v) => v.id === id)?.name || id;
const leasesFor = (p: NATProfile) =>
  (props.leases || []).filter(
    (l) =>
      l.state === "reserved" &&
      props.gateways.some(
        (g) =>
          g.vpc_id === p.vpc_id &&
          g.node_id === p.node_id &&
          g.owner_ref === l.owner_ref,
      ) &&
      l.vpc_id === p.vpc_id &&
      l.node_id === p.node_id &&
      l.profile_id === p.profile_id &&
      (l.address === p.public_ipv4 || p.public_ipv4s?.includes(l.address)),
  );
const primaryLeased = (p: NATProfile) =>
  (props.leases || []).some(
    (l) => l.state === "reserved" && l.address === p.public_ipv4,
  );
const publicAddressOptions = (p: NATProfile) => {
  const old = policyFor(p)?.public_ipv4;
  const leases = leasesFor(p);
  return [
    {
      value: "",
      label: tr(
        `原出口 · ${p.public_ipv4}`,
        `Original egress · ${p.public_ipv4}`,
      ),
      disabled: primaryLeased(p),
    },
    ...leases.map((l) => ({ value: l.address, label: l.address })),
    ...(old && !leases.some((l) => l.address === old)
      ? [
          {
            value: old,
            label: tr(`${old} · 分配待核对`, `${old} · verify allocation`),
            disabled: true,
          },
        ]
      : []),
  ];
};
function selectPublicAddress(p: NATProfile, value: string) {
  const old = policyFor(p);
  if (
    !old ||
    props.disabled ||
    (value ? !leasesFor(p).some((l) => l.address === value) : primaryLeased(p))
  )
    return;
  const next = { ...old };
  if (value) next.public_ipv4 = value;
  else delete next.public_ipv4;
  publish(next, old);
}
function publish(p: NATPolicy | null, old?: NATPolicy) {
  if (props.disabled) return;
  const next = props.modelValue.filter(
    (v) => v !== old && (!p || v.vpc_id !== p.vpc_id),
  );
  if (p) next.push(p);
  emit("update:modelValue", next);
}
function toggle(p: NATProfile) {
  const old = policyFor(p);
  if (old) {
    publish(null, old);
    return;
  }
  if (!gatewayPresent(p)) return;
  publish({
    id: key32(),
    node_id: p.node_id,
    vpc_id: p.vpc_id,
    gateway_instance_id: p.gateway_instance_id,
    profile_id: p.profile_id,
    profile_sha256: p.profile_sha256,
    snat_enabled: false,
    forwardings: [],
  });
}
function snat(p: NATProfile, value: string) {
  const old = policyFor(p);
  if (!old || (value === "true" && !p.allow_snat)) return;
  const next = { ...old, snat_enabled: value === "true" };
  if (!next.snat_enabled) delete next.internet_egress_enabled;
  publish(next, old);
}
const internetAvailable = (p: NATProfile) =>
  p.allow_snat && p.allow_internet_egress === true && publicIPv4(p.public_ipv4);
function egress(p: NATProfile, value: string) {
  const old = policyFor(p);
  if (
    !old ||
    (value === "internet" && (!old.snat_enabled || !internetAvailable(p)))
  )
    return;
  const next = { ...old };
  if (value === "internet") next.internet_egress_enabled = true;
  else delete next.internet_egress_enabled;
  publish(next, old);
}
function internetReason(p: NATProfile) {
  if (!p.allow_internet_egress)
    return tr(
      "节点尚未开放此出口的公网访问，请先由运维人员配置出口权限。",
      "Internet access is not enabled for this egress profile. Ask an operator to configure its permission first.",
    );
  if (!publicIPv4(p.public_ipv4))
    return tr(
      "此出口没有可用的公网 IPv4 地址，请先核对节点出口配置。",
      "This egress profile has no usable public IPv4 address. Review the node egress configuration first.",
    );
  if (!p.allow_snat)
    return tr(
      "此出口未开放出站地址转换，暂不可用于公网访问。",
      "Outbound translation is not permitted for this egress profile, so Internet access is unavailable.",
    );
  if (!policyFor(p)?.snat_enabled)
    return tr(
      "先开启出站地址转换，再选择公网出口。",
      "Enable outbound translation before selecting Internet access.",
    );
  return "";
}
function nextPort(p: NATProfile) {
  const old = policyFor(p);
  for (const range of p.allowed_ports) {
    for (let port = range.start; port <= range.end; port++) {
      if (
        !old?.forwardings.some(
          (f) => f.protocol === range.protocol && f.public_port === port,
        )
      )
        return { protocol: range.protocol, port };
    }
  }
  return null;
}
function add(p: NATProfile) {
  const old = policyFor(p),
    next = nextPort(p);
  if (!old || !next || !targets(p).length || old.forwardings.length >= 128)
    return;
  publish(
    {
      ...old,
      forwardings: [
        ...old.forwardings,
        {
          id: key32(),
          protocol: next.protocol,
          public_port: next.port,
          target_instance_id: targets(p)[0]!.value,
          target_port: next.port,
          source_cidr: p.allowed_source_cidrs[0] || "",
        },
      ],
    },
    old,
  );
}

function change(p: NATProfile, id: string, patch: Partial<NATForwarding>) {
  const old = policyFor(p);
  if (!old) return;
  publish(
    {
      ...old,
      forwardings: old.forwardings.map((f) =>
        f.id === id ? { ...f, ...patch } : f,
      ),
    },
    old,
  );
}
function remove(p: NATProfile, id: string) {
  const old = policyFor(p);
  if (old)
    publish(
      { ...old, forwardings: old.forwardings.filter((f) => f.id !== id) },
      old,
    );
}
const missing = computed(() =>
  props.modelValue.filter(
    (p) =>
      !props.profiles.some(
        (v) =>
          v.node_id === p.node_id &&
          v.profile_id === p.profile_id &&
          v.vpc_id === p.vpc_id &&
          v.profile_sha256 === p.profile_sha256,
      ),
  ),
);
</script>
<template>
  <section class="nat-editor">
    <header>
      <h3>{{ tr("NAT 与端口转发", "NAT & port forwarding") }}</h3>
      <p>
        {{
          tr(
            "选择出口与访问范围。端口映射仍受来源和端口限制，管理网络始终受保护。",
            "Choose an egress profile and access scope. Port mappings retain their source and port restrictions; management networks remain protected.",
          )
        }}
      </p>
    </header>
    <p v-if="!profiles.length" class="nat-empty">
      {{
        tr(
          "尚未配置 NAT 出口。批准节点出口后，可在此开启地址转换和端口转发。",
          "No NAT profiles configured. After an egress profile is approved, configure address translation and forwarding here.",
        )
      }}
    </p>
    <article
      v-for="profile in profiles"
      :key="profileKey(profile)"
      class="nat-profile"
      :class="{ 'is-selected': !!policyFor(profile) }"
    >
      <header class="profile-header">
        <div>
          <h4>{{ name(profile.vpc_id) }}</h4>
          <p>
            {{ tr("出口 IPv4", "Egress IPv4") }}
            <code>{{
              policyFor(profile)?.public_ipv4 || profile.public_ipv4
            }}</code>
            · {{ profile.node_id }}
          </p>
        </div>
        <UiButton
          :disabled="
            disabled || (!policyFor(profile) && !gatewayPresent(profile))
          "
          :aria-pressed="!!policyFor(profile)"
          @click="toggle(profile)"
          >{{
            policyFor(profile)
              ? tr("移除 NAT", "Remove NAT")
              : tr("配置 NAT", "Configure NAT")
          }}</UiButton
        >
      </header>
      <p v-if="!gatewayPresent(profile)" class="field-note">
        {{
          tr(
            "请先选择此出口对应的路由网关。",
            "Select the routing gateway for this egress profile first.",
          )
        }}
      </p>
      <template v-if="policyFor(profile)">
        <label class="field public-address-field"
          >{{ tr("公网地址绑定", "Public address binding")
          }}<UiSelect
            :model-value="policyFor(profile)?.public_ipv4 || ''"
            :options="publicAddressOptions(profile)"
            :label="tr('公网地址绑定', 'Public address binding')"
            :disabled="disabled"
            @update:model-value="selectPublicAddress(profile, $event)"
          /><span class="field-note">{{
            tr(
              "地址池中分配给此 VPC 出口的地址可在这里绑定。更换或移除出口会中断已有连接。",
              "Bind an address allocated to this VPC egress. Replacing or removing the egress interrupts existing connections.",
            )
          }}</span></label
        >
        <div class="egress-fields">
          <label class="field"
            >{{ tr("出站地址转换（SNAT）", "Outbound translation (SNAT)")
            }}<UiSelect
              :model-value="String(policyFor(profile)!.snat_enabled)"
              :options="[
                { value: 'false', label: tr('关闭', 'Off') },
                {
                  value: 'true',
                  label: tr('开启', 'On'),
                  disabled: !profile.allow_snat,
                },
              ]"
              :disabled="disabled"
              :label="tr('出站地址转换', 'Outbound translation')"
              @update:model-value="snat(profile, $event)"
            /><span class="field-note">{{
              policyFor(profile)!.snat_enabled
                ? tr(
                    "出站流量使用上方出口 IPv4 地址。",
                    "Outbound traffic uses the egress IPv4 address shown above.",
                  )
                : tr(
                    "关闭时同时停用公网出口，不影响单独配置的端口映射。",
                    "Turning this off also disables Internet egress; independently configured port mappings are retained.",
                  )
            }}</span></label
          >
          <label class="field"
            >{{ tr("出口范围", "Egress scope")
            }}<UiSelect
              :model-value="
                policyFor(profile)!.internet_egress_enabled
                  ? 'internet'
                  : 'prefixes'
              "
              :options="[
                {
                  value: 'prefixes',
                  label: tr('仅指定网段', 'Selected prefixes only'),
                },
                {
                  value: 'internet',
                  label: tr('公网 IPv4', 'Public IPv4 Internet'),
                  disabled:
                    !internetAvailable(profile) ||
                    !policyFor(profile)!.snat_enabled,
                },
              ]"
              :disabled="disabled"
              :label="tr('出口范围', 'Egress scope')"
              @update:model-value="egress(profile, $event)"
            /><span class="field-note">{{
              policyFor(profile)!.internet_egress_enabled
                ? tr(
                    "允许此 VPC 通过出口访问公网 IPv4；私有网段与管理地址不会因此开放。",
                    "Allows this VPC to reach public IPv4 destinations through the egress profile. Private and management addresses remain blocked.",
                  )
                : tr(
                    "仅访问网关中列出的目标网段；列表留空时不开放出站访问。",
                    "Only the gateway destination prefixes are reachable. An empty list grants no outbound access.",
                  )
            }}</span></label
          >
        </div>
        <p v-if="internetReason(profile)" class="egress-unavailable field-note">
          {{ internetReason(profile) }}
        </p>
        <p class="field-note selection-note">
          {{
            tr(
              "这里只保存本次选择，应用网络配置并核对节点回执后才会生效。",
              "These are selections for this change. Apply the configuration and review node receipts before treating them as active.",
            )
          }}
        </p>
        <div
          v-for="(rule, index) in policyFor(profile)!.forwardings"
          :key="rule.id"
          class="forwarding"
        >
          <div class="rule-heading">
            <strong>{{ tr("端口映射", "Port mapping") }} {{ index + 1 }}</strong
            ><UiButton
              variant="quiet"
              :disabled="disabled"
              :aria-label="`${tr('删除端口映射', 'Remove port mapping')} ${index + 1}`"
              @click="remove(profile, rule.id)"
              ><Trash2 :size="16" aria-hidden="true"
            /></UiButton>
          </div>
          <div class="forward-grid">
            <label class="field"
              >{{ tr("协议", "Protocol")
              }}<UiSelect
                :model-value="rule.protocol"
                :options="[
                  { value: 'tcp', label: 'TCP' },
                  { value: 'udp', label: 'UDP' },
                ]"
                :label="tr('协议', 'Protocol')"
                :disabled="disabled"
                @update:model-value="
                  change(profile, rule.id, {
                    protocol: $event as 'tcp' | 'udp',
                  })
                " /></label
            ><label class="field"
              >{{ tr("公开端口", "Public port")
              }}<input
                type="number"
                min="1"
                max="65535"
                :value="rule.public_port"
                :disabled="disabled"
                @input="
                  change(profile, rule.id, {
                    public_port: Number(
                      ($event.target as HTMLInputElement).value,
                    ),
                  })
                " /></label
            ><label class="field target-field"
              >{{ tr("目标实例", "Target instance")
              }}<UiSelect
                :model-value="rule.target_instance_id"
                :options="targets(profile)"
                :label="tr('目标实例', 'Target instance')"
                :disabled="disabled"
                @update:model-value="
                  change(profile, rule.id, { target_instance_id: $event })
                " /></label
            ><label class="field"
              >{{ tr("目标端口", "Target port")
              }}<input
                type="number"
                min="1"
                max="65535"
                :value="rule.target_port"
                :disabled="disabled"
                @input="
                  change(profile, rule.id, {
                    target_port: Number(
                      ($event.target as HTMLInputElement).value,
                    ),
                  })
                " /></label
            ><label class="field source-field"
              >{{ tr("允许访问的来源网段", "Allowed source prefix")
              }}<input
                :value="rule.source_cidr"
                :disabled="disabled"
                autocomplete="off"
                spellcheck="false"
                @input="
                  change(profile, rule.id, {
                    source_cidr: ($event.target as HTMLInputElement).value,
                  })
                "
              /><span class="field-note"
                >{{ tr("批准范围：", "Approved ranges: ")
                }}{{ profile.allowed_source_cidrs.join(", ") }}</span
              ></label
            >
          </div>
        </div>
        <UiButton
          class="add-forwarding"
          :disabled="
            disabled ||
            !targets(profile).length ||
            !profile.allowed_source_cidrs.length ||
            !nextPort(profile) ||
            (policyFor(profile)?.forwardings.length || 0) >= 128
          "
          @click="add(profile)"
          ><Plus :size="16" aria-hidden="true" />{{
            tr("添加端口映射", "Add port mapping")
          }}</UiButton
        >
        <p class="field-note">
          {{ tr("允许端口：", "Allowed ports: ")
          }}{{
            profile.allowed_ports
              .map((p) => `${p.protocol.toUpperCase()} ${p.start}–${p.end}`)
              .join(", ")
          }}
        </p>
      </template>
    </article>
    <p v-for="item in missing" :key="item.id" class="nat-warning" role="alert">
      {{
        tr(
          "现有 NAT 配置的批准范围已变化。请重新核对，不会自动移除原策略。",
          "The approval for an existing NAT policy has changed. Verify it before proceeding; the original policy is not removed automatically.",
        )
      }}<code>{{ item.id }}</code>
    </p>
  </section>
</template>
<style scoped>
.public-address-field {
  margin: 20px 0;
}
.nat-editor > header {
  margin-bottom: 18px;
}
.nat-editor h3 {
  font-size: 17px;
  margin: 0;
}
.nat-editor header p {
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
  margin: 10px 0 0;
}
.nat-empty {
  font-size: 13px;
  line-height: 1.7;
  background: var(--subtle);
  color: var(--secondary);
  padding: 18px;
  border-radius: 6px;
}
.nat-profile {
  border: 0;
  padding: 16px 0;
  border-radius: 0;
  margin-top: 12px;
  min-width: 0;
  border-block: 1px solid var(--border);
}
.nat-profile.is-selected {
  border-color: var(--accent);
}
.profile-header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  margin-bottom: 20px;
}
.profile-header > div {
  min-width: 0;
}
.profile-header h4 {
  margin: 0;
  font-size: 14px;
  overflow-wrap: anywhere;
}
.profile-header p {
  overflow-wrap: anywhere;
}
.forwarding {
  border-top: 1px solid var(--border);
  margin-top: 24px;
  padding-top: 14px;
}
.egress-fields {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.egress-unavailable {
  padding: 12px 14px;
  border-radius: 6px;
  background: var(--subtle);
}
.selection-note {
  margin-top: 16px;
}
.rule-heading {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
  font-size: 14px;
}
.forward-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.source-field {
  grid-column: 1/-1;
}
.add-forwarding {
  margin-top: 20px;
}
.nat-warning {
  padding: 14px;
  line-height: 1.6;
  font-size: 13px;
  background: var(--warning-bg);
  color: var(--warning);
  border-radius: 6px;
}
.nat-warning code {
  display: block;
  overflow-wrap: anywhere;
}
@media (max-width: 600px) {
  .egress-fields {
    grid-template-columns: 1fr;
  }
}
@media (max-width: 420px) {
  .forward-grid {
    grid-template-columns: 1fr;
  }
  .profile-header {
    flex-direction: column;
    align-items: stretch;
  }
  .nat-profile {
    padding: 14px;
  }
}
@media (max-width: 420px) {
  .nat-profile {
    padding: 14px 0;
  }
}
</style>
