<script setup lang="ts">
import { computed } from "vue";
import { Check, Plus, X } from "@lucide/vue";
import { useConsole } from "../context";
import type {
  OverlayGateway,
  OverlayInstanceOption,
  OverlayOptions,
  OverlaySelection,
  OverlayVPC,
} from "../api/overlay";
import UiButton from "./UiButton.vue";
import OverlayNATEditor from "./OverlayNATEditor.vue";
const props = defineProps<{
  modelValue: OverlaySelection;
  options: OverlayOptions;
  vpcs: OverlayVPC[];
  disabled?: boolean;
  recovering?: boolean;
}>();
const emit = defineEmits<{ "update:modelValue": [value: OverlaySelection] }>();
const {
  prefs: { tr },
} = useConsole();
const candidates = computed(() => props.options.instances);
const member = (id: string) =>
  props.modelValue.members.find((m) => m.instance_id === id);
const vpcName = (id: string) => props.vpcs.find((v) => v.id === id)?.name || id;
function editable(option: OverlayInstanceOption) {
  return (
    option.eligible ||
    (props.recovering &&
      !!member(option.instance_id) &&
      ["INSTANCE_STATE_UNCONFIRMED", "INSTANCE_OPERATION_PENDING"].includes(
        option.reason,
      ))
  );
}
function removeDeleted(option: OverlayInstanceOption) {
  if (props.disabled || option.state !== "deleted") return;
  emit("update:modelValue", {
    ...props.modelValue,
    members: props.modelValue.members.filter(
      (m) => m.instance_id !== option.instance_id,
    ),
  });
}
function toggleMember(option: OverlayInstanceOption) {
  if (props.disabled || !editable(option)) return;
  const selected = member(option.instance_id),
    members = [...props.modelValue.members];
  if (selected)
    members.splice(members.indexOf(selected), 1, {
      ...selected,
      enabled: !selected.enabled,
    });
  else
    members.push({
      instance_id: option.instance_id,
      vpc_id: option.vpc_id,
      enabled: true,
      reserved: option.reserved,
    });
  emit("update:modelValue", { ...props.modelValue, members });
}
const gatewayKey = (g: OverlayGateway) =>
  `${g.node_id}:${g.instance_id}:${g.vpc_id}`;
const selectedGateway = (g: OverlayGateway) =>
  props.modelValue.gateways.find((v) => gatewayKey(v) === gatewayKey(g));
function toggleGateway(g: OverlayGateway) {
  if (props.disabled) return;
  const existing = selectedGateway(g),
    gateways = props.modelValue.gateways.filter((v) => v.vpc_id !== g.vpc_id);
  if (!existing) gateways.push(structuredClone(g));
  emit("update:modelValue", { ...props.modelValue, gateways });
}
function prefixes(g: OverlayGateway, value: string) {
  if (props.disabled) return;
  emit("update:modelValue", {
    ...props.modelValue,
    gateways: props.modelValue.gateways.map((v) =>
      gatewayKey(v) === gatewayKey(g)
        ? {
            ...v,
            allowed_prefixes: value.trim()
              ? value.split(/[\n,]+/).map((x) => x.trim())
              : [],
          }
        : v,
    ),
  });
}
const reason = (value: string) =>
  value === "ROOT_MAPPING_REQUIRED"
    ? tr("尚未批准节点网络映射", "Node network mapping is not approved")
    : value === "VPC_REQUIRED"
      ? tr("请先创建对应 VPC", "Create the approved VPC first")
      : tr("当前状态不可变更", "Not eligible in the current state");
</script>
<template>
  <div class="selection-editor">
    <section class="selection-section">
      <header>
        <h3>{{ tr("实例成员", "Instance members") }}</h3>
        <p>
          {{
            tr(
              "启用表示允许接入网络，不会替已关机实例开机。已有成员停用后仍保留身份和地址。",
              "Enabled allows network access; it does not power on stopped instances. Disabled members retain their identity and address.",
            )
          }}
        </p>
      </header>
      <div v-if="!candidates.length" class="editor-empty">
        {{
          tr(
            "暂无可选实例。请先完成节点网络映射与实例地址分配。",
            "No instances available. Configure node network mappings and instance address allocations first.",
          )
        }}
      </div>
      <article
        v-for="item in candidates"
        :key="item.instance_id"
        class="member-choice"
        :class="{ 'is-selected': member(item.instance_id)?.enabled }"
      >
        <div class="member-copy">
          <strong>{{ item.hostname }}</strong
          ><span>{{ item.node_id }} · {{ item.ipv4 }}</span
          ><span>{{
            vpcName(item.vpc_id) || tr("尚未关联 VPC", "VPC not assigned")
          }}</span
          ><small v-if="item.reserved">{{
            tr("已预留，等待创建", "Reserved; awaiting creation")
          }}</small
          ><small v-if="!item.eligible">{{ reason(item.reason) }}</small>
        </div>
        <UiButton
          v-if="item.state === 'deleted' && member(item.instance_id)"
          :disabled="disabled"
          @click="removeDeleted(item)"
          >{{ tr("移除已删除成员", "Remove deleted member") }}</UiButton
        >
        <UiButton
          v-else
          :disabled="disabled || !editable(item)"
          :aria-pressed="!!member(item.instance_id)?.enabled"
          :aria-label="`${member(item.instance_id)?.enabled ? tr('停用', 'Disable') : tr('启用', 'Enable')} ${item.hostname}`"
          @click="toggleMember(item)"
          ><Check
            v-if="member(item.instance_id)?.enabled"
            :size="15"
            aria-hidden="true"
          /><Plus v-else :size="15" aria-hidden="true" />{{
            member(item.instance_id)?.enabled
              ? tr("已启用", "Enabled")
              : tr("启用", "Enable")
          }}</UiButton
        >
      </article>
      <div
        v-for="missing in modelValue.members.filter(
          (m) => !candidates.some((i) => i.instance_id === m.instance_id),
        )"
        :key="missing.instance_id"
        class="missing-member"
        role="alert"
      >
        {{
          tr(
            "现有成员缺少可用配置，请刷新核对，不会自动移除。",
            "An existing member has no available configuration. Reload to verify; it will not be removed automatically.",
          )
        }}<code>{{ missing.instance_id }}</code>
      </div>
    </section>
    <section class="selection-section">
      <header>
        <h3>{{ tr("路由网关", "Routing gateways") }}</h3>
        <p>
          {{
            tr(
              "每个 VPC 使用一个网关，在此配置指定网段。公网访问范围在下方 NAT 出口中单独设置。",
              "Choose one gateway per VPC and configure specific destination prefixes here. Internet access is configured separately in the NAT egress section below.",
            )
          }}
        </p>
      </header>
      <div v-if="!options.gateways.length" class="editor-empty">
        {{
          tr(
            "暂未配置路由网关。请先在节点配置中批准网关与可达网段。",
            "No routing gateways configured. Approve gateway identities and reachable prefixes in the node configuration first.",
          )
        }}
      </div>
      <article
        v-for="gateway in options.gateways"
        :key="gatewayKey(gateway)"
        class="gateway-choice"
        :class="{ 'is-selected': !!selectedGateway(gateway) }"
      >
        <div class="choice-heading">
          <div>
            <strong>{{ vpcName(gateway.vpc_id) }}</strong>
            <p>{{ gateway.ipv4 }} · {{ gateway.node_id }}</p>
          </div>
          <UiButton
            :disabled="disabled"
            :aria-pressed="!!selectedGateway(gateway)"
            @click="toggleGateway(gateway)"
            ><X
              v-if="selectedGateway(gateway)"
              :size="15"
              aria-hidden="true"
            /><Plus v-else :size="15" aria-hidden="true" />{{
              selectedGateway(gateway)
                ? tr("移除网关", "Remove gateway")
                : tr("使用网关", "Use gateway")
            }}</UiButton
          >
        </div>
        <label v-if="selectedGateway(gateway)" class="field"
          >{{ tr("目标网段，每行一个", "Destination prefixes, one per line")
          }}<textarea
            :value="selectedGateway(gateway)?.allowed_prefixes.join('\n')"
            :disabled="disabled"
            rows="3"
            :placeholder="tr('不添加指定网段', 'No destination prefixes')"
            spellcheck="false"
            @input="
              prefixes(gateway, ($event.target as HTMLTextAreaElement).value)
            "
          /><span class="field-note"
            >{{ tr("批准范围：", "Approved ranges: ")
            }}{{ gateway.allowed_prefixes.join(", ") || tr("无", "None") }} ·
            {{
              tr(
                "留空只关闭指定网段路由，不会自动开放公网。",
                "Leaving this empty disables specific routes; it never enables Internet access automatically.",
              )
            }}</span
          ></label
        >
      </article>
    </section>
    <OverlayNATEditor
      :model-value="modelValue.nat_policies || []"
      :profiles="options.nat_profiles"
      :leases="options.public_ip_leases || []"
      :members="modelValue.members"
      :instances="options.instances"
      :gateways="modelValue.gateways"
      :vpcs="vpcs"
      :disabled="disabled"
      @update:model-value="
        emit('update:modelValue', { ...modelValue, nat_policies: $event })
      "
    />
  </div>
</template>
<style scoped>
.selection-editor {
  display: grid;
  gap: 32px;
}
.selection-section > header {
  margin-bottom: 18px;
}
.selection-section h3 {
  margin: 0;
  font-size: 17px;
}
.selection-section header p {
  font-size: 13px;
  color: var(--secondary);
  line-height: 1.7;
  margin: 10px 0 0;
}
.member-choice {
  display: flex;
  gap: 16px;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--border);
  padding: 16px 0;
}
.member-copy {
  display: grid;
  gap: 6px;
  min-width: 0;
}
.member-copy strong {
  font-size: 14px;
  overflow-wrap: anywhere;
}
.member-copy span,
.member-copy small {
  font-size: 12px;
  color: var(--secondary);
  overflow-wrap: anywhere;
}
.is-selected .member-copy strong {
  color: var(--accent-text);
}
.gateway-choice {
  padding: 16px 0;
  border: 0;
  border-radius: 0;
  margin-top: 12px;
  border-block: 1px solid var(--border);
}
.gateway-choice.is-selected {
  border-color: var(--accent);
  background: var(--subtle);
}
.choice-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}
.choice-heading > div {
  min-width: 0;
}
.choice-heading strong {
  overflow-wrap: anywhere;
  font-size: 14px;
}
.choice-heading p {
  font-size: 13px;
  color: var(--secondary);
  overflow-wrap: anywhere;
}
.gateway-choice .field {
  margin-top: 14px;
}
.editor-empty {
  background: var(--subtle);
  padding: 18px;
  border-radius: 6px;
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
}
.missing-member {
  margin-top: 14px;
  padding: 14px;
  border-radius: 6px;
  background: var(--warning-bg);
  color: var(--warning);
  font-size: 13px;
  line-height: 1.6;
}
.missing-member code {
  display: block;
  overflow-wrap: anywhere;
}
@media (max-width: 420px) {
  .member-choice,
  .choice-heading {
    align-items: stretch;
    flex-direction: column;
  }
  .member-choice > .ui-button {
    align-self: flex-start;
  }
  .gateway-choice {
    padding: 14px;
  }
}
@media (max-width: 420px) {
  .gateway-choice {
    padding: 14px 0;
  }
}
</style>
