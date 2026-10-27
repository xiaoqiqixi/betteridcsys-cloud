<script setup lang="ts">
import { computed, reactive, shallowRef, watch } from "vue";
import { useConsole } from "../context";
import { key32 } from "../api/client";
import {
  ingressSource,
  sameIngressRules,
  validPublicIngressRequest,
  type PublicIngressPolicy,
  type PublicIngressRequest,
  type PublicIngressRule,
} from "../api/public-ingress";
import UiOverlay from "./UiOverlay.vue";
import UiSelect from "./UiSelect.vue";
import UiButton from "./UiButton.vue";
import InlineError from "./InlineError.vue";
const props = defineProps<{
  policy: PublicIngressPolicy;
  busy: boolean;
  pending: boolean;
  error: string;
}>();
const emit = defineEmits<{
  close: [];
  submit: [request: PublicIngressRequest];
  reconcile: [];
}>();
const {
  prefs: { tr },
} = useConsole();
// The rule draft and its revision belong to this dialog lifetime. A refresh
// cannot silently rebase a stale edit or replace the target identity.
const original = {
    ...props.policy,
    rules: props.policy.rules.map((r) => ({ ...r })),
  },
  rules = shallowRef<PublicIngressRule[]>(
    props.policy.rules.map((r) => ({ ...r })),
  );
const confirmation = shallowRef(""),
  ruleError = shallowRef("");
const form = reactive({ protocol: "tcp", source: "", start: "", end: "" });
const locked = computed(() => props.busy || props.pending);
const dirty = computed(
  () =>
    !sameIngressRules(rules.value, original.rules) ||
    !!confirmation.value ||
    !!form.source ||
    !!form.start ||
    !!form.end,
);
const valid = computed(
  () =>
    !locked.value &&
    props.error !== "conflict" &&
    props.policy.instance_id === original.instance_id &&
    props.policy.owner_ref === original.owner_ref &&
    props.policy.revision === original.revision &&
    props.policy.sha256 === original.sha256 &&
    props.policy.supported &&
    ["default", "active"].includes(props.policy.state) &&
    confirmation.value === original.instance_id &&
    !form.source &&
    !form.start &&
    !form.end &&
    validPublicIngressRequest({
      expected_revision: original.revision,
      rules: rules.value,
    }),
);
watch(
  () => form.protocol,
  () => {
    if (form.protocol === "icmp") {
      form.start = "";
      form.end = "";
    }
    ruleError.value = "";
  },
);
function add() {
  ruleError.value = "";
  const start = form.protocol === "icmp" ? 0 : Number(form.start),
    end = form.protocol === "icmp" ? 0 : Number(form.end || form.start);
  const next: PublicIngressRule = {
    id: key32(),
    protocol: form.protocol as PublicIngressRule["protocol"],
    source_cidr: form.source.trim(),
    port_start: start,
    port_end: end,
  };
  if (
    !ingressSource(next.source_cidr) ||
    (form.protocol !== "icmp" &&
      (!/^[0-9]{1,5}$/.test(form.start) ||
        (form.end !== "" && !/^[0-9]{1,5}$/.test(form.end)))) ||
    !validPublicIngressRequest({
      expected_revision: original.revision,
      rules: [next],
    })
  ) {
    ruleError.value = tr(
      "请输入规范的 IPv4 来源网段；TCP/UDP 端口范围为 1–65535，起始端口不得大于结束端口。",
      "Enter a canonical IPv4 source CIDR. TCP/UDP ports must be 1–65535, with the start no greater than the end.",
    );
    return;
  }
  if (rules.value.length >= 64) {
    ruleError.value = tr(
      "最多保留 64 条允许规则。",
      "Keep at most 64 allow rules.",
    );
    return;
  }
  if (
    rules.value.some(
      (r) =>
        r.protocol === next.protocol &&
        r.source_cidr === next.source_cidr &&
        r.port_start === next.port_start &&
        r.port_end === next.port_end,
    )
  ) {
    ruleError.value = tr(
      "这条允许规则已存在。",
      "This allow rule already exists.",
    );
    return;
  }
  rules.value = [...rules.value, next];
  form.source = "";
  form.start = "";
  form.end = "";
}
function remove(id: string) {
  if (!locked.value) rules.value = rules.value.filter((r) => r.id !== id);
}
function submit() {
  if (valid.value)
    emit("submit", {
      expected_revision: original.revision,
      rules: rules.value
        .map((r) => ({ ...r }))
        .sort((a, b) => a.id.localeCompare(b.id)),
    });
}
const ports = (r: PublicIngressRule) =>
  r.protocol === "icmp"
    ? tr("ICMP 回显", "ICMP echo")
    : `${r.protocol.toUpperCase()} ${r.port_start === r.port_end ? r.port_start : `${r.port_start}–${r.port_end}`}`;
</script>
<template>
  <UiOverlay
    :open="true"
    :title="tr('编辑公网入站规则', 'Edit public ingress rules')"
    :busy="busy"
    :dirty="dirty && !pending"
    :close-label="tr('关闭', 'Close')"
    :discard-label="tr('放弃更改', 'Discard changes')"
    :continue-label="tr('继续编辑', 'Keep editing')"
    @close="emit('close')"
  >
    <form
      id="public-ingress-form"
      class="ingress-form"
      novalidate
      @submit.prevent="submit"
    >
      <div class="ingress-explanation">
        <strong>{{
          tr(
            "仅允许匹配规则的公网新连接",
            "Allow only matching new public connections",
          )
        }}</strong>
        <p>
          {{
            tr(
              "这些规则属于实例，不随浮动 IP 转移。没有允许规则时，默认拒绝公网新入站；实例主动发起连接的正常回包仍可通过。",
              "Rules belong to the instance and do not move with a floating IP. With no allow rules, new public inbound connections are denied; legitimate replies to connections initiated by the instance still pass.",
            )
          }}
        </p>
        <p>
          {{
            tr(
              "当前仅管理 VPC 浮动 IP 的公网入站，不替代实例防火墙或完整安全组。",
              "This controls public ingress through a VPC floating IP only. It does not replace the guest firewall or a complete security group.",
            )
          }}
        </p>
      </div>
      <section
        class="ingress-rule-editor"
        :aria-label="tr('添加允许规则', 'Add allow rule')"
      >
        <label class="field"
          >{{ tr("协议", "Protocol")
          }}<UiSelect
            v-model="form.protocol"
            :label="tr('入站协议', 'Ingress protocol')"
            :options="[
              { value: 'tcp', label: 'TCP' },
              { value: 'udp', label: 'UDP' },
              { value: 'icmp', label: tr('ICMP 回显', 'ICMP echo') },
            ]"
            :disabled="locked"
        /></label>
        <label class="field ingress-source"
          >{{ tr("允许来源", "Allowed source")
          }}<input
            v-model="form.source"
            :aria-label="tr('允许来源 CIDR', 'Allowed source CIDR')"
            placeholder="203.0.113.10/32"
            autocomplete="off"
            spellcheck="false"
            :disabled="locked"
          /><span class="field-note">{{
            tr(
              "填写实际来源 IP/网段。0.0.0.0/0 表示所有公网来源；SSH/RDP 请优先使用可信固定网段。",
              "Enter an actual source IP/CIDR. 0.0.0.0/0 means all public sources; prefer a trusted fixed source for SSH/RDP.",
            )
          }}</span></label
        >
        <template v-if="form.protocol !== 'icmp'"
          ><label class="field"
            >{{ tr("起始端口", "Start port")
            }}<input
              v-model="form.start"
              :aria-label="tr('入站起始端口', 'Ingress start port')"
              inputmode="numeric"
              autocomplete="off"
              placeholder="443"
              :disabled="locked" /></label
          ><label class="field"
            >{{ tr("结束端口", "End port")
            }}<input
              v-model="form.end"
              :aria-label="tr('入站结束端口', 'Ingress end port')"
              inputmode="numeric"
              autocomplete="off"
              :placeholder="
                tr('留空表示单端口', 'Leave blank for a single port')
              "
              :disabled="locked" /></label
        ></template>
        <p v-if="ruleError" class="rule-error" role="alert">{{ ruleError }}</p>
        <UiButton class="add-ingress-rule" :disabled="locked" @click="add">{{
          tr("添加允许规则", "Add allow rule")
        }}</UiButton>
      </section>
      <section
        class="ingress-rules"
        :aria-label="tr('待保存的允许规则', 'Allow rules to save')"
      >
        <div class="ingress-rule-heading">
          <h3>{{ tr("允许规则", "Allow rules") }}</h3>
          <span>{{ rules.length }} / 64</span>
        </div>
        <p v-if="!rules.length" class="ingress-empty">
          {{
            tr(
              "没有允许规则。保存后不接受公网新入站连接。",
              "No allow rules. After saving, new public inbound connections are denied.",
            )
          }}
        </p>
        <div v-for="r in rules" :key="r.id" class="ingress-rule">
          <div>
            <strong>{{ ports(r) }}</strong
            ><span>{{ tr("来源", "Source") }} {{ r.source_cidr }}</span>
          </div>
          <UiButton
            variant="quiet"
            :disabled="locked"
            :aria-label="`${tr('移除允许规则', 'Remove allow rule')} ${ports(r)} ${r.source_cidr}`"
            @click="remove(r.id)"
            >{{ tr("移除", "Remove") }}</UiButton
          >
        </div>
      </section>
      <label class="field ingress-confirmation"
        >{{ tr("输入实例 ID 以确认", "Type the instance ID to confirm")
        }}<code>{{ original.instance_id }}</code
        ><input
          v-model="confirmation"
          :aria-label="tr('确认入站规则实例 ID', 'Confirm ingress instance ID')"
          autocomplete="off"
          spellcheck="false"
          :disabled="locked"
      /></label>
      <p class="ingress-note">
        {{
          tr(
            "保存只表示记录新的规则版本。有绑定地址时，须完成关联网络任务后才确认生效；删除规则可能中断原有入站连接。",
            "Saving records a new policy revision. If an address is bound, its linked network task must complete before the revision is confirmed effective. Removing rules can interrupt existing inbound connections.",
          )
        }}
      </p>
      <InlineError :error="error" />
      <p v-if="error === 'conflict'" class="ingress-note">
        {{
          tr(
            "规则或绑定状态已变化。请关闭此窗口，刷新入站规则后重新确认。",
            "The policy or binding state has changed. Close this dialog, refresh ingress rules, and confirm again.",
          )
        }}
      </p>
      <UiButton v-if="pending" :disabled="busy" @click="emit('reconcile')">{{
        tr("核对原规则操作", "Verify original policy operation")
      }}</UiButton>
    </form>
    <template #footer
      ><UiButton :disabled="busy" @click="emit('close')">{{
        tr("取消", "Cancel")
      }}</UiButton
      ><UiButton
        variant="primary"
        type="submit"
        form="public-ingress-form"
        :busy="busy"
        :disabled="!valid"
        >{{ tr("保存入站规则", "Save ingress rules") }}</UiButton
      ></template
    >
  </UiOverlay>
</template>
<style scoped>
.ingress-form {
  display: grid;
  gap: 24px;
  min-width: 0;
}
.ingress-explanation {
  padding: 16px;
  background: var(--surface-raised);
  border: 1px solid var(--border);
  border-radius: 6px;
}
.ingress-explanation strong {
  font-size: 14px;
  line-height: 1.6;
}
.ingress-explanation p,
.ingress-note,
.ingress-empty {
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
  margin: 8px 0 0;
}
.ingress-rule-editor {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}
.ingress-source,
.rule-error,
.add-ingress-rule {
  grid-column: 1/-1;
}
.rule-error {
  font-size: 13px;
  color: var(--danger);
  line-height: 1.7;
  margin: 0;
}
.add-ingress-rule {
  justify-self: start;
}
.ingress-rule-heading {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}
.ingress-rule-heading h3 {
  font-size: 15px;
  margin: 0;
}
.ingress-rule-heading span {
  color: var(--secondary);
  font-size: 13px;
}
.ingress-rule {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  padding: 12px 0;
  border-bottom: 1px solid var(--border);
  min-width: 0;
}
.ingress-rule > div {
  display: grid;
  gap: 4px;
  font-size: 13px;
  line-height: 1.6;
  overflow-wrap: anywhere;
}
.ingress-rule span {
  color: var(--secondary);
}
.ingress-confirmation code {
  font-size: 12px;
  color: var(--secondary);
  overflow-wrap: anywhere;
}
@media (max-width: 600px) {
  .ingress-rule-editor {
    grid-template-columns: minmax(0, 1fr);
  }
  .ingress-rule {
    align-items: flex-start;
  }
  .add-ingress-rule {
    width: 100%;
    justify-self: stretch;
  }
}
</style>
