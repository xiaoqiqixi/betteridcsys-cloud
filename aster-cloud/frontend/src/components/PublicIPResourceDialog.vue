<script setup lang="ts">
import { computed, reactive, shallowRef, watch } from "vue";
import { useConsole } from "../context";
import type { PublicIPPool } from "../api/public-ip";
import {
  targetsForPublicIP,
  validPublicIPResourceRequest,
  type PublicIPResource,
  type PublicIPResourceAction,
  type PublicIPResourceMode,
  type PublicIPResourceOptions,
} from "../api/public-ip-resource";
import UiOverlay from "./UiOverlay.vue";
import UiSelect from "./UiSelect.vue";
import UiButton from "./UiButton.vue";
import InlineError from "./InlineError.vue";
import BindingIngressSummary from "./BindingIngressSummary.vue";
import type { PublicIngressPolicy } from "../api/public-ingress";
const props = defineProps<{
  action: PublicIPResourceAction;
  cluster: string;
  options: PublicIPResourceOptions;
  pool?: PublicIPPool;
  resource?: PublicIPResource;
  mode?: PublicIPResourceMode;
  busy: boolean;
  pending: boolean;
  error: string;
  recoverySHA?: string;
}>();
const emit = defineEmits<{
  close: [];
  submit: [
    action: PublicIPResourceAction,
    target: string,
    body: Record<string, unknown>,
  ];
  reconcile: [];
}>();
const {
  prefs: { tr },
} = useConsole();
const frozenGeneration = props.resource?.binding_generation;
const form = reactive({
  mode: props.mode || "direct",
  owner: "",
  ownerChoice: "",
  vpc: "",
  profile: "",
  address: "",
  instance: "",
  confirm: "",
});
const ingress = shallowRef<PublicIngressPolicy | null>(null);
const original = JSON.stringify(form),
  attempted = shallowRef(false);
const locked = computed(() => props.busy || props.pending);
const dirty = computed(
  () => !props.pending && JSON.stringify(form) !== original,
);
const title = computed(() =>
  props.action === "resource.recover"
    ? tr("恢复解绑公网地址", "Recover public address detachment")
    : props.action === "resource.allocate"
      ? tr("分配实例公网 IP", "Allocate a VM public IP")
      : props.action === "resource.release"
        ? tr("回收公网地址", "Reclaim public address")
        : props.action === "resource.unbind"
          ? tr("解绑公网地址", "Unbind public address")
          : props.resource?.binding_state === "bound"
            ? props.resource.mode === "floating"
              ? tr("确认更换绑定实例", "Confirm instance reassignment")
              : tr("更换绑定实例", "Move to another instance")
            : props.resource?.mode === "floating"
              ? tr("确认绑定公网 IP", "Confirm public IP binding")
              : tr("绑定公网地址", "Bind public address"),
);
const approvedAddresses = (a: { public_ipv4s: string[] }) =>
  props.pool?.addresses.filter((ip) => a.public_ipv4s.includes(ip)) || [];
const floatingApprovals = computed(() =>
  props.options.approvals.filter(
    (a) =>
      a.cluster_id === props.cluster &&
      a.allow_floating_ip === true &&
      a.allow_internet_egress &&
      approvedAddresses(a).length > 0,
  ),
);
const vpcs = computed(() =>
  props.options.vpcs.filter(
    (v) =>
      v.cluster_id === props.cluster &&
      floatingApprovals.value.some(
        (a) => a.vpc_id === v.id && a.owner_ref === v.owner_ref,
      ),
  ),
);
const selectedVPC = computed(() => vpcs.value.find((v) => v.id === form.vpc));
const approvals = computed(() =>
  form.mode === "direct"
    ? props.options.direct_approvals.filter(
        (a) =>
          a.cluster_id === props.cluster && approvedAddresses(a).length > 0,
      )
    : floatingApprovals.value.filter(
        (a) =>
          a.vpc_id === form.vpc && a.owner_ref === selectedVPC.value?.owner_ref,
      ),
);
const profileKey = (p: { node_id: string; profile_id: string }) =>
  `${p.node_id}:${p.profile_id}`;
const selectedProfile = computed(() =>
  approvals.value.find((a) => profileKey(a) === form.profile),
);
const addresses = computed(() =>
  selectedProfile.value ? approvedAddresses(selectedProfile.value) : [],
);
const ownerChoices = computed(() =>
  [
    ...new Set([
      ...props.options.vpcs.map((v) => v.owner_ref),
      ...props.options.resource_targets.map((t) => t.owner_ref),
    ]),
  ].sort(),
);
const targets = computed(() =>
  props.resource
    ? targetsForPublicIP(props.resource, props.options).filter(
        (t) => t.instance_id !== props.resource?.instance_id,
      )
    : [],
);
const target = computed(() =>
  props.action === "resource.allocate" ? "" : props.resource?.id || "",
);
const expectedConfirmation = computed(() =>
  props.action === "resource.bind"
    ? form.instance
    : props.resource?.address || "",
);
const payload = computed<Record<string, unknown>>(() =>
  props.action === "resource.allocate"
    ? {
        pool_id: props.pool?.id || "",
        owner_ref:
          form.mode === "direct"
            ? form.owner
            : selectedVPC.value?.owner_ref || "",
        mode: form.mode,
        node_id: selectedProfile.value?.node_id || "",
        profile_id: selectedProfile.value?.profile_id || "",
        vpc_id: form.mode === "direct" ? "" : form.vpc,
        address: form.address,
      }
    : props.action === "resource.recover"
      ? {
          expected_generation: frozenGeneration,
          expected_snapshot_sha256: props.recoverySHA || "",
        }
      : props.action === "resource.bind"
        ? {
            instance_id: form.instance,
            expected_generation: frozenGeneration,
            ...(props.resource?.mode === "floating"
              ? { expected_ingress_revision: ingress.value?.revision }
              : {}),
          }
        : { expected_generation: frozenGeneration },
);
const valid = computed(
  () =>
    validPublicIPResourceRequest(props.action, target.value, payload.value) &&
    (props.action === "resource.allocate"
      ? props.pool?.enabled &&
        !!selectedProfile.value &&
        (form.address === "" || addresses.value.includes(form.address))
      : props.resource?.state === "reserved" &&
        props.resource.binding_generation === frozenGeneration &&
        (props.action === "resource.recover"
          ? props.resource.mode === "floating" &&
            ["pending", "blocked"].includes(props.resource.binding_state)
          : !["pending", "blocked"].includes(props.resource.binding_state)) &&
        form.confirm === expectedConfirmation.value &&
        !!expectedConfirmation.value &&
        (props.action === "resource.recover"
          ? true
          : props.action === "resource.bind"
            ? targets.value.some((t) => t.instance_id === form.instance) &&
              (props.resource.mode !== "floating" ||
                (!!ingress.value &&
                  ingress.value.instance_id === form.instance &&
                  ingress.value.owner_ref === props.resource.owner_ref &&
                  ingress.value.supported &&
                  ["default", "active"].includes(ingress.value.state))) &&
              (props.resource.mode === "floating" ||
                props.resource.binding_state === "unbound")
            : props.action === "resource.release"
              ? props.resource.releasable
              : props.resource.binding_state === "bound")),
);
watch(
  () => form.mode,
  () => {
    form.vpc = "";
    form.profile = "";
    form.address = "";
  },
);
watch(
  () => form.vpc,
  () => {
    form.profile = "";
    form.address = "";
  },
);
watch(
  () => form.profile,
  () => {
    form.address = "";
  },
);
watch(
  () => form.instance,
  () => {
    form.confirm = "";
    ingress.value = null;
  },
);
function chooseOwner(value: string) {
  form.ownerChoice = value;
  form.owner = value;
}
function acceptIngress(policy: PublicIngressPolicy | null) {
  if (
    policy &&
    (policy.instance_id !== form.instance ||
      policy.owner_ref !== props.resource?.owner_ref)
  )
    return;
  if (
    ingress.value &&
    (!policy ||
      ingress.value.revision !== policy.revision ||
      ingress.value.sha256 !== policy.sha256)
  )
    form.confirm = "";
  ingress.value = policy;
}
function submit() {
  attempted.value = true;
  if (!locked.value && valid.value)
    emit("submit", props.action, target.value, payload.value);
}
</script>
<template>
  <UiOverlay
    :open="true"
    :title="title"
    :busy="busy"
    :dirty="dirty"
    :close-label="tr('关闭', 'Close')"
    :discard-label="tr('放弃更改', 'Discard changes')"
    :continue-label="tr('继续编辑', 'Keep editing')"
    @close="emit('close')"
  >
    <form
      id="public-ip-resource-form"
      class="resource-form"
      novalidate
      @submit.prevent="submit"
    >
      <template v-if="action === 'resource.allocate'">
        <div class="resource-context">
          <strong>{{ pool?.name }}</strong
          ><span>{{ pool?.cidr }}</span>
        </div>
        <label class="field"
          >{{ tr("使用方式", "Address mode")
          }}<UiSelect
            v-model="form.mode"
            :label="tr('公网地址使用方式', 'Public address mode')"
            :options="[
              {
                value: 'direct',
                label: tr('虚拟机公网直绑', 'Direct VM address'),
              },
              { value: 'floating', label: tr('独立浮动 IP', 'Floating IP') },
            ]"
            :disabled="locked"
        /></label>
        <p class="resource-note">
          {{
            form.mode === "direct"
              ? tr(
                  "地址将用于实例的网卡配置。新实例可在创建时选择；已有实例只能在停机时接纳与其实际地址一致的配置，任务会核实 IP 与 MAC，不会更改实例 IP。",
                  "The address is configured on the VM interface. Select it when creating a VM; a stopped VM can only adopt its actual matching IP and MAC, verified by the task without changing the VM address.",
                )
              : tr(
                  "每个地址独立关联一台 VPC 实例。解绑后可保留地址，或切换到同一客户、同一 VPC 的另一台实例；公网入站访问由目标实例的规则单独控制。",
                  "Each address is associated with one VPC instance. Keep it after unbinding, or move it to another instance of the same owner and VPC. Public inbound access is controlled separately by the target instance’s rules.",
                )
          }}
        </p>
        <template v-if="form.mode === 'direct'">
          <label class="field"
            >{{ tr("已有客户引用", "Existing owner reference")
            }}<UiSelect
              :model-value="form.ownerChoice"
              :label="tr('选择客户引用', 'Choose owner reference')"
              :options="[
                {
                  value: '',
                  label: tr(
                    '填写新的客户引用',
                    'Enter another owner reference',
                  ),
                },
                ...ownerChoices.map((id) => ({ value: id, label: id })),
              ]"
              :disabled="locked"
              @update:model-value="chooseOwner"
          /></label>
          <label class="field"
            >{{ tr("所属客户 ID", "Owner reference")
            }}<input
              v-model="form.owner"
              maxlength="32"
              autocomplete="off"
              spellcheck="false"
              :disabled="locked || !!form.ownerChoice"
            /><span class="field-note">{{
              tr(
                "32 位小写十六进制客户引用；此处不会创建或修改财务客户。",
                "A 32-character lowercase hexadecimal owner reference. This does not create or change a billing account.",
              )
            }}</span></label
          >
        </template>
        <label v-else class="field"
          >{{ tr("所属 VPC", "VPC")
          }}<UiSelect
            v-model="form.vpc"
            :label="tr('浮动 IP 所属 VPC', 'Floating IP VPC')"
            :options="
              vpcs.map((v) => ({ value: v.id, label: `${v.name} · ${v.cidr}` }))
            "
            :placeholder="tr('选择 VPC', 'Choose a VPC')"
            :disabled="locked"
          /><span v-if="selectedVPC" class="field-note break-anywhere"
            >{{ tr("客户引用", "Owner reference") }} ·
            {{ selectedVPC.owner_ref }}</span
          ></label
        >
        <label class="field"
          >{{ tr("网络配置", "Network profile")
          }}<UiSelect
            v-model="form.profile"
            :label="tr('公网网络配置', 'Public network profile')"
            :options="
              approvals.map((p) => ({
                value: profileKey(p),
                label: `${p.node_id} · ${p.profile_id}`,
              }))
            "
            :placeholder="tr('选择已开放的网络', 'Choose an approved network')"
            :disabled="locked"
        /></label>
        <p v-if="!approvals.length" class="resource-note">
          {{
            tr(
              "当前地址池没有匹配的网络配置。请先核对节点网络与此地址池的使用范围。",
              "This pool has no matching network profile. Review the approved node networks and the pool scope first.",
            )
          }}
        </p>
        <label class="field"
          >{{ tr("公网地址", "Public address")
          }}<UiSelect
            v-model="form.address"
            :label="tr('实例公网地址', 'VM public address')"
            :options="[
              {
                value: '',
                label: tr('自动分配可用地址', 'Allocate an available address'),
              },
              ...addresses.map((ip) => ({ value: ip, label: ip })),
            ]"
            :disabled="locked || !selectedProfile"
          /><span class="field-note">{{
            tr(
              "指定地址不可用时不会自动换成其他地址。",
              "An unavailable selected address will not be silently replaced.",
            )
          }}</span></label
        >
      </template>
      <template v-else>
        <div class="resource-context">
          <strong>{{ resource?.address }}</strong
          ><span>{{
            resource?.mode === "floating"
              ? tr("独立浮动 IP", "Floating IP")
              : tr("虚拟机公网直绑", "Direct VM address")
          }}</span
          ><code>{{ resource?.owner_ref }}</code>
        </div>
        <template v-if="action === 'resource.bind'">
          <p class="resource-note">
            {{
              resource?.binding_state === "bound"
                ? tr(
                    "原实例与新实例将在切换期间隔离；完成网络变更后，新绑定才会生效。",
                    "The old and new instances are fenced during the move. The new binding takes effect only after the network change completes.",
                  )
                : tr(
                    "保存绑定后仍需执行相应任务。结果未确认前，不会将地址显示为已接通。",
                    "After saving the binding, continue its task. An unconfirmed change is not shown as connected.",
                  )
            }}
          </p>
          <label class="field"
            >{{ tr("目标实例", "Target instance")
            }}<UiSelect
              v-model="form.instance"
              :label="tr('绑定目标实例', 'Binding target instance')"
              :options="
                targets.map((t) => ({
                  value: t.instance_id,
                  label: `${t.ipv4 || tr('执行时核实地址', 'Verify address in task')} · ${t.node_id} · ${t.instance_id}`,
                }))
              "
              :placeholder="
                tr('选择同一客户的实例', 'Choose an instance of the same owner')
              "
              :disabled="locked"
          /></label>
          <BindingIngressSummary
            v-if="resource?.mode === 'floating' && form.instance"
            :key="form.instance"
            :instance-id="form.instance"
            :owner-ref="resource.owner_ref"
            @ready="acceptIngress"
          />
          <p v-if="!targets.length" class="resource-note">
            {{
              resource?.mode === "direct"
                ? tr(
                    "尚无可绑定的关机实例。请先关机；已有实例的实际地址须与此地址一致，也可在创建新实例时选择。",
                    "No matching stopped instance is available. Shut it down first; its actual address must match. You can also select this address when creating a VM.",
                  )
                : tr(
                    "尚无可绑定实例。请先将同一客户的实例加入此 VPC，并确认网络状态。",
                    "No matching instance is available. Add an instance of the same owner to this VPC and confirm its network state first.",
                  )
            }}
          </p>
        </template>
        <p v-else class="resource-note">
          {{
            action === "resource.recover"
              ? tr(
                  "此操作只恢复解绑，不恢复公网绑定。将核实各节点网络进度，规划新的解绑任务；全部节点确认隔离和释放后才能回收。",
                  "This recovers detachment only, not public binding. It checks node progress and plans a new detachment task. Reclamation requires confirmed fencing and release on every node.",
                )
              : action === "resource.release"
                ? tr(
                    "回收后地址可重新分配，历史记录仍会保留。请确认不再需要此地址。",
                    "Reclamation makes the address available for allocation again and retains its history. Confirm that it is no longer needed.",
                  )
                : tr(
                    "解绑不会回收此地址。完成相关任务并确认已断开后，可重新绑定或回收。",
                    "Unbinding keeps the address allocated. After the task confirms detachment, bind it again or reclaim it.",
                  )
          }}
        </p>
        <label class="field resource-confirmation"
          >{{
            action === "resource.bind"
              ? tr(
                  "输入目标实例 ID 以确认",
                  "Type the target instance ID to confirm",
                )
              : tr("输入公网地址以确认", "Type the public address to confirm")
          }}<code>{{ expectedConfirmation }}</code
          ><input
            v-model="form.confirm"
            autocomplete="off"
            spellcheck="false"
            :disabled="locked"
        /></label>
      </template>
      <p
        v-if="attempted && !valid && !pending"
        class="resource-error"
        role="alert"
      >
        {{
          tr(
            "请核对所选网络、客户引用及确认内容。",
            "Review the network selection, owner reference and confirmation.",
          )
        }}
      </p>
      <InlineError :error="error" /><UiButton
        v-if="pending"
        :busy="busy"
        @click="emit('reconcile')"
        >{{ tr("核对原操作", "Check original operation") }}</UiButton
      >
    </form>
    <template #footer="{ close }"
      ><UiButton :disabled="busy" @click="close">{{
        tr("取消", "Cancel")
      }}</UiButton
      ><UiButton
        variant="primary"
        type="submit"
        form="public-ip-resource-form"
        :busy="busy"
        :disabled="locked || !valid"
        >{{ title }}</UiButton
      ></template
    >
  </UiOverlay>
</template>
<style scoped>
.resource-form {
  display: grid;
  gap: 24px;
}
.resource-context {
  display: grid;
  gap: 8px;
  padding: 16px;
  border-radius: 6px;
  background: var(--subtle);
  overflow-wrap: anywhere;
}
.resource-context strong {
  font-size: 18px;
  font-variant-numeric: tabular-nums;
}
.resource-context span,
.resource-context code,
.resource-note {
  color: var(--secondary);
  font-size: 13px;
  line-height: 1.7;
}
.resource-note {
  margin: 0;
}
.resource-confirmation {
  border-top: 1px solid var(--border);
  padding-top: 24px;
}
.resource-confirmation code {
  overflow-wrap: anywhere;
  color: var(--secondary);
}
.resource-error {
  margin: 0;
  color: var(--danger);
  font-size: 13px;
  line-height: 1.6;
}
.floating-consent {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  padding: 16px;
  border: 1px solid var(--control-border);
  border-radius: 6px;
  background: var(--subtle);
}
.floating-consent > span {
  display: grid;
  gap: 8px;
  font-size: 13px;
  line-height: 1.6;
  min-width: 0;
}
.floating-consent > span > span,
.floating-consent code {
  color: var(--secondary);
  overflow-wrap: anywhere;
}
.floating-consent input {
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
.floating-consent input:checked {
  background: var(--accent);
  border-color: var(--accent);
  box-shadow: inset 0 0 0 4px var(--surface-raised);
}
</style>
