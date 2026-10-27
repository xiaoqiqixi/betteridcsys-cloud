<script setup lang="ts">
import { computed, reactive, watch, shallowRef } from "vue";
import { useConsole } from "../context";
import {
  expandPublicIPRange,
  validPublicIPRequest,
  type PublicIPAction,
  type PublicIPLease,
  type PublicIPOptions,
  type PublicIPPool,
} from "../api/public-ip";
import UiOverlay from "./UiOverlay.vue";
import UiButton from "./UiButton.vue";
import UiSelect from "./UiSelect.vue";
import InlineError from "./InlineError.vue";
const props = defineProps<{
  action: PublicIPAction;
  cluster: string;
  options: PublicIPOptions;
  pool?: PublicIPPool;
  lease?: PublicIPLease;
  busy: boolean;
  pending: boolean;
  error: string;
}>();
const emit = defineEmits<{
  close: [];
  submit: [
    action: PublicIPAction,
    target: string,
    body: Record<string, unknown>,
  ];
  reconcile: [];
}>();
const {
  prefs: { tr },
} = useConsole();
const form = reactive({
  name: "",
  cidr: "",
  first: "",
  last: "",
  addresses: "",
  entry: "range",
  vpc: "",
  profile: "",
  address: "",
  confirm: "",
});
const invalid = computed(() => attempted.value && !valid.value);
const attempted = shallowRef(false);
const locked = computed(() => props.busy || props.pending);
const dirty = computed(
  () =>
    Object.entries(form).some(([k, v]) => k !== "entry" && v !== "") &&
    !props.pending,
);
const title = computed(() =>
  props.action === "pool.create"
    ? tr("新建公网 IP 池", "New public IP pool")
    : props.action === "pool.extend"
      ? tr("补充公网地址", "Add public addresses")
      : props.action === "pool.state"
        ? props.pool?.enabled
          ? tr("停用地址分配", "Disable allocations")
          : tr("启用地址分配", "Enable allocations")
        : props.action === "lease.allocate"
          ? tr("分配公网 IP", "Allocate public IP")
          : tr("回收公网 IP", "Reclaim public IP"),
);
const vpcs = computed(() =>
  props.options.vpcs.filter(
    (v) =>
      v.cluster_id === props.cluster &&
      props.options.approvals.some(
        (a) =>
          a.vpc_id === v.id &&
          a.owner_ref === v.owner_ref &&
          a.cluster_id === v.cluster_id &&
          props.pool?.addresses.some((ip) => a.public_ipv4s.includes(ip)),
      ),
  ),
);
const approvals = computed(() =>
  props.options.approvals.filter(
    (a) =>
      a.cluster_id === props.cluster &&
      a.vpc_id === form.vpc &&
      props.pool?.addresses.some((ip) => a.public_ipv4s.includes(ip)),
  ),
);
const approval = computed(() =>
  approvals.value.find((a) => `${a.node_id}:${a.profile_id}` === form.profile),
);
const allocAddresses = computed(
  () =>
    props.pool?.addresses.filter((ip) =>
      approval.value?.public_ipv4s.includes(ip),
    ) || [],
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
const inventory = computed(() =>
  form.entry === "range"
    ? expandPublicIPRange(form.first.trim(), form.last.trim())
    : form.addresses.split(/[\s,，]+/).filter(Boolean),
);
const poolApprovalAddresses = computed(
  () =>
    new Set(
      props.options.approvals
        .filter((a) => a.cluster_id === props.cluster)
        .flatMap((a) => a.public_ipv4s),
    ),
);
const target = computed(() =>
  props.action === "pool.state" || props.action === "pool.extend"
    ? props.pool?.id || ""
    : props.action === "lease.release"
      ? props.lease?.id || ""
      : "",
);
const payload = computed<Record<string, unknown>>(() =>
  props.action === "pool.create"
    ? {
        cluster_id: props.cluster,
        name: form.name.trim(),
        cidr: form.cidr.trim(),
        addresses: inventory.value,
        enabled: true,
      }
    : props.action === "pool.extend"
      ? { addresses: inventory.value }
      : props.action === "pool.state"
        ? { enabled: !props.pool?.enabled }
        : props.action === "lease.allocate"
          ? {
              pool_id: props.pool?.id || "",
              owner_ref: approval.value?.owner_ref || "",
              vpc_id: form.vpc,
              node_id: approval.value?.node_id || "",
              profile_id: approval.value?.profile_id || "",
              address: form.address,
            }
          : {},
);
const valid = computed(
  () =>
    validPublicIPRequest(props.action, target.value, payload.value) &&
    (!["pool.create", "pool.extend"].includes(props.action) ||
      inventory.value.every((ip) => poolApprovalAddresses.value.has(ip))) &&
    (props.action !== "pool.extend" ||
      (inventory.value.every((ip) => !props.pool?.addresses.includes(ip)) &&
        (props.pool?.addresses.length || 0) + inventory.value.length <=
          4096)) &&
    (props.action !== "lease.allocate" ||
      (props.pool?.enabled && !!approval.value)) &&
    (props.action !== "lease.release" ||
      (props.lease?.releasable && form.confirm === props.lease.address)),
);
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
      id="public-ip-form"
      class="ip-form"
      novalidate
      @submit.prevent="submit"
    >
      <template v-if="action === 'pool.create' || action === 'pool.extend'">
        <div v-if="action === 'pool.extend'" class="ip-context">
          <strong>{{ pool?.name }}</strong
          ><span>{{ pool?.cidr }}</span>
        </div>
        <p class="ip-intro">
          {{
            tr(
              "添加已获准使用的地址，统一管理公网出口库存。",
              "Add approved addresses to manage public egress inventory.",
            )
          }}
        </p>
        <label v-if="action === 'pool.create'" class="field"
          >{{ tr("地址池名称", "Pool name")
          }}<input
            v-model="form.name"
            maxlength="80"
            :disabled="locked"
            autocomplete="off"
            required
        /></label>
        <label v-if="action === 'pool.create'" class="field"
          >{{ tr("所属网段", "Subnet")
          }}<input
            v-model="form.cidr"
            :disabled="locked"
            placeholder="a.b.c.d/24"
            spellcheck="false"
            required
        /></label>
        <div class="ip-context">
          <strong>{{ tr("可纳管地址", "Approved inventory") }}</strong>
          <div
            class="approved-addresses"
            tabindex="0"
            :aria-label="tr('可纳管地址', 'Approved inventory')"
          >
            {{
              [...poolApprovalAddresses].join(" · ") ||
              tr("暂无已配置地址", "No configured addresses")
            }}
          </div>
        </div>
        <label class="field"
          >{{ tr("添加方式", "Address entry")
          }}<UiSelect
            v-model="form.entry"
            :label="tr('添加方式', 'Address entry')"
            :options="[
              { value: 'range', label: tr('连续地址范围', 'Address range') },
              { value: 'list', label: tr('逐个填写', 'Address list') },
            ]"
            :disabled="locked"
        /></label>
        <div v-if="form.entry === 'range'" class="ip-pair">
          <label class="field"
            >{{ tr("起始 IP", "First IP")
            }}<input
              v-model="form.first"
              :disabled="locked"
              spellcheck="false"
              required
          /></label>
          <label class="field"
            >{{ tr("结束 IP", "Last IP")
            }}<input
              v-model="form.last"
              :disabled="locked"
              spellcheck="false"
              required
          /></label>
        </div>
        <label v-else class="field"
          >{{ tr("公网地址，每行一个", "Public addresses, one per line")
          }}<textarea
            v-model="form.addresses"
            :disabled="locked"
            rows="5"
            spellcheck="false"
            required
          />
        </label>
        <p class="field-note">
          {{
            tr(
              "最多 4096 个地址；地址须位于所填网段，并已配置在对应出口。不能重复加入其他地址池。",
              "Up to 4096 addresses within this subnet, preconfigured on the approved egress. Addresses cannot belong to another pool.",
            )
          }}
        </p>
      </template>
      <template v-else-if="action === 'lease.allocate'">
        <div class="ip-context">
          <strong>{{ pool?.name }}</strong
          ><span>{{ pool?.cidr }}</span>
        </div>
        <label class="field"
          >{{ tr("所属 VPC", "VPC")
          }}<UiSelect
            v-model="form.vpc"
            :label="tr('所属 VPC', 'VPC')"
            :options="
              vpcs.map((v) => ({ value: v.id, label: `${v.name} · ${v.cidr}` }))
            "
            :placeholder="tr('选择 VPC', 'Select VPC')"
            :disabled="locked"
        /></label>
        <label class="field"
          >{{ tr("NAT 出口", "NAT egress")
          }}<UiSelect
            v-model="form.profile"
            :label="tr('NAT 出口', 'NAT egress')"
            :options="
              approvals.map((a) => ({
                value: `${a.node_id}:${a.profile_id}`,
                label: `${a.node_id} · ${a.profile_id}`,
              }))
            "
            :placeholder="tr('选择出口', 'Select egress')"
            :disabled="locked || !form.vpc"
        /></label>
        <label class="field"
          >{{ tr("公网 IP", "Public IP")
          }}<UiSelect
            v-model="form.address"
            :label="tr('公网 IP', 'Public IP')"
            :options="[
              {
                value: '',
                label: tr('自动分配可用地址', 'Allocate an available address'),
              },
              ...allocAddresses.map((ip) => ({ value: ip, label: ip })),
            ]"
            :disabled="locked || !approval"
        /></label>
        <p class="field-note">
          {{
            tr(
              "分配后，到 VPC 网络配置中选择此地址并应用。分配本身不会更改正在使用的出口。",
              "After allocation, select this address in the VPC network configuration and apply it. Allocation alone does not change the active egress.",
            )
          }}
        </p>
        <p v-if="!vpcs.length" class="ip-warning">
          {{
            tr(
              "此地址池暂无可用的 VPC 出口，请先核对出口地址配置。",
              "No VPC egress can use this pool. Review the egress address configuration first.",
            )
          }}
        </p>
      </template>
      <template v-else-if="action === 'pool.state'">
        <div class="ip-context">
          <strong>{{ pool?.name }}</strong
          ><span>{{ pool?.cidr }}</span>
        </div>
        <p class="ip-intro">
          {{
            pool?.enabled
              ? tr(
                  "停用后不再分配新地址。现有分配与 NAT 连接保持不变。",
                  "Disabling prevents new allocations. Existing allocations and NAT connections remain unchanged.",
                )
              : tr(
                  "启用后，此池中符合出口配置的空闲地址可再次分配。",
                  "Enabling makes available approved addresses allocatable again.",
                )
          }}
        </p>
      </template>
      <template v-else>
        <div class="ip-context">
          <strong>{{ lease?.address }}</strong
          ><span>{{ lease?.node_id }} · {{ lease?.profile_id }}</span>
        </div>
        <p class="ip-intro">
          {{
            tr(
              "回收后地址可重新分配，原分配记录仍会保留。已绑定或结果待确认的地址不能回收。",
              "Reclaiming makes the address available for allocation while retaining its history. Bound addresses or unconfirmed operations cannot be reclaimed.",
            )
          }}
        </p>
        <label class="field"
          >{{
            tr(
              "输入公网 IP 以确认回收",
              "Type the public IP to confirm reclamation",
            )
          }}<input
            v-model="form.confirm"
            :disabled="locked"
            autocomplete="off"
            spellcheck="false"
            required
        /></label>
      </template>
      <p v-if="invalid" role="alert" class="ip-warning">
        {{
          tr(
            "请核对填写内容和地址批准范围。",
            "Check the form and approved address scope.",
          )
        }}
      </p>
      <InlineError v-if="error" :error="error" />
      <UiButton v-if="pending" :busy="busy" @click="emit('reconcile')">{{
        tr("核对原操作", "Check original operation")
      }}</UiButton>
    </form>
    <template #footer="{ close }"
      ><UiButton :disabled="busy" @click="close">{{
        tr("取消", "Cancel")
      }}</UiButton
      ><UiButton
        variant="primary"
        type="submit"
        form="public-ip-form"
        :busy="busy"
        :disabled="locked"
        >{{ title }}</UiButton
      ></template
    >
  </UiOverlay>
</template>
<style scoped>
.approved-addresses {
  max-height: 140px;
  overflow: auto;
  overflow-wrap: anywhere;
  font-size: 13px;
  line-height: 1.8;
  color: var(--secondary);
}
.ip-form {
  display: grid;
  gap: 20px;
  min-width: 0;
}
.ip-intro {
  font-size: 14px;
  line-height: 1.75;
  margin: 0;
  color: var(--secondary);
}
.ip-pair {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
.ip-context {
  display: grid;
  gap: 8px;
  padding: 16px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--subtle);
  overflow-wrap: anywhere;
}
.ip-context span {
  font-size: 13px;
  color: var(--secondary);
}
.ip-warning {
  font-size: 13px;
  line-height: 1.7;
  color: var(--warning);
  padding: 12px;
  border-radius: 6px;
  background: var(--warning-bg);
  margin: 0;
}
@media (max-width: 600px) {
  .ip-pair {
    grid-template-columns: 1fr;
  }
}
</style>
