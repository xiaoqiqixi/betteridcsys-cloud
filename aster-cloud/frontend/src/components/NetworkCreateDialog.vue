<script setup lang="ts">
import { computed, onScopeDispose, reactive, shallowRef, watch } from "vue";
import { useConsole } from "../context";
import { useMutation, acknowledgeNetwork } from "../composables/mutation";
import { ApiError, key32, record, validNode, validPage } from "../api/client";
import {
  matchesNetworkIntent,
  networkField,
  networkPage,
  networkID,
  ipv4,
  type NetworkKind,
  type NetworkRecord,
} from "../api/network";
import type { Node } from "../api/types";
import UiButton from "./UiButton.vue";
import UiOverlay from "./UiOverlay.vue";
import UiSelect from "./UiSelect.vue";
import InlineError from "./InlineError.vue";

const props = defineProps<{ open: boolean; kind: NetworkKind }>();
const emit = defineEmits<{ close: []; saved: [] }>();
const {
  api,
  session,
  prefs: { tr },
  notify,
} = useConsole();
const mutation = useMutation();
const form = reactive({
  name: "",
  node_id: "",
  owner_ref: "",
  cidr: "",
  vlan_id: "",
  vpc_id: "",
  gateway: "",
  addresses: "",
  pool_id: "",
  instance_id: "",
  address: "",
});
const nodes = shallowRef<Node[]>([]),
  options = shallowRef<NetworkRecord[]>([]),
  optionError = shallowRef(""),
  reading = shallowRef(false),
  optionsBusy = shallowRef(false);
const intent = shallowRef<Record<string, unknown> | null>(null);
const draftError = shallowRef("");
let generation = 0,
  abort: AbortController | undefined;
const title = computed(() =>
  props.kind === "vpcs"
    ? tr("新建私有网络", "New private network")
    : props.kind === "pools"
      ? tr("新建 IP 地址池", "New IP pool")
      : tr("预留 IP 地址", "Reserve an IP address"),
);
const blocked = computed(
  () => mutation.busy.value || reading.value || !!mutation.pendingKey.value,
);
const nodeOptions = computed(() =>
  nodes.value.map((n) => ({
    value: n.id,
    label: `${n.id} · ${n.datacenter_id}`,
  })),
);
const objectOptions = computed(() => [
  ...(props.kind === "pools"
    ? [{ value: "", label: tr("经典网络", "Classic network") }]
    : []),
  ...options.value.map((v) => ({
    value: v.id,
    label: "name" in v ? `${v.name} · ${v.id.slice(0, 8)}` : v.id,
  })),
]);
async function loadOptions() {
  const ticket = ++generation,
    epoch = session.epoch.value;
  abort?.abort();
  abort = new AbortController();
  optionsBusy.value = true;
  optionError.value = "";
  try {
    const result = await api.get(
      "/nodes",
      (v): v is { items: Node[]; next_cursor: string | null } =>
        validPage(v, validNode),
      abort.signal,
    );
    let values: NetworkRecord[] = [];
    if (props.kind !== "vpcs") {
      const kind = props.kind === "pools" ? "vpcs" : "pools";
      const page = await api.get(
        `/networks/${kind}`,
        networkPage(kind),
        abort.signal,
      );
      values = page.items;
    }
    if (ticket !== generation || epoch !== session.epoch.value || !props.open)
      return;
    nodes.value = result.items;
    options.value = values;
  } catch (cause) {
    if (ticket !== generation || epoch !== session.epoch.value) return;
    optionError.value = cause instanceof ApiError ? cause.kind : "network";
    if (cause instanceof ApiError && cause.kind === "unauthorized")
      session.invalidate();
  } finally {
    if (ticket === generation) optionsBusy.value = false;
  }
}
watch(
  [() => props.open, () => props.kind],
  ([open]) => {
    generation++;
    abort?.abort();
    if (open) {
      Object.keys(form).forEach((k) => {
        form[k as keyof typeof form] = "";
      });
      intent.value = null;
      draftError.value = "";
      options.value = [];
      nodes.value = [];
      mutation.clearMessage();
      void loadOptions();
    }
  },
  { immediate: true, flush: "sync" },
);
watch(session.epoch, () => {
  generation++;
  abort?.abort();
  emit("close");
});
onScopeDispose(() => {
  generation++;
  abort?.abort();
});
function payload(): Record<string, unknown> {
  if (props.kind === "vpcs")
    return {
      owner_ref: form.owner_ref.trim(),
      node_id: form.node_id.trim(),
      name: form.name.trim(),
      cidr: form.cidr.trim(),
      vlan_id: Number(form.vlan_id),
    };
  if (props.kind === "pools")
    return {
      node_id: form.node_id.trim(),
      vpc_id: form.vpc_id.trim(),
      name: form.name.trim(),
      cidr: form.cidr.trim(),
      gateway: form.gateway.trim(),
      addresses: form.addresses.split(/[\s,，]+/).filter(Boolean),
      enabled: true,
    };
  return {
    pool_id: form.pool_id.trim(),
    instance_id: form.instance_id.trim(),
    owner_ref: form.owner_ref.trim(),
    address: form.address.trim(),
  };
}
async function save() {
  if (blocked.value || !session.can("nodes.manage")) return;
  const body = payload(),
    kind = props.kind,
    key = key32(),
    ticket = generation,
    epoch = session.epoch.value;
  draftError.value = "";
  const common =
    kind === "leases" ||
    (typeof body.name === "string" &&
      [...body.name].length >= 1 &&
      [...body.name].length <= 80 &&
      typeof body.node_id === "string" &&
      nodes.value.some((n) => n.id === body.node_id) &&
      typeof body.cidr === "string" &&
      /^\d+\.\d+\.\d+\.\d+\/(?:[0-9]|[12][0-9]|3[0-2])$/.test(body.cidr));
  const valid =
    common &&
    (kind === "vpcs"
      ? networkID(body.owner_ref) &&
        Number.isInteger(body.vlan_id) &&
        Number(body.vlan_id) >= 1 &&
        Number(body.vlan_id) <= 4094
      : kind === "pools"
        ? (body.vpc_id === "" || networkID(body.vpc_id)) &&
          ipv4(body.gateway) &&
          Array.isArray(body.addresses) &&
          body.addresses.length > 0 &&
          body.addresses.length <= 4096 &&
          body.addresses.every(ipv4) &&
          new Set(body.addresses).size === body.addresses.length
        : networkID(body.pool_id) &&
          networkID(body.instance_id) &&
          networkID(body.owner_ref) &&
          (body.address === "" || ipv4(body.address)));
  if (!valid) {
    draftError.value = "invalid";
    return;
  }
  intent.value = structuredClone(body);
  const result = await mutation.execute(
    "POST",
    `/networks/${kind}`,
    body,
    (v): v is Record<string, unknown> =>
      record(v) &&
      v.replay === false &&
      matchesNetworkIntent(
        kind,
        v[networkField(kind)],
        mutation.pendingKey.value,
        body,
      ),
    {
      key,
      expectedStatus: 201,
      isCurrent: () =>
        ticket === generation &&
        epoch === session.epoch.value &&
        props.open &&
        kind === props.kind &&
        session.can("nodes.manage"),
    },
  );
  if (
    result &&
    ticket === generation &&
    epoch === session.epoch.value &&
    props.open &&
    kind === props.kind &&
    session.can("nodes.manage")
  ) {
    notify(
      tr(
        "配置已保存，尚未应用到节点。",
        "Configuration saved; not yet applied to a node.",
      ),
    );
    emit("saved");
    emit("close");
  }
}
async function inspect() {
  const key = mutation.pendingKey.value,
    body = intent.value,
    owner = session.user.value?.id,
    kind = props.kind;
  if (!key || !body || !owner || reading.value) return;
  const epoch = session.epoch.value,
    ticket = generation;
  reading.value = true;
  try {
    const result = await api.get(
      `/networks/${kind}/${key}`,
      (v): v is Record<string, unknown> =>
        record(v) &&
        matchesNetworkIntent(kind, v[networkField(kind)], key, body),
    );
    if (epoch !== session.epoch.value || ticket !== generation || !props.open)
      return;
    if (
      !(await acknowledgeNetwork(
        owner,
        kind,
        body,
        key,
        result[networkField(kind)],
        () =>
          epoch === session.epoch.value &&
          ticket === generation &&
          props.open &&
          kind === props.kind &&
          owner === session.user.value?.id &&
          session.can("nodes.read"),
      ))
    )
      throw new ApiError("unavailable");
    if (epoch !== session.epoch.value || ticket !== generation || !props.open)
      return;
    mutation.clearMessage();
    notify(tr("已找到原记录。", "Original record confirmed."));
    emit("saved");
    emit("close");
  } catch (cause) {
    if (epoch === session.epoch.value && ticket === generation) {
      optionError.value = cause instanceof ApiError ? cause.kind : "network";
      if (cause instanceof ApiError && cause.kind === "unauthorized")
        session.invalidate();
    }
  } finally {
    reading.value = false;
  }
}
</script>
<template>
  <UiOverlay
    :open="open"
    :title="title"
    :busy="mutation.busy.value || reading"
    :close-label="tr('关闭', 'Close')"
    @close="emit('close')"
  >
    <p class="network-note">
      {{
        tr(
          "保存后为待应用状态。应用成功前，实例网络不会生效；未确认解除绑定的地址会保持预留。",
          "Saved configuration remains pending application. Connectivity is not confirmed until application succeeds; addresses remain reserved until detachment is confirmed.",
        )
      }}
    </p>
    <InlineError :error="optionError" />
    <UiButton
      v-if="optionError && !mutation.pendingKey.value"
      :busy="optionsBusy"
      @click="loadOptions"
      >{{ tr("重新加载选项", "Reload options") }}</UiButton
    >
    <form
      id="network-create-form"
      class="network-form"
      novalidate
      @submit.prevent="save"
    >
      <label v-if="kind !== 'leases'" class="field"
        >{{ tr("名称", "Name")
        }}<input
          v-model="form.name"
          required
          maxlength="100"
          :disabled="blocked"
      /></label>
      <label v-if="kind !== 'leases'" class="field"
        >{{ tr("计算节点", "Compute node")
        }}<UiSelect
          v-model="form.node_id"
          :options="nodeOptions"
          :label="tr('计算节点', 'Compute node')"
          :disabled="blocked || optionsBusy"
          :placeholder="tr('选择已配置节点', 'Select an approved node')"
      /></label>
      <label v-if="kind !== 'pools'" class="field"
        >{{ tr("客户归属 ID", "Customer owner ID")
        }}<input
          v-model="form.owner_ref"
          required
          pattern="[a-f0-9]{32}"
          maxlength="32"
          :disabled="blocked"
          autocomplete="off"
      /></label>
      <label v-if="kind === 'pools'" class="field"
        >{{ tr("所属网络", "Network")
        }}<UiSelect
          v-model="form.vpc_id"
          :options="objectOptions"
          :label="tr('所属网络', 'Network')"
          :disabled="blocked || optionsBusy"
      /></label>
      <label v-if="kind !== 'leases'" class="field"
        >{{ tr("IPv4 网段（CIDR）", "IPv4 subnet (CIDR)")
        }}<input
          v-model="form.cidr"
          required
          placeholder="10.20.0.0/24"
          :disabled="blocked"
          autocomplete="off"
      /></label>
      <label v-if="kind === 'vpcs'" class="field"
        >VLAN ID<input
          v-model="form.vlan_id"
          type="number"
          min="1"
          max="4094"
          required
          :disabled="blocked"
      /></label>
      <template v-if="kind === 'pools'">
        <label class="field"
          >{{ tr("网关", "Gateway")
          }}<input
            v-model="form.gateway"
            required
            :disabled="blocked"
            autocomplete="off"
        /></label>
        <label class="field"
          >{{ tr("可分配地址，每行一个", "Assignable addresses, one per line")
          }}<textarea
            v-model="form.addresses"
            required
            rows="5"
            :disabled="blocked"
            spellcheck="false"
          />
        </label>
        <p class="secondary">
          {{
            tr(
              "最多 4096 个地址，不包含网关、网络地址和广播地址。",
              "Up to 4096 addresses; exclude gateway, network and broadcast addresses.",
            )
          }}
        </p>
      </template>
      <template v-if="kind === 'leases'">
        <label class="field"
          >{{ tr("IP 地址池", "IP pool")
          }}<UiSelect
            v-model="form.pool_id"
            :options="objectOptions"
            :label="tr('IP 地址池', 'IP pool')"
            :disabled="blocked || optionsBusy"
        /></label>
        <label class="field"
          >{{ tr("实例 ID", "Instance ID")
          }}<input
            v-model="form.instance_id"
            required
            pattern="[a-f0-9]{32}"
            maxlength="32"
            :disabled="blocked"
            autocomplete="off"
        /></label>
        <label class="field"
          >{{ tr("指定地址（可选）", "Specific address (optional)")
          }}<input
            v-model="form.address"
            :disabled="blocked"
            :placeholder="
              tr(
                '留空则分配第一个可用地址',
                'Leave blank for the first available address',
              )
            "
            autocomplete="off"
        /></label>
      </template>
    </form>
    <InlineError :error="draftError" />
    <InlineError
      :error="mutation.error.value"
      :pending-key="mutation.pendingKey.value"
    />
    <UiButton
      v-if="mutation.pendingKey.value"
      :busy="reading"
      @click="inspect"
      >{{ tr("只读核对原记录", "Read original record") }}</UiButton
    >
    <template #footer
      ><UiButton
        :disabled="mutation.busy.value || reading"
        @click="emit('close')"
        >{{ tr("取消", "Cancel") }}</UiButton
      ><UiButton
        type="submit"
        form="network-create-form"
        variant="primary"
        :busy="mutation.busy.value"
        :disabled="
          blocked ||
          optionsBusy ||
          !!optionError ||
          !session.can('nodes.manage')
        "
        >{{ tr("保存", "Save") }}</UiButton
      ></template
    >
  </UiOverlay>
</template>
<style scoped>
.network-form {
  display: grid;
  gap: 18px;
  margin-top: 20px;
}
.network-note {
  color: var(--secondary);
  font-size: 13px;
  line-height: 1.7;
  margin: 0 0 16px;
}
.network-form textarea {
  font: inherit;
  min-height: 120px;
  width: 100%;
  resize: vertical;
  border: 1px solid var(--control-border);
  border-radius: 6px;
  padding: 12px;
  background: var(--surface);
  color: var(--text);
}
.network-form .secondary {
  margin: -8px 0 0;
  font-size: 12px;
  line-height: 1.7;
}
</style>
