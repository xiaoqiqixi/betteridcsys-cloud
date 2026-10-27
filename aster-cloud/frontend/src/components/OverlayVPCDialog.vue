<script setup lang="ts">
import { computed, onScopeDispose, reactive, shallowRef, watch } from "vue";
import { useRoute } from "vue-router";
import { ApiError, key32, record } from "../api/client";
import {
  matchesVPC,
  validOverlayVPCInput,
  type OverlayVPC,
  type OverlayVPCInput,
} from "../api/overlay";
import { useConsole } from "../context";
import { useOverlayMutation } from "../composables/overlay-mutation";
import UiSelect from "./UiSelect.vue";
import UiOverlay from "./UiOverlay.vue";
import UiButton from "./UiButton.vue";
import InlineError from "./InlineError.vue";
const props = defineProps<{ cluster: string; approvedIds: string[] }>(),
  emit = defineEmits<{ close: []; saved: [] }>();
const {
    api,
    session,
    notify,
    prefs: { tr },
  } = useConsole(),
  route = useRoute(),
  mutation = useOverlayMutation(() => `vpc:${props.cluster}`);
const form = reactive({
    id: props.approvedIds[0] || "new",
    name: "",
    owner_ref: "",
    cidr: "",
    vni: "",
  }),
  error = shallowRef(""),
  reading = shallowRef(false),
  intent = shallowRef<OverlayVPCInput | null>(null);
let generation = 0;
if (
  mutation.pending.value &&
  validOverlayVPCInput(mutation.pending.value.body)
) {
  intent.value = mutation.pending.value.body;
  Object.assign(form, intent.value, {
    id: mutation.pending.value.key,
    vni: String(intent.value.vni),
  });
}
const blocked = computed(
  () =>
    mutation.busy.value ||
    !!mutation.pendingKey.value ||
    reading.value ||
    !session.can("nodes.manage"),
);
const current = (ticket: number, identity: number) =>
  ticket === generation &&
  identity === session.epoch.value &&
  session.can("nodes.manage");
watch(
  [() => props.cluster, () => route.fullPath, session.epoch],
  () => {
    generation++;
    emit("close");
  },
  { flush: "sync" },
);
onScopeDispose(() => generation++);
async function save() {
  if (blocked.value) return;
  const body = {
    cluster_id: props.cluster,
    owner_ref: form.owner_ref.trim(),
    name: form.name.trim(),
    cidr: form.cidr.trim(),
    vni: Number(form.vni),
  };
  error.value = "";
  if (
    !validOverlayVPCInput(body) ||
    (form.id !== "new" && !props.approvedIds.includes(form.id))
  ) {
    error.value = "invalid";
    return;
  }
  const key = form.id === "new" ? key32() : form.id,
    ticket = generation,
    identity = session.epoch.value;
  intent.value = body;
  const result = await mutation.execute(
    "/overlays/vpcs",
    body,
    (v, key): v is { vpc: OverlayVPC; replay: boolean } =>
      record(v) && v.replay === false && matchesVPC(v.vpc, key, body),
    () => current(ticket, identity),
    { key, status: 201 },
  );
  if (!result || !current(ticket, identity)) return;
  notify(
    tr(
      "VPC 已创建。添加实例并应用网络配置后生效。",
      "VPC created. Add members and apply network configuration to activate it.",
    ),
  );
  emit("saved");
  emit("close");
}
async function inspect() {
  const key = mutation.pendingKey.value,
    body = intent.value,
    ticket = generation,
    identity = session.epoch.value;
  if (!key || !body || reading.value) return;
  reading.value = true;
  error.value = "";
  try {
    await api.get(
      `/overlays/vpcs/${key}`,
      (v): v is { vpc: OverlayVPC } =>
        record(v) && matchesVPC(v.vpc, key, body),
    );
    if (
      !current(ticket, identity) ||
      !mutation.acknowledge(key, () => current(ticket, identity))
    )
      return;
    notify(
      tr(
        "已核对原 VPC 记录，无需再次创建。",
        "Original VPC confirmed. Do not create it again.",
      ),
    );
    emit("saved");
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
    :title="tr('新建 VPC', 'New VPC')"
    :busy="mutation.busy.value || reading"
    :close-label="tr('关闭', 'Close')"
    @close="emit('close')"
  >
    <p class="secondary">
      {{
        tr(
          "同一 VPC 内的实例可跨计算节点通信。客户归属和网段创建后保持不变。",
          "Members of a VPC can communicate across compute nodes. Ownership and subnet stay fixed after creation.",
        )
      }}
    </p>
    <form
      id="overlay-vpc-form"
      class="vpc-form"
      novalidate
      @submit.prevent="save"
    >
      <label class="field"
        >{{ tr("网络标识", "Network identity")
        }}<UiSelect
          v-model="form.id"
          :options="[
            {
              value: 'new',
              label: tr('创建新网络标识', 'Create a new network identity'),
            },
            ...approvedIds.map((id, index) => ({
              value: id,
              label: `${tr('已批准网络', 'Approved network')} ${index + 1} · ${id.slice(-8)}`,
            })),
          ]"
          :disabled="blocked"
          :label="tr('网络标识', 'Network identity')"
        /><span class="field-note">{{
          form.id === "new"
            ? tr(
                "创建后尚未映射节点。添加实例前，请在主控与节点配置中批准对应的网络映射。",
                "The new VPC will have no node mappings. Approve its mapping in controller and node configuration before adding instances.",
              )
            : form.id
        }}</span></label
      >
      <label class="field"
        >{{ tr("名称", "Name")
        }}<input
          v-model="form.name"
          maxlength="80"
          required
          :disabled="blocked"
          autocomplete="off"
          placeholder="Production network"
      /></label>
      <label class="field"
        >{{ tr("客户归属 ID", "Customer owner ID")
        }}<input
          v-model="form.owner_ref"
          required
          maxlength="32"
          :disabled="blocked"
          autocomplete="off"
        /><span class="field-note">{{
          tr(
            "与实例的客户归属保持一致。",
            "Must match the customer ownership of the instances.",
          )
        }}</span></label
      >
      <div class="vpc-row">
        <label class="field"
          >{{ tr("IPv4 网段", "IPv4 subnet")
          }}<input
            v-model="form.cidr"
            required
            placeholder="10.20.0.0/24"
            :disabled="blocked"
            autocomplete="off" /></label
        ><label class="field"
          >VNI<input
            v-model="form.vni"
            type="number"
            min="1"
            max="16777215"
            required
            :disabled="blocked"
          /><span class="field-note">{{
            tr(
              "集群内唯一，范围 1–16777215。",
              "Unique within the cluster, 1–16777215.",
            )
          }}</span></label
        >
      </div>
    </form>
    <InlineError
      :error="error || mutation.error.value"
      :pending-key="mutation.pendingKey.value"
    /><UiButton
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
        variant="primary"
        form="overlay-vpc-form"
        type="submit"
        :busy="mutation.busy.value"
        :disabled="blocked"
        >{{ tr("创建 VPC", "Create VPC") }}</UiButton
      ></template
    >
  </UiOverlay>
</template>
<style scoped>
.vpc-form {
  display: grid;
  gap: 20px;
  margin-top: 24px;
}
.vpc-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}
@media (max-width: 420px) {
  .vpc-row {
    grid-template-columns: 1fr;
  }
}
</style>
