<script setup lang="ts">
import { onScopeDispose, shallowRef, watch } from "vue";
import { Radio, ShieldAlert } from "@lucide/vue";
import type { Instance, InstanceObservation } from "../api/types";
import { ApiError, observationResponse } from "../api/client";
import { useConsole } from "../context";
import { dateText } from "../format";
import UiButton from "./UiButton.vue";
import StatusBadge from "./StatusBadge.vue";
const props = defineProps<{ instance: Instance }>();
const {
  api,
  session,
  prefs: { tr, locale },
} = useConsole();
const observation = shallowRef<InstanceObservation | null>(null),
  loading = shallowRef(false),
  error = shallowRef("");
let sequence = 0,
  abort: AbortController | undefined;
function reset() {
  sequence++;
  abort?.abort();
  observation.value = null;
  loading.value = false;
  error.value = "";
}
watch(
  [() => props.instance.id, () => props.instance.node_id, session.epoch],
  reset,
);
onScopeDispose(reset);
async function read() {
  if (loading.value) return;
  abort?.abort();
  abort = new AbortController();
  const ticket = ++sequence,
    identity = session.epoch.value;
  loading.value = true;
  observation.value = null;
  error.value = "";
  try {
    const result = await api.get(
      `/instances/${encodeURIComponent(props.instance.id)}/observation`,
      observationResponse,
      abort.signal,
    );
    if (ticket !== sequence || identity !== session.epoch.value) return;
    const value = result.observation;
    if (
      value.instance_id !== props.instance.id ||
      value.node_id !== props.instance.node_id ||
      value.owner_ref !== props.instance.owner_ref ||
      value.hostname !== props.instance.hostname
    )
      throw new ApiError("invalid");
    observation.value = value;
  } catch (cause) {
    if (ticket !== sequence || identity !== session.epoch.value) return;
    error.value = cause instanceof ApiError ? cause.kind : "network";
    if (cause instanceof ApiError && cause.kind === "unauthorized")
      session.invalidate();
  } finally {
    if (ticket === sequence) loading.value = false;
  }
}
</script>
<template>
  <section
    class="observation-panel"
    :aria-label="tr('当前实例状态', 'Current instance state')"
  >
    <header>
      <div class="observation-heading">
        <Radio :size="19" aria-hidden="true" />
        <h2>{{ tr("当前状态", "Current state") }}</h2>
        <StatusBadge v-if="observation" :state="observation.state" /><span
          v-else
          class="unconfirmed"
          role="status"
          >{{
            loading ? tr("正在读取", "Reading") : tr("未确认", "Unconfirmed")
          }}</span
        >
      </div>
      <UiButton :busy="loading" @click="read">{{
        tr("读取当前状态", "Read current state")
      }}</UiButton>
    </header>
    <p v-if="error" class="observation-error" role="alert">
      {{
        error === "conflict"
          ? tr(
              "实例正在操作或状态无法确认，请稍后再次读取。",
              "An operation is in progress or the state cannot be confirmed. Read it again later.",
            )
          : tr(
              "本次读取未能确认实例状态，请检查连接后再次读取。",
              "This read could not confirm the instance state. Check the connection and read it again.",
            )
      }}
    </p>
    <dl v-if="observation" class="observation-data">
      <div>
        <dt>{{ tr("IPv4 地址", "IPv4 address") }}</dt>
        <dd>{{ observation.ipv4 || "—" }}</dd>
      </div>
      <div>
        <dt>{{ tr("网卡地址", "MAC address") }}</dt>
        <dd>{{ observation.mac || "—" }}</dd>
      </div>
      <div>
        <dt>{{ tr("采样时间", "Observed at") }}</dt>
        <dd>{{ dateText(observation.observed_at, locale) }}</dd>
      </div>
    </dl>
    <p v-else-if="!error && !loading" class="observation-hint">
      {{
        tr(
          "按需读取节点当前状态，采样结果不会自动刷新。",
          "Read the current node state when needed. Observations do not refresh automatically.",
        )
      }}
    </p>
    <div
      v-if="observation?.source_fenced || observation?.target_pending"
      class="fence-notice"
      role="status"
    >
      <ShieldAlert :size="18" aria-hidden="true" />
      <div>
        <p v-if="observation.source_fenced">
          {{
            tr(
              "源实例已隔离，请保持隔离，避免源与目标同时启动。",
              "The source is fenced. Keep it fenced to prevent both instances from starting.",
            )
          }}
        </p>
        <p v-if="observation.target_pending">
          {{
            tr(
              "目标实例尚未激活。",
              "The target instance is not activated yet.",
            )
          }}
        </p>
      </div>
    </div>
  </section>
</template>
<style scoped>
.observation-panel {
  padding: 20px 0;
  margin: 0 0 28px;
  background: var(--surface);
  border: 0;
  border-radius: 0;
  min-width: 0;
  border-block: 1px solid var(--border);
}
.observation-panel > header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
.observation-heading {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.observation-heading > svg {
  color: var(--secondary);
  flex-shrink: 0;
}
.observation-heading h2 {
  font-size: 15px;
  font-weight: 600;
  margin: 0;
}
.unconfirmed {
  font-size: 12px;
  color: var(--secondary);
  padding: 5px 8px;
  background: var(--subtle);
  border-radius: 7px;
}
.observation-hint {
  font-size: 12px;
  color: var(--secondary);
  margin: 16px 0 0;
  line-height: 1.7;
}
.observation-error {
  color: var(--warning);
  background: var(--warning-bg);
  padding: 12px 14px;
  border-radius: 6px;
  font-size: 13px;
  line-height: 1.7;
  margin: 20px 0 0;
}
.observation-data {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 18px;
  margin: 20px 0 0;
}
.observation-data dt {
  font-size: 12px;
  color: var(--secondary);
  margin-bottom: 8px;
}
.observation-data dd {
  font-size: 14px;
  line-height: 1.6;
  overflow-wrap: anywhere;
  margin: 0;
}
.fence-notice {
  display: flex;
  gap: 10px;
  align-items: flex-start;
  padding: 14px;
  margin-top: 20px;
  color: var(--warning);
  background: var(--warning-bg);
  border-radius: 6px;
}
.fence-notice > svg {
  margin-top: 3px;
  flex-shrink: 0;
}
.fence-notice p {
  margin: 0;
  font-size: 13px;
  line-height: 1.7;
}
.fence-notice p + p {
  margin-top: 6px;
}
@media (max-width: 600px) {
  .observation-panel {
    padding: 20px;
  }
  .observation-data {
    grid-template-columns: 1fr;
    gap: 16px;
  }
  .observation-panel > header {
    align-items: flex-start;
  }
  .observation-panel > header > .ui-button {
    font-size: 13px;
  }
}
@media (max-width: 600px) {
  .observation-panel {
    padding: 18px 0;
  }
}
</style>
