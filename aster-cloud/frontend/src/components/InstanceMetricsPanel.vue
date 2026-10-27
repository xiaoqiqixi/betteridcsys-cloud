<script setup lang="ts">
import { computed, onScopeDispose, shallowRef, watch } from "vue";
import { Activity } from "@lucide/vue";
import type { Instance, InstanceMetrics } from "../api/types";
import { ApiError, metricObservedNanos, metricsResponse } from "../api/client";
import { useConsole } from "../context";
import {
  metricCounter,
  metricCPUTime,
  metricTimeText,
} from "../metrics-format";
import UiButton from "./UiButton.vue";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{ instance: Instance }>();
const {
  api,
  session,
  prefs: { tr, locale },
} = useConsole();
const metrics = shallowRef<InstanceMetrics | null>(null),
  loading = shallowRef(false),
  error = shallowRef(""),
  expired = shallowRef(false);
const canRead = computed(() => session.can("instances.read"));
const binding = computed(() =>
  JSON.stringify([
    props.instance.id,
    props.instance.node_id,
    props.instance.owner_ref,
    props.instance.hostname,
    props.instance.resources.cpu_cores,
  ]),
);
let sequence = 0,
  abort: AbortController | undefined,
  expiry: ReturnType<typeof setTimeout> | undefined;
function reset() {
  sequence++;
  abort?.abort();
  clearTimeout(expiry);
  metrics.value = null;
  loading.value = false;
  expired.value = false;
  error.value = "";
}
watch([binding, session.epoch, () => session.user.value?.id, canRead], reset, {
  flush: "sync",
});
onScopeDispose(reset);

async function read() {
  if (loading.value || !canRead.value) return;
  reset();
  abort = new AbortController();
  const ticket = sequence,
    identity = session.epoch.value,
    expected = binding.value,
    isCurrent = () =>
      ticket === sequence &&
      identity === session.epoch.value &&
      expected === binding.value &&
      canRead.value;
  loading.value = true;
  try {
    const result = await api.get(
      `/instances/${encodeURIComponent(props.instance.id)}/metrics`,
      metricsResponse(props.instance),
      abort.signal,
    );
    if (!isCurrent()) return;
    const observed = metricObservedNanos(result.metrics.observed_at);
    if (observed === null) throw new ApiError("invalid");
    const age = BigInt(Date.now()) * 1000000n - observed;
    // Reject old/future responses on receipt, then locally expire an accepted
    // sample. The timer changes only its label; it never polls the node.
    if (age > 60000000000n || age < -5000000000n) throw new ApiError("invalid");
    metrics.value = result.metrics;
    expiry = setTimeout(
      () => {
        if (isCurrent()) expired.value = true;
      },
      Number((60000000000n - age) / 1000000n) + 1,
    );
  } catch (cause) {
    if (!isCurrent()) return;
    error.value = cause instanceof ApiError ? cause.kind : "network";
    if (cause instanceof ApiError && cause.kind === "unauthorized")
      session.invalidate();
  } finally {
    if (ticket === sequence) loading.value = false;
  }
}
const errorText = computed(() => {
  if (error.value === "forbidden")
    return tr(
      "你没有读取实例监控的权限。",
      "You do not have permission to read instance metrics.",
    );
  if (error.value === "conflict")
    return tr(
      "实例正在操作或暂时无法采样，请稍后重新读取。",
      "The instance is busy or cannot be sampled. Read it again later.",
    );
  if (error.value === "invalid")
    return tr(
      "无法确认本次监控数据，请重新读取。",
      "This sample could not be verified. Read the metrics again.",
    );
  return tr(
    "本次监控读取失败，请检查连接后重新读取。",
    "Metrics could not be read. Check your connection and read them again.",
  );
});
</script>

<template>
  <section
    class="metrics-panel"
    :aria-label="tr('资源监控', 'Resource monitoring')"
    :aria-busy="loading || undefined"
  >
    <header class="metrics-header">
      <div class="metrics-heading">
        <Activity :size="19" aria-hidden="true" />
        <h2>{{ tr("资源监控", "Resource monitoring") }}</h2>
        <span
          class="sample-state"
          :class="{ 'is-expired': expired }"
          role="status"
          >{{
            loading
              ? tr("正在读取", "Reading")
              : metrics
                ? expired
                  ? tr("采样已过期", "Sample expired")
                  : tr("本次采样", "Latest sample")
                : tr("未采样", "Not sampled")
          }}</span
        >
      </div>
      <UiButton :busy="loading" :disabled="!canRead" @click="read">{{
        tr("读取监控", "Read metrics")
      }}</UiButton>
    </header>

    <p v-if="error" class="metrics-error" role="alert">{{ errorText }}</p>
    <div v-else-if="loading" class="metrics-skeleton" aria-hidden="true">
      <span v-for="item in 4" :key="item" />
    </div>
    <template v-else-if="metrics">
      <div class="sample-meta">
        <span>{{ tr("采样时间", "Observed at") }}</span>
        <time :datetime="metrics.observed_at" :title="metrics.observed_at">{{
          metricTimeText(metrics.observed_at, locale)
        }}</time>
        <StatusBadge :state="metrics.state" />
      </div>
      <p v-if="expired" class="metrics-expired" role="status">
        {{
          tr(
            "以下为上次采样数据，已超过 60 秒。请重新读取以查看当前数据。",
            "This is the previous sample, now over 60 seconds old. Read it again for current data.",
          )
        }}
      </p>
      <div class="metrics-grid">
        <section class="metric-group">
          <h3>{{ tr("CPU", "CPU") }}</h3>
          <dl>
            <div>
              <dt>{{ tr("累计 CPU 时间", "Cumulative CPU time") }}</dt>
              <dd>{{ metricCPUTime(metrics.cpu_time_ns, locale) }}</dd>
            </div>
            <div>
              <dt>{{ tr("虚拟处理器", "Virtual processors") }}</dt>
              <dd>{{ metrics.vcpus }} vCPU</dd>
            </div>
          </dl>
        </section>
        <section class="metric-group">
          <h3>{{ tr("内存", "Memory") }}</h3>
          <dl>
            <div>
              <dt>{{ tr("驻留内存（RSS）", "Resident memory (RSS)") }}</dt>
              <dd>
                {{ metricCounter(metrics.memory_rss_kib, "KiB", locale) }}
              </dd>
            </div>
            <div>
              <dt>{{ tr("当前分配内存", "Current memory allocation") }}</dt>
              <dd>
                {{ metricCounter(metrics.memory_actual_kib, "KiB", locale) }}
              </dd>
            </div>
            <div>
              <dt>{{ tr("客户机报告空闲", "Guest-reported unused") }}</dt>
              <dd>
                {{ metricCounter(metrics.memory_unused_kib, "KiB", locale) }}
              </dd>
            </div>
          </dl>
        </section>
        <section class="metric-group">
          <h3>{{ tr("系统盘 I/O", "System disk I/O") }}</h3>
          <dl>
            <div>
              <dt>{{ tr("累计读取", "Cumulative read") }}</dt>
              <dd>
                {{ metricCounter(metrics.block_read_bytes, "B", locale) }}
              </dd>
            </div>
            <div>
              <dt>{{ tr("累计写入", "Cumulative write") }}</dt>
              <dd>
                {{ metricCounter(metrics.block_write_bytes, "B", locale) }}
              </dd>
            </div>
          </dl>
        </section>
        <section class="metric-group">
          <h3>{{ tr("网络 I/O", "Network I/O") }}</h3>
          <dl>
            <div>
              <dt>{{ tr("累计接收", "Cumulative receive") }}</dt>
              <dd>
                {{ metricCounter(metrics.network_receive_bytes, "B", locale) }}
              </dd>
            </div>
            <div>
              <dt>{{ tr("累计发送", "Cumulative transmit") }}</dt>
              <dd>
                {{ metricCounter(metrics.network_transmit_bytes, "B", locale) }}
              </dd>
            </div>
          </dl>
        </section>
      </div>
      <p class="metrics-hint">
        {{
          tr(
            "采样不会自动刷新。累计计数可能在重启后重置；网络计数不是账单流量，RSS 也不是客户机内存使用率。",
            "Samples do not refresh automatically. Counters may reset after a restart. Network counters are not billed transfer, and RSS is not guest memory utilization.",
          )
        }}
      </p>
    </template>
    <p v-else class="metrics-hint">
      {{
        canRead
          ? tr(
              "按需读取实例的 CPU、内存、系统盘与网络采样，不会自动刷新。",
              "Read CPU, memory, system disk and network samples when needed. They do not refresh automatically.",
            )
          : tr(
              "你没有读取实例监控的权限。",
              "You do not have permission to read instance metrics.",
            )
      }}
    </p>
  </section>
</template>

<style scoped>
.metrics-panel {
  padding: 20px 0;
  margin-bottom: 24px;
  background: var(--surface);
  border: 0;
  border-radius: 0;
  min-width: 0;
  border-block: 1px solid var(--border);
}
.metrics-header,
.metrics-heading,
.sample-meta {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}
.metrics-header {
  justify-content: space-between;
  gap: 16px;
}
.metrics-heading > svg {
  color: var(--secondary);
  flex-shrink: 0;
}
.metrics-heading h2 {
  font-size: 15px;
  font-weight: 600;
  margin: 0;
}
.sample-state {
  font-size: 12px;
  color: var(--secondary);
  padding: 5px 8px;
  background: var(--subtle);
  border-radius: 7px;
}
.sample-state.is-expired {
  color: var(--warning);
  background: var(--warning-bg);
}
.sample-meta {
  font-size: 12px;
  color: var(--secondary);
  margin-top: 20px;
  line-height: 1.7;
}
.sample-meta time {
  overflow-wrap: anywhere;
}
.metrics-grid,
.metrics-skeleton {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 20px 28px;
  margin-top: 20px;
}
.metric-group {
  min-width: 0;
  border-top: 1px solid var(--border);
  padding-top: 16px;
}
.metric-group h3 {
  margin: 0 0 14px;
  font-size: 14px;
  font-weight: 600;
}
.metric-group dl {
  margin: 0;
}
.metric-group dl > div {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-top: 10px;
  font-size: 14px;
  line-height: 1.7;
}
.metric-group dt {
  color: var(--secondary);
  min-width: 0;
  flex: 1;
}
.metric-group dd {
  margin: 0;
  min-width: 0;
  flex: 1.15;
  text-align: right;
  overflow-wrap: anywhere;
  font-variant-numeric: tabular-nums;
}
.metrics-hint {
  font-size: 12px;
  line-height: 1.7;
  color: var(--secondary);
  margin: 20px 0 0;
}
.metrics-error,
.metrics-expired {
  color: var(--warning);
  background: var(--warning-bg);
  padding: 12px 14px;
  border-radius: 6px;
  font-size: 13px;
  line-height: 1.7;
  margin: 20px 0 0;
}
.metrics-skeleton span {
  display: block;
  background: var(--skeleton);
  border-radius: 7px;
  height: 36px;
}
@media (max-width: 600px) {
  .metrics-panel {
    padding: 20px;
  }
  .metrics-header {
    align-items: flex-start;
  }
  .metrics-grid,
  .metrics-skeleton {
    grid-template-columns: 1fr;
    gap: 20px;
  }
  .metric-group dl > div {
    flex-wrap: wrap;
  }
}
@media (max-width: 600px) {
  .metrics-panel {
    padding: 18px 0;
  }
}
</style>
