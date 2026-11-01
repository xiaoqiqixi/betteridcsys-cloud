<script setup lang="ts">
import { computed, shallowRef, watch, useId } from "vue";
import { RouterLink } from "vue-router";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { useMutation } from "../composables/mutation";
import {
  trafficCounter,
  trafficGiB,
  validTraffic,
  type TrafficPolicy,
} from "../api/traffic";
import { dateText } from "../format";
import UiButton from "./UiButton.vue";
import UiSelect from "./UiSelect.vue";
import StateBlock from "./StateBlock.vue";
import InlineError from "./InlineError.vue";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{ instanceId: string }>();
const {
  prefs: { tr, locale },
  session,
  notify,
} = useConsole();
const titleId = useId();
const query = useQuery(
  () => `/instances/${encodeURIComponent(props.instanceId)}/traffic`,
  validTraffic,
);
const mutation = useMutation();
const draft = shallowRef<TrafficPolicy | null>(null);
const editing = shallowRef(false);
const bytes = shallowRef("");
const mode = shallowRef("none");
const throttle = shallowRef("10");
watch(
  () => props.instanceId,
  () => {
    draft.value = null;
    editing.value = false;
  },
);
const directions = computed(() => [
  { value: "in", label: tr("入站", "Inbound") },
  { value: "out", label: tr("出站", "Outbound") },
  { value: "both", label: tr("双向合计", "Both directions") },
]);
const policies = computed(() => [
  { value: "none", label: tr("仅记录", "Record only") },
  {
    value: "throttle",
    label: tr("限速", "Throttle"),
    disabled: !query.data.value?.throttle_supported,
  },
  {
    value: "suspend",
    label: tr("暂停实例", "Suspend"),
    disabled: !query.data.value?.suspend_supported,
  },
]);
const writable = computed(
  () =>
    session.can("instances.manage") &&
    query.data.value?.accounting_supported &&
    !mutation.pendingKey.value,
);
const valid = computed(
  () =>
    draft.value &&
    draft.value.reset_day >= 1 &&
    draft.value.reset_day <= 31 &&
    Number.isInteger(draft.value.reset_day) &&
    (bytes.value === "" || trafficCounter(bytes.value)) &&
    (mode.value === "none" || bytes.value !== "") &&
    (mode.value !== "throttle" ||
      (/^[1-9][0-9]*$/.test(throttle.value) &&
        Number(throttle.value) <= 100000)),
);
function edit() {
  const p = query.data.value?.policy;
  if (!p) return;
  draft.value = { ...p };
  bytes.value = p.limit_bytes ?? "";
  mode.value = p.overage_policy.startsWith("throttle:")
    ? "throttle"
    : p.overage_policy;
  throttle.value = p.overage_policy.split(":")[1] ?? "10";
  editing.value = true;
}
function resetDay(event: Event) {
  if (draft.value)
    draft.value = {
      ...draft.value,
      reset_day: Number((event.target as HTMLInputElement).value),
    };
}
function direction(value: string) {
  if (draft.value)
    draft.value = {
      ...draft.value,
      direction: value as TrafficPolicy["direction"],
    };
}
async function save() {
  if (!draft.value || !valid.value || !writable.value || mutation.busy.value)
    return;
  const policy = {
    ...draft.value,
    limit_bytes: bytes.value || null,
    overage_policy:
      mode.value === "throttle" ? `throttle:${throttle.value}` : mode.value,
  };
  const result = await mutation.execute(
    "POST",
    `/instances/${encodeURIComponent(props.instanceId)}/traffic`,
    policy,
    (x): x is import("../api/traffic").TrafficView =>
      validTraffic(x) &&
      x.policy.reset_day === policy.reset_day &&
      x.policy.direction === policy.direction &&
      x.policy.limit_bytes === policy.limit_bytes &&
      x.policy.overage_policy === policy.overage_policy,
  );
  if (result) {
    editing.value = false;
    notify(tr("流量策略已保存。", "Traffic policy saved."));
    await query.reload();
  }
}
function rate(value: number) {
  return value ? `${value} Mbps` : tr("不限速", "Unlimited");
}
</script>
<template>
  <section class="content-section traffic-panel" :aria-labelledby="titleId">
    <div class="traffic-heading">
      <h2 :id="titleId">{{ tr("带宽与流量", "Bandwidth and traffic") }}</h2>
      <UiButton
        variant="quiet"
        :busy="query.loading.value"
        @click="query.reload"
        >{{ tr("刷新", "Refresh") }}</UiButton
      >
    </div>
    <StateBlock
      :loading="query.loading.value"
      :error="query.error.value"
      @reload="query.reload"
    >
      <template v-if="query.data.value">
        <dl class="traffic-grid">
          <div>
            <dt>{{ tr("入站带宽", "Inbound limit") }}</dt>
            <dd>{{ rate(query.data.value.inbound_mbps) }}</dd>
          </div>
          <div>
            <dt>{{ tr("出站带宽", "Outbound limit") }}</dt>
            <dd>{{ rate(query.data.value.outbound_mbps) }}</dd>
          </div>
          <div>
            <dt>{{ tr("本期入站", "Received this period") }}</dt>
            <dd>
              {{
                query.data.value.observed_at
                  ? trafficGiB(query.data.value.rx_bytes)
                  : "—"
              }}
            </dd>
          </div>
          <div>
            <dt>{{ tr("本期出站", "Sent this period") }}</dt>
            <dd>
              {{
                query.data.value.observed_at
                  ? trafficGiB(query.data.value.tx_bytes)
                  : "—"
              }}
            </dd>
          </div>
          <div>
            <dt>{{ tr("流量额度", "Traffic allowance") }}</dt>
            <dd>
              {{
                query.data.value.policy.limit_bytes === null
                  ? tr("不限量", "Unlimited")
                  : trafficGiB(query.data.value.policy.limit_bytes)
              }}
            </dd>
          </div>
          <div>
            <dt>{{ tr("统计方向", "Counted direction") }}</dt>
            <dd>
              {{
                directions.find(
                  (v) => v.value === query.data.value?.policy.direction,
                )?.label
              }}
            </dd>
          </div>
          <div>
            <dt>{{ tr("超额策略", "Overage policy") }}</dt>
            <dd>
              {{
                policies.find(
                  (v) =>
                    v.value ===
                    query.data.value?.policy.overage_policy.split(":")[0],
                )?.label
              }}<template
                v-if="
                  query.data.value.policy.overage_policy.startsWith('throttle:')
                "
              >
                ·
                {{ query.data.value.policy.overage_policy.split(":")[1] }}
                Mbps</template
              >
            </dd>
          </div>
          <div>
            <dt>{{ tr("重置日（UTC）", "Reset day (UTC)") }}</dt>
            <dd>{{ query.data.value.policy.reset_day }}</dd>
          </div>
        </dl>
        <p class="secondary">
          {{ dateText(query.data.value.period_start, locale) }} –
          {{ dateText(query.data.value.period_end, locale) }}
        </p>
        <p class="secondary">
          {{ tr("最近采样", "Last sample") }}:
          {{
            query.data.value.observed_at
              ? dateText(query.data.value.observed_at, locale)
              : tr("尚无采样", "No samples yet")
          }}
        </p>
        <p v-if="!query.data.value.accounting_supported" class="secondary">
          {{
            tr(
              "此节点未启用流量统计。",
              "Traffic accounting is not enabled on this node.",
            )
          }}
        </p>
        <p v-else-if="!query.data.value.throttle_supported" class="secondary">
          {{
            tr(
              "此网络不支持动态流量限速。",
              "Dynamic traffic throttling is unsupported on this network.",
            )
          }}
        </p>
        <p v-if="query.data.value.enforcement" class="traffic-enforcement">
          {{ tr("最近执行任务", "Latest enforcement") }}
          <RouterLink :to="`/operations/${query.data.value.enforcement.id}`">{{
            query.data.value.enforcement.id.slice(0, 8)
          }}</RouterLink>
          <StatusBadge :state="query.data.value.enforcement.state" />
        </p>
        <UiButton v-if="!editing && writable" variant="quiet" @click="edit">{{
          tr("编辑流量策略", "Edit traffic policy")
        }}</UiButton>
        <form
          v-if="editing && draft"
          class="traffic-form"
          @submit.prevent="save"
        >
          <label
            >{{ tr("重置日（1–31）", "Reset day (1–31)")
            }}<input
              type="number"
              min="1"
              max="31"
              :value="draft.reset_day"
              :disabled="query.data.value.reset_day_locked"
              @input="resetDay"
          /></label>
          <UiSelect
            :label="tr('统计方向', 'Counted direction')"
            :model-value="draft.direction"
            :options="directions"
            @update:model-value="direction"
          />
          <label
            >{{
              tr(
                "额度（字节，留空不限量）",
                "Allowance (bytes; blank for unlimited)",
              )
            }}<input v-model="bytes" inputmode="numeric"
          /></label>
          <UiSelect
            :label="tr('超额策略', 'Overage policy')"
            v-model="mode"
            :options="policies"
          />
          <label v-if="mode === 'throttle'"
            >{{ tr("超额后限速（Mbps）", "Overage rate (Mbps)")
            }}<input v-model="throttle" type="number" min="1" max="100000"
          /></label>
          <p class="secondary">
            {{
              tr(
                "有用量后不可更改重置日。新账期会解除流量限制；已暂停实例需手动启动。",
                "The reset day is fixed after usage begins. A new period clears traffic limits; suspended instances need an explicit start.",
              )
            }}
          </p>
          <div class="traffic-heading">
            <UiButton
              type="submit"
              :disabled="!valid || !writable"
              :busy="mutation.busy.value"
              >{{ tr("保存", "Save") }}</UiButton
            ><UiButton
              variant="quiet"
              :disabled="mutation.busy.value || !!mutation.pendingKey.value"
              @click="editing = false"
              >{{ tr("取消", "Cancel") }}</UiButton
            >
          </div>
        </form>
      </template>
    </StateBlock>
    <InlineError
      v-if="mutation.error.value || mutation.pendingKey.value"
      :error="mutation.error.value"
      :pending-key="mutation.pendingKey.value"
    />
  </section>
</template>
<style scoped>
.traffic-panel {
  margin-block: 24px;
}
.traffic-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.traffic-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 20px;
  margin-block: 20px;
}
.traffic-grid dt {
  color: var(--secondary);
  font-size: 12px;
}
.traffic-grid dd {
  margin: 6px 0 0;
  font-variant-numeric: tabular-nums;
}
.traffic-form {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  padding-top: 20px;
}
.traffic-form label {
  display: grid;
  gap: 8px;
  font-size: 13px;
}
.traffic-form input {
  width: 100%;
  min-height: 38px;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 8px 10px;
  background: var(--surface);
  color: inherit;
}
.traffic-form > p,
.traffic-form > .traffic-heading {
  grid-column: 1 / -1;
}
.traffic-enforcement {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
</style>
