<script setup lang="ts">
import { computed, onScopeDispose, shallowRef, watch } from "vue";
import { RouterLink } from "vue-router";
import { Plus, RefreshCw, ArrowUpRight } from "@lucide/vue";
import { ApiError } from "../api/client";
import { epochResponse } from "../api/overlay";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { usePublicIPResourceMutation } from "../composables/public-ip-resource-mutation";
import { publicIPPage, type PublicIPPool } from "../api/public-ip";
import {
  publicIPResourcePage,
  validPublicIPResourceOptions,
  type PublicIPResource,
  type PublicIPResourceAction,
} from "../api/public-ip-resource";
import type { Instance } from "../api/types";
import { dateText } from "../format";
import UiButton from "./UiButton.vue";
import UiSelect from "./UiSelect.vue";
import StateBlock from "./StateBlock.vue";
import InlineError from "./InlineError.vue";
import PublicIPResourceDialog from "./PublicIPResourceDialog.vue";
const props = defineProps<{
  cluster?: string;
  cursor?: string;
  instance?: Instance;
}>();
const emit = defineEmits<{ page: [cursor: string] }>();
const {
  api,
  session,
  prefs: { tr, locale },
  notify,
} = useConsole();
const localCursor = shallowRef("");
const cursor = computed(() =>
  props.instance ? localCursor.value : props.cursor || "",
);
const scope = computed(() =>
  new URLSearchParams({
    ...(props.cluster ? { cluster_id: props.cluster } : {}),
    ...(props.instance ? { owner_ref: props.instance.owner_ref } : {}),
    ...(cursor.value ? { cursor: cursor.value } : {}),
  }).toString(),
);
const options = useQuery(
  () => "/public-ips/options",
  validPublicIPResourceOptions,
);
const list = useQuery(
  () => `/public-ips/resources${scope.value ? `?${scope.value}` : ""}`,
  (v): v is { items: PublicIPResource[]; next_cursor: string | null } =>
    publicIPResourcePage(v) &&
    v.items.every(
      (r) =>
        (!props.cluster || r.cluster_id === props.cluster) &&
        (!props.instance || r.owner_ref === props.instance.owner_ref),
    ),
);
const pools = useQuery(
  () =>
    `/public-ips/pools${props.cluster ? `?cluster_id=${encodeURIComponent(props.cluster)}` : ""}`,
  (v): v is { items: PublicIPPool[]; next_cursor: string | null } =>
    publicIPPage("pools")(v),
);
const poolID = shallowRef("");
const pool = computed(() =>
  pools.data.value?.items.find((p) => p.id === poolID.value),
);
const mutation = usePublicIPResourceMutation();
const editing = shallowRef<{
  action: PublicIPResourceAction;
  pool?: PublicIPPool;
  resource?: PublicIPResource;
  recoverySHA?: string;
} | null>(null);
const accepted = shallowRef<PublicIPResource | null>(null);
const canManage = computed(
  () => session.can("nodes.manage") && session.can("instances.manage"),
);
let alive = true;
onScopeDispose(() => {
  alive = false;
});
const readingRecovery = shallowRef(false),
  recoveryError = shallowRef("");
const locked = computed(
  () =>
    !canManage.value ||
    readingRecovery.value ||
    mutation.busy.value ||
    !!mutation.pending.value,
);
watch(
  () => props.cluster,
  () => {
    poolID.value = "";
    editing.value = null;
    accepted.value = null;
  },
);
function page(value: string) {
  if (props.instance) localCursor.value = value;
  else emit("page", value);
}
async function edit(
  action: PublicIPResourceAction,
  resource?: PublicIPResource,
) {
  if (action === "resource.recover") {
    if (locked.value || !resource?.epoch_id || !options.data.value) return;
    const frozen = { ...resource },
      epoch = session.epoch.value;
    readingRecovery.value = true;
    recoveryError.value = "";
    try {
      const result = await api.get(
        `/overlays/epochs/${frozen.epoch_id}`,
        epochResponse,
      );
      if (!alive || epoch !== session.epoch.value || !canManage.value) return;
      if (
        result.epoch.id !== frozen.epoch_id ||
        result.epoch.cluster_id !== frozen.cluster_id
      )
        throw new ApiError("invalid");
      editing.value = {
        action,
        resource: frozen,
        recoverySHA: result.epoch.snapshot_sha256,
      };
    } catch (cause) {
      if (alive && epoch === session.epoch.value)
        recoveryError.value =
          cause instanceof ApiError ? cause.kind : "network";
    } finally {
      readingRecovery.value = false;
    }
    return;
  }
  if (
    !locked.value &&
    options.data.value &&
    (action !== "resource.allocate" || pool.value)
  )
    editing.value = {
      action,
      resource: resource ? { ...resource } : undefined,
      pool: pool.value as PublicIPPool | undefined,
    };
}
async function reload() {
  await Promise.all([list.reload(), options.reload(), pools.reload()]);
}
async function submit(
  action: PublicIPResourceAction,
  target: string,
  body: Record<string, unknown>,
) {
  const op = await mutation.execute(action, target, body);
  if (op) {
    accepted.value = op.result.resource;
    editing.value = null;
    notify(
      tr(
        op.result.resource.binding_state === "pending"
          ? "变更已记录，请继续执行关联任务。"
          : "公网地址配置已保存。",
        op.result.resource.binding_state === "pending"
          ? "Change recorded. Continue its linked task."
          : "Public address configuration saved.",
      ),
    );
    await reload();
  }
}
async function reconcile() {
  const op = await mutation.reconcile();
  if (op) {
    accepted.value = op.result.resource;
    editing.value = null;
    notify(
      tr(
        "原操作已核实，请查看当前资源状态。",
        "Original operation verified. Review the current resource state.",
      ),
    );
    await reload();
  }
}
const taskPath = (r: PublicIPResource) =>
  r.epoch_id
    ? `/networks/epochs/${r.epoch_id}`
    : r.operation_id
      ? `/operations/${r.operation_id}`
      : "";
const bindingLabel = (r: PublicIPResource) =>
  ({
    unbound: tr("已分配 · 未绑定", "Allocated · unbound"),
    pending: tr(
      "变更待执行或核实",
      "Change awaiting execution or verification",
    ),
    bound: tr("已绑定", "Bound"),
    blocked: tr("变更受阻", "Change blocked"),
    released: tr("已回收", "Reclaimed"),
  })[r.binding_state];
</script>
<template>
  <section
    class="vm-public-panel"
    :aria-label="tr('实例公网地址', 'VM public addresses')"
  >
    <header class="resource-heading">
      <div>
        <h2>{{ tr("实例公网地址", "VM public addresses") }}</h2>
        <p>
          {{
            instance
              ? tr(
                  "此客户的直绑地址与浮动 IP。选择目标实例后，仍需执行并核实关联任务。",
                  "Direct and floating IPs of this owner. Binding changes require execution and verification of their linked tasks.",
                )
              : tr(
                  "管理虚拟机公网直绑和独立浮动 IP。共享 NAT 出口保留在 NAT 分配中。",
                  "Manage direct VM addresses and independent floating IPs. Shared NAT egress remains in NAT allocations.",
                )
          }}
        </p>
      </div>
      <UiButton :busy="list.loading.value" @click="reload"
        ><RefreshCw :size="16" aria-hidden="true" />{{
          tr("刷新公网地址", "Refresh public addresses")
        }}</UiButton
      >
    </header>
    <div v-if="canManage && !instance" class="allocation-toolbar">
      <label class="field"
        >{{ tr("从地址池分配", "Allocate from pool")
        }}<UiSelect
          v-model="poolID"
          :label="tr('实例公网地址池', 'VM public address pool')"
          :options="
            (pools.data.value?.items || [])
              .filter((p) => p.enabled)
              .map((p) => ({ value: p.id, label: `${p.name} · ${p.cidr}` }))
          "
          :placeholder="tr('选择地址池', 'Choose a pool')"
          :disabled="locked || pools.loading.value" /></label
      ><UiButton
        variant="primary"
        :disabled="locked || !pool || !options.data.value"
        @click="edit('resource.allocate')"
        ><Plus :size="16" aria-hidden="true" />{{
          tr("分配实例地址", "Allocate VM address")
        }}</UiButton
      >
    </div>
    <p v-if="pools.data.value?.next_cursor && !instance" class="resource-note">
      {{
        tr(
          "此处显示第一页地址池。请在地址池页面查看后续记录。",
          "This chooser shows the first page of pools. Open Pools to review subsequent records.",
        )
      }}
    </p>
    <InlineError
      :error="options.error.value || pools.error.value || recoveryError"
    />
    <section
      v-if="mutation.pending.value"
      class="resource-pending"
      role="status"
    >
      <div>
        <strong>{{
          tr(
            "有一项公网地址操作等待核实",
            "A public address operation needs verification",
          )
        }}</strong>
        <p>
          {{
            tr(
              "原意图与客户、地址和代数保持不变；核实前不会再次提交。",
              "The original owner, address and generation remain frozen. No new submission is sent before verification.",
            )
          }}
        </p>
        <code>{{ mutation.pending.value.key }}</code>
      </div>
      <UiButton :busy="mutation.busy.value" @click="reconcile">{{
        tr("核对原操作", "Check original operation")
      }}</UiButton>
    </section>
    <div
      v-if="accepted && taskPath(accepted)"
      class="resource-next"
      role="status"
    >
      <span>{{
        tr(
          "操作已记录，不代表公网已接通。",
          "The operation is recorded, not proof of public connectivity.",
        )
      }}</span
      ><RouterLink :to="taskPath(accepted)"
        >{{ tr("继续关联任务", "Continue linked task")
        }}<ArrowUpRight :size="16" aria-hidden="true"
      /></RouterLink>
    </div>
    <InlineError v-if="!editing" :error="mutation.error.value" />
    <StateBlock
      :loading="list.loading.value"
      :error="list.error.value"
      :empty="!list.data.value?.items.length"
      :title="tr('暂无实例公网地址', 'No VM public addresses')"
      :description="
        tr(
          '从地址池分配直绑地址或浮动 IP；回收后的记录也会保留。',
          'Allocate a direct or floating IP from a pool. Reclaimed records are also retained.',
        )
      "
      @reload="list.reload"
    >
      <div class="resource-list">
        <article
          v-for="r in list.data.value?.items"
          :key="r.id"
          class="vm-public-resource"
          :data-resource-id="r.id"
        >
          <header>
            <div>
              <h3>{{ r.address }}</h3>
              <span class="resource-note">{{
                r.mode === "floating"
                  ? tr("独立浮动 IP", "Floating IP")
                  : tr("虚拟机公网直绑", "Direct VM address")
              }}</span>
            </div>
            <span class="binding-state" :data-binding-state="r.binding_state">{{
              bindingLabel(r)
            }}</span>
          </header>
          <dl class="resource-details">
            <div>
              <dt>{{ tr("所属客户", "Owner reference") }}</dt>
              <dd>{{ r.owner_ref }}</dd>
            </div>
            <div>
              <dt>{{ tr("计算节点", "Compute node") }}</dt>
              <dd>{{ r.node_id }}</dd>
            </div>
            <div v-if="r.vpc_id">
              <dt>VPC</dt>
              <dd>
                {{
                  options.data.value?.vpcs.find((v) => v.id === r.vpc_id)
                    ?.name || r.vpc_id
                }}
              </dd>
            </div>
            <div>
              <dt>{{ tr("绑定实例", "Bound instance") }}</dt>
              <dd>
                <RouterLink
                  v-if="r.instance_id"
                  :to="`/instances/${r.instance_id}`"
                  >{{ r.instance_id }}</RouterLink
                ><span v-else>{{ tr("未选择", "None selected") }}</span>
              </dd>
            </div>
            <div>
              <dt>{{ tr("最近更新", "Last updated") }}</dt>
              <dd>{{ dateText(r.updated_at, locale) }}</dd>
            </div>
          </dl>
          <p v-if="r.binding_state === 'pending'" class="resource-note">
            {{
              tr(
                "当前为已记录的目标状态。完成关联任务后，请刷新以核实实际绑定。",
                "This is the recorded desired state. Complete the linked task, then refresh to verify the actual binding.",
              )
            }}
          </p>
          <p v-if="r.binding_state === 'blocked'" class="resource-note">
            {{
              tr(
                "请查看关联任务的结果，核实节点与网络状态后处理；不要重复分配或绑定。",
                "Review the linked task and node/network state. Do not repeat allocation or binding.",
              )
            }}
          </p>
          <footer>
            <code>{{ r.id }}</code>
            <div class="resource-actions">
              <RouterLink v-if="taskPath(r)" :to="taskPath(r)">{{
                tr("查看关联任务", "View linked task")
              }}</RouterLink
              ><template v-if="canManage && r.state === 'reserved'"
                ><UiButton
                  v-if="
                    r.mode === 'floating' &&
                    ['pending', 'blocked'].includes(r.binding_state)
                  "
                  :disabled="locked || !options.data.value"
                  :busy="readingRecovery"
                  @click="edit('resource.recover', r)"
                  >{{ tr("恢复解绑", "Recover detachment") }}</UiButton
                >
                <UiButton
                  v-if="
                    r.binding_state === 'unbound' ||
                    (r.mode === 'floating' && r.binding_state === 'bound')
                  "
                  :disabled="locked || !options.data.value"
                  @click="edit('resource.bind', r)"
                  >{{
                    r.binding_state === "bound"
                      ? tr("更换实例", "Move to instance")
                      : tr("绑定实例", "Bind instance")
                  }}</UiButton
                ><UiButton
                  v-if="r.binding_state === 'bound'"
                  :disabled="locked || !options.data.value"
                  @click="edit('resource.unbind', r)"
                  >{{ tr("解绑", "Unbind") }}</UiButton
                ><UiButton
                  variant="danger"
                  :disabled="locked || !r.releasable || !options.data.value"
                  @click="edit('resource.release', r)"
                  >{{ tr("回收", "Reclaim") }}</UiButton
                ></template
              >
            </div>
          </footer>
        </article>
      </div>
    </StateBlock>
    <footer class="resource-pagination">
      <UiButton v-if="cursor" @click="page('')">{{
        tr("返回第一页", "First page")
      }}</UiButton
      ><UiButton
        v-if="list.data.value?.next_cursor"
        @click="page(list.data.value.next_cursor)"
        >{{ tr("下一页", "Next page") }}</UiButton
      >
    </footer>
    <PublicIPResourceDialog
      v-if="editing && options.data.value"
      :key="`${editing.action}:${editing.resource?.id || editing.pool?.id}`"
      :action="editing.action"
      :cluster="
        editing.resource?.cluster_id ||
        editing.pool?.cluster_id ||
        cluster ||
        ''
      "
      :options="options.data.value"
      :pool="editing.pool"
      :resource="editing.resource"
      :recoverySHA="editing.recoverySHA"
      :busy="mutation.busy.value"
      :pending="!!mutation.pending.value"
      :error="mutation.error.value"
      @submit="submit"
      @reconcile="reconcile"
      @close="editing = null"
    />
  </section>
</template>
<style scoped>
.vm-public-panel {
  display: grid;
  gap: 20px;
  min-width: 0;
}
.resource-heading,
.allocation-toolbar,
.vm-public-resource > header,
.vm-public-resource > footer,
.resource-next,
.resource-pending {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}
.resource-heading h2 {
  margin: 0;
  font-size: 18px;
  letter-spacing: -0.02em;
}
.resource-heading p,
.resource-note {
  color: var(--secondary);
  font-size: 13px;
  line-height: 1.7;
  margin: 8px 0 0;
}
.resource-heading > div,
.allocation-toolbar .field {
  min-width: 0;
}
.allocation-toolbar {
  align-items: flex-end;
}
.allocation-toolbar .field {
  flex: 1;
  max-width: 560px;
}
.resource-list {
  display: block;
  gap: 0;
}
.vm-public-resource {
  padding: 18px 0;
  border: 0;
  border-radius: 0;
  background: var(--surface);
  min-width: 0;
  border-bottom: 1px solid var(--border);
}
.vm-public-resource:last-child {
  border-bottom: 0;
}
.vm-public-resource h3 {
  margin: 0;
  font-size: 18px;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.02em;
}
.binding-state {
  color: var(--secondary);
  font-size: 13px;
  text-align: right;
}
.binding-state[data-binding-state="bound"] {
  color: var(--success);
}
.resource-details {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px 24px;
  margin: 18px 0;
}
.resource-details > div {
  min-width: 0;
}
.resource-details dt {
  color: var(--secondary);
  font-size: 13px;
  margin-bottom: 6px;
}
.resource-details dd {
  margin: 0;
  font-size: 14px;
  overflow-wrap: anywhere;
}
.vm-public-resource > footer {
  border-top: 1px solid var(--border);
  margin-top: 18px;
  padding-top: 12px;
  flex-wrap: wrap;
}
.vm-public-resource code,
.resource-pending code {
  overflow-wrap: anywhere;
  color: var(--secondary);
  font-size: 12px;
}
.resource-actions,
.resource-pagination {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.resource-actions a,
.resource-next a {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 44px;
  font-size: 13px;
}
.resource-pending,
.resource-next {
  padding: 16px;
  background: var(--subtle);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 13px;
  line-height: 1.7;
}
.resource-pending p {
  color: var(--secondary);
  margin: 8px 0;
}
@media (max-width: 600px) {
  .resource-heading,
  .allocation-toolbar,
  .resource-pending,
  .resource-next {
    align-items: stretch;
    flex-direction: column;
  }
  .vm-public-resource {
    padding: 16px;
  }
  .resource-details {
    grid-template-columns: minmax(0, 1fr);
  }
  .vm-public-resource > header {
    align-items: flex-start;
  }
  .binding-state {
    max-width: 45%;
  }
  .resource-actions {
    width: 100%;
  }
  .resource-actions > * {
    flex: 1 1 auto;
    justify-content: center;
  }
}
@media (max-width: 600px) {
  .vm-public-resource {
    padding: 18px 0;
  }
}
</style>
