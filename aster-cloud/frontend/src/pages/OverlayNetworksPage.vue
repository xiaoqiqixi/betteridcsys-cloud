<script setup lang="ts">
import { computed, shallowRef, watch } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { Plus, RefreshCw, Settings2, ArrowUpRight } from "@lucide/vue";
import { useConsole } from "../context";
import { dateText } from "../format";
import { useQuery } from "../composables/query";
import {
  clusterID,
  clusterList,
  epochList,
  overlayOptions,
  vpcList,
  phaseNames,
  type OverlayEpoch,
  type OverlayOptions,
  type OverlayVPC,
} from "../api/overlay";
import NetworkNav from "../components/NetworkNav.vue";
import UiButton from "../components/UiButton.vue";
import UiSelect from "../components/UiSelect.vue";
import StateBlock from "../components/StateBlock.vue";
import StatusBadge from "../components/StatusBadge.vue";
import OverlayVPCDialog from "../components/OverlayVPCDialog.vue";
import OverlayEpochDialog from "../components/OverlayEpochDialog.vue";
import OverlaySnapshotPanel from "../components/OverlaySnapshotPanel.vue";
const route = useRoute(),
  router = useRouter(),
  {
    session,
    prefs: { tr, locale },
  } = useConsole();
const clusters = useQuery(() => "/overlays/clusters", clusterList),
  creating = shallowRef(false),
  editing = shallowRef(false);
const cluster = computed(() =>
  typeof route.query.cluster_id === "string" ? route.query.cluster_id : "",
);
const before = computed(() =>
  typeof route.query.before_epoch === "string" ? route.query.before_epoch : "",
);
const queryValid = computed(
  () =>
    Object.keys(route.query).every(
      (k) => k === "cluster_id" || k === "before_epoch",
    ) &&
    (route.query.cluster_id === undefined ||
      clusterID(route.query.cluster_id)) &&
    (route.query.before_epoch === undefined ||
      (typeof route.query.before_epoch === "string" &&
        /^[1-9][0-9]*$/.test(route.query.before_epoch) &&
        Number.isSafeInteger(Number(route.query.before_epoch)))),
);
const approved = computed(
  () =>
    queryValid.value &&
    clusters.data.value?.items.some((c) => c.id === cluster.value),
);
const options = useQuery(
  () =>
    approved.value
      ? `/overlays/options?cluster_id=${cluster.value}`
      : "INVALID",
  (v): v is OverlayOptions =>
    overlayOptions(v) && v.cluster_id === cluster.value,
);
const vpcs = useQuery(
  () =>
    approved.value ? `/overlays/vpcs?cluster_id=${cluster.value}` : "INVALID",
  (v): v is { items: OverlayVPC[] } =>
    vpcList(v) && v.items.every((item) => item.cluster_id === cluster.value),
);
const epochs = useQuery(
  () =>
    approved.value
      ? `/overlays/epochs?cluster_id=${cluster.value}${before.value ? `&before_epoch=${before.value}` : ""}`
      : "INVALID",
  (v): v is { items: OverlayEpoch[]; next_before_epoch: number | null } =>
    epochList(v) && v.items.every((e) => e.cluster_id === cluster.value),
);
watch(
  () => clusters.data.value,
  () => {
    if (queryValid.value && !cluster.value && clusters.data.value?.items[0])
      void router.replace({
        path: route.path,
        query: { cluster_id: clusters.data.value.items[0].id },
      });
  },
);
watch(
  () => route.fullPath,
  () => {
    creating.value = false;
    editing.value = false;
  },
  { flush: "sync" },
);
const clusterOptions = computed(
  () =>
    clusters.data.value?.items.map((c) => ({ value: c.id, label: c.id })) || [],
);
const availableIDs = computed(() =>
  [...new Set(options.data.value?.mappings.map((m) => m.vpc_id) || [])].filter(
    (id) => !vpcs.data.value?.items.some((v) => v.id === id),
  ),
);
const pinsCurrent = computed(
  () =>
    !options.data.value?.latest_epoch ||
    JSON.stringify(
      [...options.data.value.profiles].sort((a, b) =>
        a.node_id.localeCompare(b.node_id),
      ),
    ) ===
      JSON.stringify(
        [...options.data.value.latest_epoch.snapshot.profiles].sort((a, b) =>
          a.node_id.localeCompare(b.node_id),
        ),
      ),
);
const canPlan = computed(
  () =>
    session.can("nodes.manage") &&
    session.can("instances.manage") &&
    pinsCurrent.value &&
    !options.data.value?.profile_migration_required &&
    options.data.value &&
    vpcs.data.value?.items.length &&
    (!options.data.value.latest_epoch ||
      options.data.value.latest_epoch.state === "succeeded"),
);
const latest = computed(() => options.data.value?.latest_epoch);
function changeCluster(value: string) {
  void router.push({ path: route.path, query: { cluster_id: value } });
}
function refresh() {
  void clusters.reload();
  void options.reload();
  void vpcs.reload();
  void epochs.reload();
}
function saved(epoch: OverlayEpoch) {
  void router.push(`/networks/epochs/${epoch.id}`);
}
function page(value: number | null) {
  void router.push({
    path: route.path,
    query: {
      cluster_id: cluster.value,
      ...(value ? { before_epoch: String(value) } : {}),
    },
  });
}
</script>
<template>
  <section class="page overlay-page">
    <header class="page-heading">
      <div>
        <h1>{{ tr("VPC 与路由", "VPC & routing") }}</h1>
        <p>
          {{
            tr(
              "管理跨节点私有网络、路由出口与网络恢复。",
              "Manage cross-node private networks, routing egress and network recovery.",
            )
          }}
        </p>
      </div>
      <UiButton :busy="clusters.loading.value" @click="refresh"
        ><RefreshCw :size="16" aria-hidden="true" />{{
          tr("刷新", "Refresh")
        }}</UiButton
      >
    </header>
    <NetworkNav />
    <StateBlock
      :loading="clusters.loading.value"
      :error="clusters.error.value || (!queryValid ? 'invalid' : '')"
      :empty="!clusters.data.value?.items.length"
      :title="tr('尚未配置网络集群', 'No network clusters configured')"
      :description="
        tr(
          '请先在主控中批准节点网络配置，随后可在这里创建 VPC 和应用变更。',
          'Approve node network profiles in the controller first, then create VPCs and apply changes here.',
        )
      "
      @reload="refresh"
    >
      <div class="cluster-toolbar">
        <label class="field cluster-field"
          >{{ tr("网络集群", "Network cluster")
          }}<UiSelect
            :model-value="cluster"
            :options="clusterOptions"
            :label="tr('网络集群', 'Network cluster')"
            @update:model-value="changeCluster"
        /></label>
        <div class="cluster-meta">
          <span>{{ tr("参与节点", "Participating nodes") }}</span>
          <p>
            {{
              clusters.data.value?.items
                .find((c) => c.id === cluster)
                ?.node_ids.join(", ")
            }}
          </p>
        </div>
      </div>
      <StateBlock
        :loading="options.loading.value || vpcs.loading.value"
        :error="!approved ? 'invalid' : options.error.value || vpcs.error.value"
        @reload="refresh"
      >
        <div class="section-heading">
          <div>
            <h2>{{ tr("私有网络", "Private networks") }}</h2>
            <p>
              {{
                tr(
                  "按客户隔离网络，节点间共享同一地址空间。",
                  "Customer-isolated networks share one address space across nodes.",
                )
              }}
            </p>
          </div>
          <UiButton v-if="session.can('nodes.manage')" @click="creating = true"
            ><Plus :size="16" aria-hidden="true" />{{
              tr("新建 VPC", "New VPC")
            }}</UiButton
          >
        </div>
        <p
          v-if="session.can('nodes.manage') && !availableIDs.length"
          class="field-note"
        >
          {{
            tr(
              "可先创建 VPC，再批准节点网络映射。未映射的 VPC 不能接入实例。",
              "Create a VPC first, then approve its node network mappings. Unmapped VPCs cannot connect instances.",
            )
          }}
        </p>
        <div v-if="vpcs.data.value?.items.length" class="vpc-list">
          <article
            v-for="vpc in vpcs.data.value.items"
            :key="vpc.id"
            class="vpc-card"
          >
            <header>
              <h3>{{ vpc.name }}</h3>
              <span>VNI {{ vpc.vni }}</span>
            </header>
            <strong class="vpc-cidr">{{ vpc.cidr }}</strong>
            <p
              v-if="
                !options.data.value?.mappings.some((m) => m.vpc_id === vpc.id)
              "
              class="unmapped-vpc"
            >
              {{ tr("尚未映射节点", "No node mappings yet") }}
            </p>
            <dl>
              <div>
                <dt>{{ tr("客户归属", "Customer owner") }}</dt>
                <dd>{{ vpc.owner_ref }}</dd>
              </div>
              <div>
                <dt>{{ tr("网络 ID", "Network ID") }}</dt>
                <dd>{{ vpc.id }}</dd>
              </div>
            </dl>
          </article>
        </div>
        <p v-else class="no-vpcs">
          {{
            tr(
              "还没有 VPC。先创建已批准网络，再添加实例成员。",
              "No VPCs yet. Create an approved network, then add instance members.",
            )
          }}
        </p>
        <section class="current-config">
          <div class="section-heading">
            <div>
              <h2>{{ tr("当前网络配置", "Current network configuration") }}</h2>
              <p v-if="latest">
                {{ tr("版本", "Version") }} {{ latest.epoch }} ·
                {{ tr(...phaseNames[latest.phase]) }}
              </p>
              <p v-else>
                {{
                  tr(
                    "尚未应用网络配置。",
                    "No network configuration has been applied.",
                  )
                }}
              </p>
            </div>
            <div class="config-actions">
              <StatusBadge v-if="latest" :state="latest.state" /><UiButton
                v-if="canPlan"
                variant="primary"
                @click="editing = true"
                ><Settings2 :size="16" aria-hidden="true" />{{
                  tr("配置网络", "Configure network")
                }}</UiButton
              ><RouterLink
                v-else-if="latest"
                :to="`/networks/epochs/${latest.id}`"
                class="detail-link"
                >{{ tr("查看变更与恢复", "Change details & recovery")
                }}<ArrowUpRight :size="16" aria-hidden="true"
              /></RouterLink>
            </div>
          </div>
          <p
            v-if="
              !pinsCurrent || options.data.value?.profile_migration_required
            "
            class="config-notice"
          >
            {{
              tr(
                "节点配置已更新，请先完成恢复审批并恢复网络，再提交新的网络变更。",
                "Node profiles have changed. Approve and recover the network before submitting another change.",
              )
            }}
          </p>
          <p
            v-if="latest && latest.state !== 'succeeded'"
            class="config-notice"
          >
            {{
              tr(
                "此版本尚未确认完成。请查看节点任务，结果待核实时不要重新派发。",
                "This version is not confirmed complete. Review node tasks; do not redispatch an uncertain result.",
              )
            }}
          </p>
          <OverlaySnapshotPanel
            v-if="latest"
            :snapshot="latest.snapshot"
            :vpcs="vpcs.data.value?.items"
            :nat-profiles="options.data.value?.nat_profiles"
          />
          <p v-else class="field-note">
            {{
              tr(
                "配置网络会提交完整成员、路由与 NAT 选择。",
                "Configure networking to submit the complete member, route and NAT selection.",
              )
            }}
          </p>
        </section>
      </StateBlock>
      <section class="history-section">
        <div class="section-heading">
          <h2>{{ tr("网络变更记录", "Network change history") }}</h2>
        </div>
        <StateBlock
          :loading="epochs.loading.value"
          :error="epochs.error.value"
          :empty="!epochs.data.value?.items.length"
          :title="tr('暂无网络变更', 'No network changes yet')"
          @reload="epochs.reload"
          ><div class="epoch-list">
            <RouterLink
              v-for="epoch in epochs.data.value?.items"
              :key="epoch.id"
              :to="`/networks/epochs/${epoch.id}`"
              class="epoch-row"
              ><div>
                <strong
                  >{{ tr("版本", "Version") }} {{ epoch.epoch
                  }}<span v-if="epoch.recovery">{{
                    tr("恢复变更", "Recovery")
                  }}</span></strong
                ><code>{{ epoch.id }}</code
                ><small
                  >{{ tr(...phaseNames[epoch.phase]) }} ·
                  {{ dateText(epoch.created_at, locale) }}</small
                >
              </div>
              <StatusBadge :state="epoch.state"
            /></RouterLink></div
        ></StateBlock>
        <div class="epoch-pagination">
          <UiButton v-if="before" @click="page(null)">{{
            tr("最新记录", "Latest changes")
          }}</UiButton
          ><UiButton
            v-if="epochs.data.value?.next_before_epoch"
            @click="page(epochs.data.value.next_before_epoch)"
            >{{ tr("更早记录", "Older changes") }}</UiButton
          >
        </div>
      </section>
    </StateBlock>
    <OverlayVPCDialog
      v-if="creating && options.data.value"
      :cluster="cluster"
      :approved-ids="availableIDs"
      @close="creating = false"
      @saved="refresh"
    />
    <OverlayEpochDialog
      v-if="editing && options.data.value && vpcs.data.value"
      :cluster="cluster"
      :options="options.data.value"
      :vpcs="vpcs.data.value.items"
      @close="editing = false"
      @saved="saved"
    />
  </section>
</template>
<style scoped>
.cluster-toolbar {
  display: flex;
  align-items: flex-end;
  gap: 24px;
  margin: 0 0 24px;
}
.cluster-field {
  width: 280px;
  max-width: 100%;
}
.cluster-meta {
  min-width: 0;
}
.cluster-meta > span {
  font-size: 12px;
  color: var(--secondary);
}
.cluster-meta p {
  font-size: 13px;
  line-height: 1.6;
  overflow-wrap: anywhere;
  margin: 10px 0;
}
.section-heading {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 20px;
  margin-bottom: 18px;
}
.section-heading > div {
  min-width: 0;
}
.section-heading h2 {
  font-size: 17px;
  margin: 0;
}
.section-heading p {
  font-size: 13px;
  line-height: 1.7;
  margin: 8px 0 0;
  color: var(--secondary);
}
.vpc-list {
  display: block;
  border-top: 1px solid var(--border);
}
.vpc-card {
  border: 0;
  background: var(--surface);
  padding: 18px 0;
  border-radius: 0;
  min-width: 0;
  border-bottom: 1px solid var(--border);
  display: grid;
  grid-template-columns: minmax(160px, 1fr) minmax(150px, 1fr) minmax(0, 2fr);
  gap: 12px 24px;
  align-items: start;
}
.vpc-card header {
  display: flex;
  justify-content: space-between;
  gap: 6px;
  align-items: flex-start;
  flex-direction: column;
  grid-column: 1;
  grid-row: 1;
}
.vpc-card h3 {
  font-size: 15px;
  margin: 0;
  overflow-wrap: anywhere;
}
.vpc-card header span {
  font-size: 12px;
  color: var(--secondary);
  flex-shrink: 0;
}
.vpc-cidr {
  display: block;
  margin-top: 0;
  font-size: 17px;
  font-weight: 600;
  letter-spacing: -0.02em;
  overflow-wrap: anywhere;
  grid-column: 2;
  grid-row: 1;
  font-variant-numeric: tabular-nums;
}
.unmapped-vpc {
  font-size: 12px;
  color: var(--warning);
  background: var(--warning-bg);
  border-radius: 4px;
  padding: 8px 10px;
  line-height: 1.6;
  grid-column: 1 / -1;
  grid-row: 2;
  margin: 0;
}
.vpc-card dl {
  display: grid;
  gap: 10px;
  margin: 0;
  grid-column: 3;
  grid-row: 1;
}
.vpc-card dl > div {
  display: grid;
  grid-template-columns: 76px minmax(0, 1fr);
  gap: 12px;
  font-size: 13px;
  line-height: 1.6;
}
.vpc-card dt {
  color: var(--secondary);
}
.vpc-card dd {
  margin: 0;
  overflow-wrap: anywhere;
}
.current-config {
  border-top: 1px solid var(--border);
  padding-top: 24px;
  margin-top: 24px;
}
.config-actions {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}
.detail-link {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  min-height: 44px;
  font-size: 13px;
  text-decoration: none;
}
.config-notice {
  font-size: 13px;
  line-height: 1.7;
  padding: 12px;
  background: var(--warning-bg);
  color: var(--warning);
  border-radius: 6px;
  margin: 0 0 20px;
}
.history-section {
  margin-top: 28px;
  padding-top: 24px;
  border-top: 1px solid var(--border);
}
.epoch-list {
  border: 0;
  border-radius: 0;
  background: var(--surface);
  overflow: clip;
  border-block: 1px solid var(--border);
}
.epoch-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  padding: 16px 0;
  text-decoration: none;
  color: var(--text);
}
.epoch-row + .epoch-row {
  border-top: 1px solid var(--border);
}
.epoch-row:hover {
  background: var(--subtle);
}
.epoch-row > div {
  display: grid;
  gap: 6px;
  min-width: 0;
}
.epoch-row strong {
  font-size: 14px;
}
.epoch-row strong span {
  font-size: 11px;
  font-weight: 400;
  margin-left: 12px;
  color: var(--secondary);
}
.epoch-row code,
.epoch-row small {
  font-size: 12px;
  color: var(--secondary);
  overflow-wrap: anywhere;
}
.epoch-pagination {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 18px;
}
.no-vpcs {
  padding: 20px 0;
  background: var(--surface);
  border: 0;
  border-radius: 0;
  color: var(--secondary);
  font-size: 14px;
  line-height: 1.7;
  border-block: 1px solid var(--border);
}
@media (max-width: 800px) {
  .section-heading {
    align-items: flex-start;
    flex-direction: column;
  }
  .cluster-toolbar {
    align-items: stretch;
    flex-direction: column;
    gap: 16px;
  }
  .cluster-field {
    width: 100%;
  }
}
@media (max-width: 420px) {
  .epoch-row {
    align-items: flex-start;
    flex-direction: column;
  }
  .vpc-card header {
    align-items: flex-start;
    flex-direction: column;
  }
  .config-actions {
    align-items: flex-start;
    flex-direction: column;
  }
}
@media (max-width: 900px) {
  .vpc-card {
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  }
  .vpc-card dl {
    grid-column: 1 / -1;
    grid-row: 2;
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .unmapped-vpc {
    grid-row: 3;
  }
}
@media (max-width: 600px) {
  .vpc-card {
    padding: 18px 0;
    gap: 14px;
  }
  .vpc-card dl {
    grid-template-columns: minmax(0, 1fr);
  }
  .vpc-card dl > div {
    grid-template-columns: 80px minmax(0, 1fr);
  }
}
</style>
