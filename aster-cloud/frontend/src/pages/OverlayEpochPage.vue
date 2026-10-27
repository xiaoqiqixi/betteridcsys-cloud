<script setup lang="ts">
import { computed, shallowRef, watch } from "vue";
import { RouterLink, useRoute, useRouter } from "vue-router";
import { ArrowLeft, RefreshCw, Check, Circle } from "@lucide/vue";
import { networkID } from "../api/network";
import {
  epochDetail,
  overlayOptions,
  phaseNames,
  vpcList,
  type OverlayEpoch,
  type OverlayOptions,
  type OverlayVPC,
  type OverlayTask,
} from "../api/overlay";
import { useQuery } from "../composables/query";
import { useConsole } from "../context";
import { dateText } from "../format";
import UiButton from "../components/UiButton.vue";
import StateBlock from "../components/StateBlock.vue";
import StatusBadge from "../components/StatusBadge.vue";
import OverlaySnapshotPanel from "../components/OverlaySnapshotPanel.vue";
import OverlayEpochActions from "../components/OverlayEpochActions.vue";
import OverlayEpochDialog from "../components/OverlayEpochDialog.vue";
const route = useRoute(),
  router = useRouter(),
  {
    prefs: { tr, locale },
  } = useConsole();
const id = computed(() =>
    typeof route.params.id === "string" ? route.params.id : "",
  ),
  recovering = shallowRef(false);
const valid = computed(
  () => networkID(id.value) && Object.keys(route.query).length === 0,
);
const detail = useQuery(
  () => (valid.value ? `/overlays/epochs/${id.value}` : "INVALID"),
  (v): v is { epoch: OverlayEpoch; tasks: OverlayTask[] } =>
    epochDetail(v) && v.epoch.id === id.value,
);
const cluster = computed(() => detail.data.value?.epoch.cluster_id || "");
const options = useQuery(
  () =>
    cluster.value ? `/overlays/options?cluster_id=${cluster.value}` : "INVALID",
  (v): v is OverlayOptions =>
    overlayOptions(v) && v.cluster_id === cluster.value,
);
const vpcs = useQuery(
  () =>
    cluster.value ? `/overlays/vpcs?cluster_id=${cluster.value}` : "INVALID",
  (v): v is { items: OverlayVPC[] } =>
    vpcList(v) && v.items.every((item) => item.cluster_id === cluster.value),
);
const phases = ["prepare", "program", "release"] as const;
const latest = computed(
  () => options.data.value?.latest_epoch?.id === id.value,
);
function refresh() {
  void detail.reload();
}
function saved(epoch: OverlayEpoch) {
  void router.push(`/networks/epochs/${epoch.id}`);
}
watch(
  () => route.fullPath,
  () => (recovering.value = false),
  { flush: "sync" },
);
const stageComplete = (phase: string) =>
  !!detail.data.value &&
  detail.data.value.epoch.snapshot.profiles.every((p) =>
    detail.data.value?.tasks.some(
      (t) =>
        t.node_id === p.node_id && t.phase === phase && t.state === "succeeded",
    ),
  );
</script>
<template>
  <section class="page epoch-page">
    <RouterLink
      :to="{
        path: '/networks/overlays',
        query: cluster ? { cluster_id: cluster } : {},
      }"
      class="back-link"
      ><ArrowLeft :size="16" aria-hidden="true" />{{
        tr("返回网络管理", "Back to networking")
      }}</RouterLink
    ><StateBlock
      :loading="detail.loading.value"
      :error="detail.error.value"
      @reload="refresh"
      ><template v-if="detail.data.value"
        ><header class="page-heading epoch-heading">
          <div>
            <h1>
              {{ tr("网络变更", "Network change") }}
              {{ detail.data.value.epoch.epoch }}
            </h1>
            <p>
              {{ detail.data.value.epoch.cluster_id
              }}<span v-if="detail.data.value.epoch.recovery">
                · {{ tr("恢复版本", "Recovery version") }}</span
              >
            </p>
          </div>
          <div class="heading-actions">
            <StatusBadge :state="detail.data.value.epoch.state" /><UiButton
              :busy="detail.loading.value"
              @click="refresh"
              ><RefreshCw :size="16" aria-hidden="true" />{{
                tr("刷新", "Refresh")
              }}</UiButton
            >
          </div>
        </header>
        <div class="change-identity">
          <span>{{ tr("变更 ID", "Change ID") }}</span
          ><code>{{ detail.data.value.epoch.id }}</code
          ><span>{{ tr("创建时间", "Created") }}</span
          ><span>{{
            dateText(detail.data.value.epoch.created_at, locale)
          }}</span>
        </div>
        <p v-if="detail.data.value.epoch.superseded_by" class="change-notice">
          {{
            tr(
              "此版本已由新的恢复变更替代，原任务和回执保留。",
              "This version was superseded by a recovery change. Original tasks and receipts remain available.",
            )
          }}<RouterLink
            :to="`/networks/epochs/${detail.data.value.epoch.superseded_by}`"
            >{{ tr("查看恢复变更", "View recovery change") }}</RouterLink
          >
        </p>
        <p
          v-else-if="detail.data.value.epoch.state === 'uncertain'"
          class="change-notice warning"
        >
          {{
            tr(
              "部分节点结果待核实。先核对已有回执；需要重新应用时，使用“恢复网络”创建新版本，不要重复原任务。",
              "Some node results are unconfirmed. Check existing receipts first. To reapply configuration, create a new version with Recover network rather than repeating original tasks.",
            )
          }}
        </p>
        <StateBlock
          :loading="options.loading.value || vpcs.loading.value"
          :error="options.error.value || vpcs.error.value"
          @reload="
            () => {
              options.reload();
              vpcs.reload();
            }
          "
          ><OverlayEpochActions
            :key="id"
            :epoch="detail.data.value.epoch"
            :latest="latest"
            :recoverable="
              !options.data.value?.profile_migration_required ||
              options.data.value?.profile_migration_approved
            "
            @updated="refresh"
            @recover="recovering = true"
        /></StateBlock>
        <p
          v-if="
            options.data.value?.profile_migration_required &&
            !options.data.value.profile_migration_approved
          "
          class="change-notice warning"
        >
          {{
            tr(
              "节点网络配置已变化，尚未批准此版本的迁移恢复。请先完成主控与节点配置审批，再恢复网络。",
              "Node network profiles have changed, but recovery migration is not approved. Complete controller and node approval before recovering the network.",
            )
          }}
        </p>
        <ol class="phase-track" :aria-label="tr('变更阶段', 'Change phases')">
          <li
            v-for="phase in phases"
            :key="phase"
            :class="{
              complete: stageComplete(phase),
              current: detail.data.value.epoch.phase === phase,
            }"
            :aria-current="
              detail.data.value.epoch.phase === phase ? 'step' : undefined
            "
          >
            <Check
              v-if="stageComplete(phase)"
              :size="18"
              aria-hidden="true"
            /><Circle v-else :size="18" aria-hidden="true" /><span>{{
              tr(...phaseNames[phase])
            }}</span
            ><small>{{
              stageComplete(phase)
                ? tr("全部节点已确认", "All nodes confirmed")
                : tr("等待全部节点确认", "Awaiting every node")
            }}</small>
          </li>
        </ol>
        <section class="node-tasks">
          <div class="section-title">
            <h2>{{ tr("节点执行记录", "Node execution records") }}</h2>
            <p>
              {{
                tr(
                  "只有每个节点都完成当前阶段，才会进入下一阶段。",
                  "The next phase starts only after every node completes the current phase.",
                )
              }}
            </p>
          </div>
          <article
            v-for="profile in detail.data.value.epoch.snapshot.profiles"
            :key="profile.node_id"
            class="node-task"
          >
            <h3>{{ profile.node_id }}</h3>
            <div class="node-phases">
              <div v-for="phase in phases" :key="phase" class="node-phase">
                <span>{{ tr(...phaseNames[phase]) }}</span
                ><StatusBadge
                  :state="
                    detail.data.value.tasks.find(
                      (t) => t.node_id === profile.node_id && t.phase === phase,
                    )?.state || 'unknown'
                  "
                />
                <details
                  v-if="
                    detail.data.value.tasks.some(
                      (t) => t.node_id === profile.node_id && t.phase === phase,
                    )
                  "
                >
                  <summary>{{ tr("任务详情", "Task details") }}</summary>
                  <dl>
                    <div>
                      <dt>{{ tr("操作 ID", "Operation ID") }}</dt>
                      <dd>
                        {{
                          detail.data.value.tasks.find(
                            (t) =>
                              t.node_id === profile.node_id &&
                              t.phase === phase,
                          )?.operation_id
                        }}
                      </dd>
                    </div>
                    <div
                      v-if="
                        detail.data.value.tasks.find(
                          (t) =>
                            t.node_id === profile.node_id && t.phase === phase,
                        )?.result
                      "
                    >
                      <dt>{{ tr("节点回执", "Node receipt") }}</dt>
                      <dd>
                        {{
                          detail.data.value.tasks.find(
                            (t) =>
                              t.node_id === profile.node_id &&
                              t.phase === phase,
                          )?.result?.code
                        }}
                      </dd>
                    </div>
                    <div>
                      <dt>{{ tr("更新时间", "Updated") }}</dt>
                      <dd>
                        {{
                          dateText(
                            detail.data.value.tasks.find(
                              (t) =>
                                t.node_id === profile.node_id &&
                                t.phase === phase,
                            )?.updated_at,
                            locale,
                          )
                        }}
                      </dd>
                    </div>
                  </dl>
                </details>
              </div>
            </div>
          </article>
        </section>
        <section class="version-config">
          <h2>{{ tr("此版本的网络配置", "Configuration in this version") }}</h2>
          <OverlaySnapshotPanel
            :snapshot="detail.data.value.epoch.snapshot"
            :vpcs="vpcs.data.value?.items"
            :nat-profiles="options.data.value?.nat_profiles"
          />
        </section>
        <details class="version-proof">
          <summary>
            {{
              tr("版本校验与恢复依据", "Version verification & recovery basis")
            }}
          </summary>
          <dl>
            <div>
              <dt>SHA-256</dt>
              <dd>{{ detail.data.value.epoch.snapshot_sha256 }}</dd>
            </div>
            <div v-if="detail.data.value.epoch.recovery">
              <dt>{{ tr("原版本 SHA-256", "Original SHA-256") }}</dt>
              <dd>{{ detail.data.value.epoch.recovery.snapshot_sha256 }}</dd>
            </div>
          </dl>
          <p>
            {{
              tr(
                "节点确认表示配置已应用，不代替实际网络连通性验收。",
                "Node confirmation means configuration was applied; it does not replace live connectivity verification.",
              )
            }}
          </p>
        </details>
        <OverlayEpochDialog
          v-if="
            recovering &&
            options.data.value &&
            vpcs.data.value &&
            (!options.data.value.profile_migration_required ||
              options.data.value.profile_migration_approved)
          "
          :key="id"
          :cluster="cluster"
          :options="options.data.value"
          :vpcs="vpcs.data.value.items"
          :recover="detail.data.value.epoch"
          @close="recovering = false"
          @saved="saved"
        /> </template
    ></StateBlock>
  </section>
</template>
<style scoped>
.epoch-heading {
  margin-top: 26px;
}
.change-identity {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  gap: 12px 18px;
  padding: 16px 0 20px;
  margin-bottom: 20px;
  border-bottom: 1px solid var(--border);
  font-size: 14px;
  color: var(--secondary);
}
.change-identity code {
  overflow-wrap: anywhere;
  color: var(--text);
}
.change-identity > span {
  overflow-wrap: anywhere;
}
.phase-track {
  list-style: none;
  margin: 24px 0;
  padding: 16px 0;
  background: var(--surface);
  border: 0;
  border-radius: 0;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 16px;
  border-block: 1px solid var(--border);
}
.phase-track li {
  display: grid;
  grid-template-columns: 20px minmax(0, 1fr);
  gap: 8px;
  font-size: 13px;
  color: var(--secondary);
}
.phase-track small {
  grid-column: 2;
  font-size: 12px;
  line-height: 1.5;
}
.phase-track .current {
  color: var(--accent-text);
}
.phase-track .complete {
  color: var(--success);
}
.section-title h2,
.version-config > h2 {
  font-size: 19px;
  margin: 0 0 10px;
}
.section-title p {
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
  margin: 0 0 20px;
}
.node-task {
  padding: 18px 0;
  background: var(--surface);
  border: 0;
  border-radius: 0;
  margin-top: 12px;
  min-width: 0;
  border-bottom: 1px solid var(--border);
}
.node-task h3 {
  margin: 0 0 16px;
  font-size: 15px;
  overflow-wrap: anywhere;
}
.node-phases {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 20px;
}
.node-phase {
  min-width: 0;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 12px;
  font-size: 13px;
}
.node-phase > .status-badge {
  justify-self: start;
}
.node-phase details {
  width: 100%;
}
.node-phase summary,
.version-proof summary {
  cursor: pointer;
  min-height: 44px;
  display: flex;
  align-items: center;
  color: var(--accent-text);
  font-size: 13px;
}
.node-phase summary::before,
.version-proof summary::before {
  content: "+";
  margin-right: 8px;
}
.node-phase details[open] summary::before,
.version-proof[open] summary::before {
  content: "−";
}
.node-phase dl {
  display: grid;
  gap: 12px;
  margin: 0;
}
.node-phase dt {
  font-size: 12px;
  color: var(--secondary);
  margin-bottom: 6px;
}
.node-phase dd {
  margin: 0;
  overflow-wrap: anywhere;
  font-size: 12px;
  line-height: 1.6;
}
.version-config {
  margin-top: 28px;
  padding-top: 24px;
  border-top: 1px solid var(--border);
}
.version-config > h2 {
  margin-bottom: 24px;
}
.version-proof {
  margin-top: 30px;
  padding-top: 14px;
  border-top: 1px solid var(--border);
}
.version-proof dl {
  font-size: 12px;
  line-height: 1.7;
}
.version-proof dt {
  color: var(--secondary);
}
.version-proof dd {
  margin: 8px 0 16px;
  overflow-wrap: anywhere;
}
.version-proof p {
  font-size: 13px;
  color: var(--secondary);
  line-height: 1.7;
}
.change-notice {
  background: var(--subtle);
  color: var(--secondary);
  font-size: 13px;
  line-height: 1.7;
  padding: 18px;
  border-radius: 6px;
  margin-bottom: 24px;
}
.change-notice a {
  display: inline-block;
  margin-left: 8px;
}
.change-notice.warning {
  background: var(--warning-bg);
  color: var(--warning);
}
@media (max-width: 700px) {
  .phase-track {
    grid-template-columns: 1fr;
    gap: 18px;
  }
  .node-phases {
    grid-template-columns: 1fr;
    gap: 0;
  }
  .node-phase {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    padding: 16px 0;
    border-top: 1px solid var(--border);
  }
  .node-phase details {
    grid-column: 1/-1;
  }
  .node-phase > span {
    font-size: 12px;
  }
}
@media (max-width: 420px) {
  .change-identity {
    grid-template-columns: 1fr;
    gap: 7px;
  }
  .change-identity > code {
    margin-bottom: 10px;
  }
  .node-task {
    padding: 18px;
  }
  .node-phase {
    grid-template-columns: 1fr;
  }
  .epoch-heading .heading-actions {
    width: 100%;
    justify-content: space-between;
  }
}
@media (max-width: 420px) {
  .node-task {
    padding: 18px 0;
  }
}
</style>
