<script setup lang="ts">
import { computed, shallowRef, nextTick, watch } from "vue";
import { useRoute, RouterLink } from "vue-router";
import {
  ArrowLeft,
  RefreshCw,
  Power,
  Copy,
  Archive,
  ArrowRightLeft,
} from "@lucide/vue";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { validDetail } from "../api/client";
import type { Action } from "../api/types";
import { actionAllowed } from "../permissions";
import { actionNames, dateText, sizeMiB } from "../format";
import UiButton from "../components/UiButton.vue";
import StateBlock from "../components/StateBlock.vue";
import StatusBadge from "../components/StatusBadge.vue";
import ActionDialog from "../components/ActionDialog.vue";
import InstanceObservationPanel from "../components/InstanceObservationPanel.vue";
import InstanceMetricsPanel from "../components/InstanceMetricsPanel.vue";
import SourceRetirementPanel from "../components/SourceRetirementPanel.vue";
import MigrationWizard from "../components/MigrationWizard.vue";
import PublicIPResourcesPanel from "../components/PublicIPResourcesPanel.vue";
import PublicIngressPanel from "../components/PublicIngressPanel.vue";
const route = useRoute(),
  {
    prefs: { tr, locale },
    session,
  } = useConsole();
const detail = useQuery(
  () => `/instances/${encodeURIComponent(String(route.params.id))}`,
  validDetail,
);
const instance = computed(() => detail.data.value?.instance);
const publicResourceRevision = shallowRef(0);
const action = shallowRef<Action | null>(null),
  artifactId = shallowRef(""),
  migrationOpen = shallowRef(false),
  tab = shallowRef(
    typeof route.query.tab === "string" &&
      ["overview", "snapshots", "backups", "public", "tasks"].includes(
        route.query.tab,
      )
      ? route.query.tab
      : "overview",
  );
watch(
  () => route.query.tab,
  (value) => {
    tab.value =
      typeof value === "string" &&
      ["overview", "snapshots", "backups", "public", "tasks"].includes(value)
        ? value
        : "overview";
  },
);
const tabs = computed(() => [
  { value: "overview", label: tr("概览", "Overview") },
  { value: "snapshots", label: tr("快照", "Snapshots") },
  { value: "backups", label: tr("备份", "Backups") },
  { value: "public", label: tr("公网地址", "Public addresses") },
  { value: "tasks", label: tr("任务", "Tasks") },
]);
const artifacts = computed(
  () =>
    detail.data.value?.artifacts.filter(
      (v) => v.kind === (tab.value === "snapshots" ? "snapshot" : "backup"),
    ) || [],
);
function canOperate(value: Action) {
  return (
    !!instance.value &&
    !detail.data.value?.migrations.some(
      (migration) => !["active", "rejected"].includes(migration.phase),
    ) &&
    actionAllowed(
      value,
      instance.value.state,
      session.user.value?.permissions || [],
    )
  );
}
function choose(value: Action, id = "") {
  artifactId.value = id;
  action.value = value;
}
async function closeAction() {
  action.value = null;
  await nextTick();
}
async function closeMigration() {
  migrationOpen.value = false;
  await nextTick();
}
function tabKey(event: KeyboardEvent) {
  if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  event.preventDefault();
  const items = tabs.value,
    index = items.findIndex((v) => v.value === tab.value),
    target =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? items.length - 1
          : (index + (event.key === "ArrowLeft" ? -1 : 1) + items.length) %
            items.length;
  tab.value = items[target]!.value;
  void nextTick(() => document.getElementById(`tab-${tab.value}`)?.focus());
}
</script>
<template>
  <section class="page">
    <RouterLink to="/instances" class="back-link"
      ><ArrowLeft :size="16" aria-hidden="true" />{{
        tr("全部实例", "All instances")
      }}</RouterLink
    ><StateBlock
      :loading="detail.loading.value"
      :error="detail.error.value"
      @reload="detail.reload"
      ><template v-if="instance"
        ><header class="page-heading detail-heading">
          <div>
            <div class="title-with-state">
              <h1>{{ instance.hostname || instance.id }}</h1>
              <span class="recorded-state"
                >{{ tr("记录状态", "Recorded state") }}
                <StatusBadge :state="instance.state"
              /></span>
            </div>
            <p class="identifier-line">{{ instance.id }}</p>
          </div>
          <UiButton :busy="detail.loading.value" @click="detail.reload"
            ><RefreshCw :size="16" aria-hidden="true" />{{
              tr("刷新", "Refresh")
            }}</UiButton
          >
        </header>
        <InstanceObservationPanel :instance="instance" />
        <div class="action-toolbar">
          <UiButton :disabled="!canOperate('start')" @click="choose('start')"
            ><Power :size="16" aria-hidden="true" />{{
              tr("启动", "Start")
            }}</UiButton
          ><UiButton
            :disabled="!canOperate('shutdown')"
            @click="choose('shutdown')"
            >{{ tr("关机", "Shut down") }}</UiButton
          ><UiButton
            :disabled="!canOperate('reboot')"
            @click="choose('reboot')"
            >{{ tr("重启", "Restart") }}</UiButton
          ><UiButton
            :disabled="!session.can('migration.manage')"
            @click="migrationOpen = true"
            ><ArrowRightLeft :size="16" aria-hidden="true" />{{
              tr("迁移", "Migrate")
            }}</UiButton
          ><UiButton
            variant="danger"
            :disabled="!canOperate('force_off')"
            @click="choose('force_off')"
            >{{ tr("强制关机", "Force off") }}</UiButton
          >
        </div>
        <div
          class="detail-tabs"
          role="tablist"
          @keydown="tabKey"
          :aria-label="tr('实例详情', 'Instance details')"
        >
          <button
            v-for="item in tabs"
            :key="item.value"
            role="tab"
            type="button"
            :aria-selected="tab === item.value"
            :tabindex="tab === item.value ? 0 : -1"
            :id="`tab-${item.value}`"
            :aria-controls="`content-${item.value}`"
            :class="{ selected: tab === item.value }"
            @click="tab = item.value"
          >
            {{ item.label }}
          </button>
        </div>
        <section
          :id="`content-${tab}`"
          role="tabpanel"
          :aria-labelledby="`tab-${tab}`"
          class="tab-content"
        >
          <template v-if="tab === 'public'">
            <PublicIngressPanel
              v-if="
                instance.resources.network_type === 'vpc' &&
                session.can('nodes.read') &&
                session.can('instances.read')
              "
              :key="`ingress-${instance.id}`"
              :instance="instance"
              @changed="publicResourceRevision++"
            />
            <p
              v-else-if="instance.resources.network_type === 'normal'"
              class="direct-ingress-note"
            >
              {{
                tr(
                  "普通网络的公网直绑访问需使用实例防火墙控制。平台公网入站规则目前仅适用 VPC 浮动 IP。",
                  "Use the guest firewall to control direct public access on a normal network. Platform public ingress rules currently apply only to VPC floating IPs.",
                )
              }}
            </p>
            <PublicIPResourcesPanel
              :key="`${instance.id}:${publicResourceRevision}`"
              :instance="instance"
            />
          </template>
          <template v-else-if="tab === 'overview'"
            ><InstanceMetricsPanel :instance="instance" />
            <div class="detail-grid">
              <article class="content-section">
                <h2>{{ tr("资源规格", "Resources") }}</h2>
                <dl class="detail-pairs">
                  <div>
                    <dt>CPU</dt>
                    <dd>{{ instance.resources.cpu_cores }} vCPU</dd>
                  </div>
                  <div>
                    <dt>{{ tr("内存", "Memory") }}</dt>
                    <dd>{{ sizeMiB(instance.resources.memory_mib) }}</dd>
                  </div>
                  <div>
                    <dt>{{ tr("系统磁盘", "System disk") }}</dt>
                    <dd>{{ instance.resources.system_disk_gib }} GiB</dd>
                  </div>
                  <div>
                    <dt>{{ tr("系统镜像", "System image") }}</dt>
                    <dd>{{ instance.resources.image_id || "—" }}</dd>
                  </div>
                </dl>
              </article>
              <article class="content-section">
                <h2>{{ tr("实例信息", "Instance information") }}</h2>
                <dl class="detail-pairs">
                  <div>
                    <dt>{{ tr("节点", "Node") }}</dt>
                    <dd>{{ instance.node_id }}</dd>
                  </div>
                  <div>
                    <dt>{{ tr("所属账户", "Owner") }}</dt>
                    <dd>{{ instance.owner_ref }}</dd>
                  </div>
                  <div>
                    <dt>{{ tr("创建时间", "Created") }}</dt>
                    <dd>{{ dateText(instance.created_at, locale) }}</dd>
                  </div>
                  <div>
                    <dt>{{ tr("最后更新", "Last updated") }}</dt>
                    <dd>{{ dateText(instance.updated_at, locale) }}</dd>
                  </div>
                </dl>
              </article>
            </div>
            <SourceRetirementPanel
              v-for="migration in (detail.data.value?.migrations || []).filter(
                (m) => m.phase === 'active' && m.source_retirement_state,
              )"
              :key="migration.id"
              :instance="instance"
              :migration="migration"
            />
            <section class="danger-zone">
              <div>
                <h2>{{ tr("删除实例", "Delete instance") }}</h2>
                <p>
                  {{
                    tr(
                      "删除可能永久移除实例数据，请先确认备份。",
                      "Deletion may permanently remove instance data. Check backups first.",
                    )
                  }}
                </p>
              </div>
              <UiButton
                variant="danger"
                :disabled="!canOperate('delete')"
                @click="choose('delete')"
                >{{ tr("删除实例", "Delete instance") }}</UiButton
              >
            </section></template
          ><template v-else-if="tab === 'snapshots' || tab === 'backups'"
            ><div class="section-heading">
              <div>
                <h2>
                  {{
                    tab === "snapshots"
                      ? tr("实例快照", "Instance snapshots")
                      : tr("实例备份", "Instance backups")
                  }}
                </h2>
                <p>
                  {{
                    tr(
                      "恢复操作会覆盖当前数据，请先确认实例状态。",
                      "Restoring overwrites current data. Check the instance state first.",
                    )
                  }}
                </p>
              </div>
              <UiButton
                :disabled="
                  !canOperate(
                    tab === 'snapshots' ? 'snapshot_create' : 'backup_create',
                  )
                "
                @click="
                  choose(
                    tab === 'snapshots' ? 'snapshot_create' : 'backup_create',
                  )
                "
                ><Copy
                  v-if="tab === 'snapshots'"
                  :size="16"
                  aria-hidden="true"
                /><Archive v-else :size="16" aria-hidden="true" />{{
                  tr("创建", "Create")
                }}</UiButton
              >
            </div>
            <StateBlock
              :empty="!artifacts.length"
              :title="tr('暂无记录', 'No records yet')"
              :description="
                tr(
                  '创建后可在任务中查看处理进度。',
                  'After creation, follow progress in Tasks.',
                )
              "
              ><div class="artifact-list">
                <article
                  v-for="artifact in artifacts"
                  :key="artifact.id"
                  class="artifact-row"
                >
                  <div>
                    <strong>{{ artifact.id }}</strong>
                    <p>{{ dateText(artifact.created_at, locale) }}</p>
                  </div>
                  <StatusBadge :state="artifact.state" />
                  <div class="row-actions">
                    <UiButton
                      v-if="artifact.kind === 'backup'"
                      :disabled="!canOperate('backup_verify')"
                      @click="choose('backup_verify', artifact.id)"
                      >{{ tr("校验", "Verify") }}</UiButton
                    ><UiButton
                      :disabled="
                        !canOperate(
                          artifact.kind === 'snapshot'
                            ? 'snapshot_restore'
                            : 'backup_restore',
                        )
                      "
                      @click="
                        choose(
                          artifact.kind === 'snapshot'
                            ? 'snapshot_restore'
                            : 'backup_restore',
                          artifact.id,
                        )
                      "
                      >{{ tr("恢复", "Restore") }}</UiButton
                    ><UiButton
                      variant="quiet"
                      :disabled="
                        !canOperate(
                          artifact.kind === 'snapshot'
                            ? 'snapshot_delete'
                            : 'backup_delete',
                        )
                      "
                      @click="
                        choose(
                          artifact.kind === 'snapshot'
                            ? 'snapshot_delete'
                            : 'backup_delete',
                          artifact.id,
                        )
                      "
                      >{{ tr("删除", "Delete") }}</UiButton
                    >
                  </div>
                </article>
              </div></StateBlock
            ></template
          ><template v-else
            ><StateBlock
              :empty="!detail.data.value?.operations.length"
              :title="tr('暂无操作任务', 'No operation tasks yet')"
              ><div class="resource-list">
                <RouterLink
                  v-for="operation in detail.data.value?.operations"
                  :key="operation.id"
                  :to="`/operations/${encodeURIComponent(operation.id)}`"
                  class="compact-row"
                  ><div>
                    <strong>{{
                      actionNames[operation.action]
                        ? tr(...actionNames[operation.action]!)
                        : operation.action
                    }}</strong>
                    <p>{{ dateText(operation.created_at, locale) }}</p>
                  </div>
                  <StatusBadge :state="operation.state"
                /></RouterLink></div></StateBlock
          ></template>
        </section>
        <ActionDialog
          v-if="action"
          :open="!!action"
          :instance="instance"
          :action="action"
          :artifact-id="artifactId"
          @close="closeAction" /><MigrationWizard
          :open="migrationOpen"
          :instance="instance"
          :migrations="detail.data.value?.migrations || []"
          @close="closeMigration" /></template
    ></StateBlock>
  </section>
</template>
<style scoped>
.direct-ingress-note {
  font-size: 13px;
  line-height: 1.7;
  color: var(--secondary);
  padding: 14px 0;
  border: 0;
  border-radius: 0;
  background: var(--surface);
  margin: 0 0 24px;
  border-block: 1px solid var(--border);
}
.detail-heading {
  margin-top: 20px;
}
.title-with-state {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
.recorded-state {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--secondary);
  font-weight: 400;
}
.identifier-line {
  overflow-wrap: anywhere;
  font-size: 13px !important;
}
.action-toolbar {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin: 20px 0 24px;
}
.detail-tabs {
  display: flex;
  gap: 24px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 22px;
  max-width: 100%;
  overflow-x: auto;
  overscroll-behavior-inline: contain;
}
.detail-tabs button {
  flex-shrink: 0;
  white-space: nowrap;
  min-height: 48px;
  padding: 0 0 12px;
  background: none;
  border: 0;
  border-bottom: 2px solid transparent;
  color: var(--secondary);
  font-weight: 500;
}
.detail-tabs .selected {
  color: var(--accent-text);
  border-bottom-color: var(--accent);
}
.detail-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
}
.danger-zone {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  margin-top: 24px;
  padding: 24px 0;
  border-top: 1px solid var(--border);
}
.danger-zone h2 {
  font-size: 16px;
  margin: 0 0 8px;
}
.danger-zone p {
  font-size: 13px;
  color: var(--secondary);
  margin: 0;
  line-height: 1.6;
}
.artifact-row {
  padding: 16px 0;
  border-bottom: 1px solid var(--border);
  display: flex;
  gap: 16px;
  align-items: center;
  flex-wrap: wrap;
}
.artifact-row:last-child {
  border-bottom: 0;
}
.artifact-row > div:first-child {
  flex: 1;
  min-width: 140px;
}
.artifact-row strong {
  font-size: 13px;
  overflow-wrap: anywhere;
}
.artifact-row p {
  font-size: 12px;
  color: var(--secondary);
  margin: 8px 0 0;
}
.row-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.artifact-list {
  background: var(--surface);
  border: 0;
  border-radius: 0;
  border-block: 1px solid var(--border);
}
.tab-content {
  min-width: 0;
}
@media (max-width: 760px) {
  .detail-grid {
    grid-template-columns: 1fr;
  }
  .detail-tabs {
    gap: 20px;
  }
  .danger-zone {
    align-items: flex-start;
    flex-direction: column;
  }
  .artifact-row {
    padding: 20px;
  }
  .row-actions {
    width: 100%;
  }
  .action-toolbar {
    gap: 8px;
  }
  .action-toolbar .ui-button {
    padding: 0 12px;
  }
}
@media (max-width: 760px) {
  .artifact-row {
    padding: 16px 0;
  }
}
</style>
