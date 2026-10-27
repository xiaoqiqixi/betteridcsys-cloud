<script setup lang="ts">
import { computed, shallowRef } from "vue";
import {
  Copy,
  ChevronDown,
  ChevronUp,
  ArrowUpRight,
  Server,
} from "@lucide/vue";

export type InstanceStateTone =
  "success" | "warning" | "danger" | "neutral" | "info";

export interface InstanceLedgerItem {
  id: string;
  href: string;
  hostname: string;
  stateLabel: string;
  stateTone: InstanceStateTone;
  cpuLabel: string;
  memoryLabel: string;
  diskLabel: string;
  nodeLabel: string;
}

export interface InstanceLedgerLabels {
  title?: string;
  colInstance: string;
  colState: string;
  colSpec: string;
  colNode: string;
  colId?: string;
  colAction?: string;
  viewDetails: string;
  fullId: string;
  copyId?: string;
  expandId?: string;
  collapseId?: string;
  emptyText?: string;
}

export interface InstanceLedgerProps {
  items: InstanceLedgerItem[];
  labels: InstanceLedgerLabels;
}

const props = defineProps<InstanceLedgerProps>();

const emit = defineEmits<{
  (e: "copy-id", id: string): void;
}>();

const expandedIds = shallowRef<ReadonlySet<string>>(new Set());

const uiLabels = computed(() => ({
  title: props.labels.title ?? "",
  colInstance: props.labels.colInstance,
  colState: props.labels.colState,
  colSpec: props.labels.colSpec,
  colNode: props.labels.colNode,
  colId: props.labels.colId ?? props.labels.fullId,
  colAction: props.labels.colAction ?? props.labels.viewDetails,
  viewDetails: props.labels.viewDetails,
  fullId: props.labels.fullId,
  copyId: props.labels.copyId ?? props.labels.fullId,
  expandId: props.labels.expandId ?? props.labels.fullId,
  collapseId: props.labels.collapseId ?? props.labels.fullId,
  emptyText: props.labels.emptyText ?? "—",
}));

function isExpanded(id: string): boolean {
  return expandedIds.value.has(id);
}

function toggleExpandId(id: string): void {
  const next = new Set(expandedIds.value);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  expandedIds.value = next;
}

function handleCopyId(id: string): void {
  emit("copy-id", id);
}
</script>

<template>
  <section
    class="aw-instance-ledger"
    :aria-label="uiLabels.title || uiLabels.colInstance"
  >
    <!-- Empty Ledger State -->
    <div v-if="!items.length" class="aw-ledger-empty" role="status">
      <Server class="aw-icon-empty" aria-hidden="true" />
      <p class="aw-ledger-empty-text">{{ uiLabels.emptyText }}</p>
    </div>

    <template v-else>
      <!-- Desktop Semantic Table (>768px) -->
      <div class="aw-ledger-desktop">
        <table class="aw-ledger-table">
          <thead>
            <tr>
              <th scope="col" class="aw-col-instance">
                {{ uiLabels.colInstance }}
              </th>
              <th scope="col" class="aw-col-state">
                {{ uiLabels.colState }}
              </th>
              <th scope="col" class="aw-col-spec">
                {{ uiLabels.colSpec }}
              </th>
              <th scope="col" class="aw-col-node">
                {{ uiLabels.colNode }}
              </th>
              <th scope="col" class="aw-col-action">
                <span class="aw-sr-only">{{ uiLabels.colAction }}</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in items" :key="item.id" class="aw-ledger-row">
              <!-- Instance Hostname & Expandable/Copyable Full ID -->
              <td class="aw-cell-instance">
                <div class="aw-instance-primary">
                  <a
                    :href="item.href"
                    :title="item.hostname"
                    class="aw-hostname-link"
                  >
                    <span class="aw-hostname-text">{{ item.hostname }}</span>
                  </a>
                </div>

                <div class="aw-id-bar">
                  <button
                    type="button"
                    class="aw-id-toggle-btn"
                    :aria-expanded="isExpanded(item.id) ? 'true' : 'false'"
                    :aria-label="
                      isExpanded(item.id)
                        ? `${uiLabels.collapseId}: ${item.id}`
                        : `${uiLabels.expandId}: ${item.id}`
                    "
                    @click="toggleExpandId(item.id)"
                  >
                    <span class="aw-id-prefix">{{ uiLabels.fullId }}:</span>
                    <code
                      class="aw-id-code"
                      :class="{ 'is-expanded': isExpanded(item.id) }"
                      >{{ item.id }}</code
                    >
                    <ChevronUp
                      v-if="isExpanded(item.id)"
                      class="aw-icon-xs"
                      aria-hidden="true"
                    />
                    <ChevronDown v-else class="aw-icon-xs" aria-hidden="true" />
                  </button>

                  <button
                    type="button"
                    class="aw-copy-btn"
                    :aria-label="`${uiLabels.copyId}: ${item.id}`"
                    :title="`${uiLabels.copyId}: ${item.id}`"
                    @click="handleCopyId(item.id)"
                  >
                    <Copy class="aw-icon-sm" aria-hidden="true" />
                  </button>
                </div>
              </td>

              <!-- State Badge -->
              <td class="aw-cell-state">
                <span
                  class="aw-state-badge"
                  :class="`is-tone-${item.stateTone}`"
                >
                  <span class="aw-state-dot" aria-hidden="true"></span>
                  <span class="aw-state-text">{{ item.stateLabel }}</span>
                </span>
              </td>

              <!-- Specs: CPU / Memory / Disk -->
              <td class="aw-cell-spec">
                <div class="aw-spec-inline">
                  <span class="aw-spec-token">{{ item.cpuLabel }}</span>
                  <span class="aw-spec-sep" aria-hidden="true">·</span>
                  <span class="aw-spec-token">{{ item.memoryLabel }}</span>
                  <span class="aw-spec-sep" aria-hidden="true">·</span>
                  <span class="aw-spec-token">{{ item.diskLabel }}</span>
                </div>
              </td>

              <!-- Node -->
              <td class="aw-cell-node">
                <span class="aw-node-badge">{{ item.nodeLabel }}</span>
              </td>

              <!-- Nearby Details Anchor -->
              <td class="aw-cell-action">
                <a
                  :href="item.href"
                  :title="item.hostname"
                  class="aw-details-link"
                  :aria-label="`${uiLabels.viewDetails} — ${item.hostname}`"
                >
                  <span>{{ uiLabels.viewDetails }}</span>
                  <ArrowUpRight class="aw-icon-sm" aria-hidden="true" />
                </a>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Mobile Compact Continuous Ledger (<=768px: 320px / 375px / 430px) -->
      <ul class="aw-ledger-mobile" role="list">
        <li v-for="item in items" :key="item.id" class="aw-mobile-item">
          <!-- Line 1: Hostname Anchor + State Badge -->
          <div class="aw-mobile-line-top">
            <a
              :href="item.href"
              :title="item.hostname"
              class="aw-mobile-hostname-link"
            >
              <span class="aw-hostname-text">{{ item.hostname }}</span>
            </a>

            <span class="aw-state-badge" :class="`is-tone-${item.stateTone}`">
              <span class="aw-state-dot" aria-hidden="true"></span>
              <span class="aw-state-text">{{ item.stateLabel }}</span>
            </span>
          </div>

          <!-- Line 2: Specs (CPU / Memory / Disk) + Node -->
          <div class="aw-mobile-line-meta">
            <div class="aw-mobile-spec-group" :aria-label="uiLabels.colSpec">
              <span class="aw-spec-token">{{ item.cpuLabel }}</span>
              <span class="aw-spec-sep" aria-hidden="true">·</span>
              <span class="aw-spec-token">{{ item.memoryLabel }}</span>
              <span class="aw-spec-sep" aria-hidden="true">·</span>
              <span class="aw-spec-token">{{ item.diskLabel }}</span>
            </div>

            <div class="aw-mobile-node-group" :aria-label="uiLabels.colNode">
              <span class="aw-node-label-prefix">{{ uiLabels.colNode }}:</span>
              <span class="aw-node-badge">{{ item.nodeLabel }}</span>
            </div>
          </div>

          <!-- Line 3: Expandable Full ID + Copy Trigger + Nearby Details Anchor -->
          <div class="aw-mobile-line-actions">
            <div class="aw-mobile-id-controls">
              <button
                type="button"
                class="aw-id-toggle-btn"
                :aria-expanded="isExpanded(item.id) ? 'true' : 'false'"
                :aria-label="
                  isExpanded(item.id)
                    ? `${uiLabels.collapseId}: ${item.id}`
                    : `${uiLabels.expandId}: ${item.id}`
                "
                @click="toggleExpandId(item.id)"
              >
                <span class="aw-id-prefix">{{ uiLabels.fullId }}</span>
                <code v-if="!isExpanded(item.id)" class="aw-id-code-short">{{
                  item.id
                }}</code>
                <ChevronUp
                  v-if="isExpanded(item.id)"
                  class="aw-icon-xs"
                  aria-hidden="true"
                />
                <ChevronDown v-else class="aw-icon-xs" aria-hidden="true" />
              </button>

              <button
                type="button"
                class="aw-copy-btn"
                :aria-label="`${uiLabels.copyId}: ${item.id}`"
                :title="`${uiLabels.copyId}: ${item.id}`"
                @click="handleCopyId(item.id)"
              >
                <Copy class="aw-icon-sm" aria-hidden="true" />
              </button>
            </div>

            <a
              :href="item.href"
              :title="item.hostname"
              class="aw-details-link aw-mobile-details-link"
              :aria-label="`${uiLabels.viewDetails} — ${item.hostname}`"
            >
              <span>{{ uiLabels.viewDetails }}</span>
              <ArrowUpRight class="aw-icon-sm" aria-hidden="true" />
            </a>
          </div>

          <!-- Expanded Full ID Drawer Row (Never Truncated) -->
          <div v-if="isExpanded(item.id)" class="aw-mobile-id-drawer">
            <span class="aw-id-drawer-label">{{ uiLabels.fullId }}:</span>
            <code class="aw-id-drawer-value">{{ item.id }}</code>
          </div>
        </li>
      </ul>
    </template>
  </section>
</template>

<style scoped>
.aw-instance-ledger {
  --aw-ledger-bg: var(--surface);
  --aw-ledger-header-bg: var(--subtle);
  --aw-ledger-row-hover: var(--hover);
  --aw-ledger-border: var(--border);
  --aw-ledger-border-strong: var(--border);
  --aw-ledger-text: var(--text);
  --aw-ledger-text-secondary: var(--secondary);
  --aw-ledger-text-muted: var(--muted);
  --aw-ledger-link: var(--accent-text);
  --aw-ledger-link-hover: var(--accent-hover);
  --aw-ledger-surface-subtle: var(--subtle);
  --aw-ledger-focus: var(--accent);
  --aw-tone-success-bg: var(--success-bg);
  --aw-tone-success-text: var(--success);
  --aw-tone-success-border: transparent;
  --aw-tone-success-dot: var(--success);
  --aw-tone-warning-bg: var(--warning-bg);
  --aw-tone-warning-text: var(--warning);
  --aw-tone-warning-border: transparent;
  --aw-tone-warning-dot: var(--warning);
  --aw-tone-danger-bg: var(--danger-bg);
  --aw-tone-danger-text: var(--danger);
  --aw-tone-danger-border: transparent;
  --aw-tone-danger-dot: var(--danger);
  --aw-tone-info-bg: var(--accent-bg);
  --aw-tone-info-text: var(--accent-text);
  --aw-tone-info-border: transparent;
  --aw-tone-info-dot: var(--accent-text);
  --aw-tone-neutral-bg: var(--hover);
  --aw-tone-neutral-text: var(--secondary);
  --aw-tone-neutral-border: transparent;
  --aw-tone-neutral-dot: var(--secondary);

  box-sizing: border-box;
  width: 100%;
  max-width: 100%;
  background-color: var(--aw-ledger-bg);
  border-top: 1px solid var(--aw-ledger-border-strong);
  border-bottom: 1px solid var(--aw-ledger-border-strong);
  color: var(--aw-ledger-text);
  font-family:
    -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC",
    "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  font-size: 14px;
  line-height: 1.45;
  -webkit-font-smoothing: antialiased;
}

.aw-sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

/* Empty State */
.aw-ledger-empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 36px 16px;
  color: var(--aw-ledger-text-muted);
  text-align: center;
}

.aw-icon-empty {
  width: 22px;
  height: 22px;
  opacity: 0.75;
}

.aw-ledger-empty-text {
  margin: 0;
  font-size: 14px;
}

/* Desktop Table View */
.aw-ledger-desktop {
  width: 100%;
  overflow-x: hidden;
}

.aw-ledger-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  font-size: 14px;
}

.aw-ledger-table th {
  padding: 10px 12px;
  background-color: var(--aw-ledger-header-bg);
  border-bottom: 1px solid var(--aw-ledger-border-strong);
  color: var(--aw-ledger-text-secondary);
  font-size: 13px;
  font-weight: 600;
  text-align: left;
  letter-spacing: 0.01em;
}

.aw-col-instance {
  width: 34%;
}

.aw-col-state {
  width: 14%;
}

.aw-col-spec {
  width: 24%;
}

.aw-col-node {
  width: 14%;
}

.aw-col-action {
  width: 14%;
  text-align: right;
}

.aw-ledger-row {
  border-bottom: 1px solid var(--aw-ledger-border);
  transition: background-color 0.12s ease;
}

.aw-ledger-row:last-child {
  border-bottom: none;
}

.aw-ledger-row:hover {
  background-color: var(--aw-ledger-row-hover);
}

.aw-ledger-table td {
  padding: 10px 12px;
  vertical-align: middle;
  font-size: 14px;
}

/* Instance Column */
.aw-instance-primary {
  display: flex;
  align-items: center;
  min-width: 0;
}

.aw-hostname-link,
.aw-mobile-hostname-link {
  display: inline-flex;
  align-items: center;
  min-height: 44px;
  padding: 0 4px;
  margin-left: -4px;
  border-radius: 6px;
  color: var(--aw-ledger-text);
  font-size: 15px;
  font-weight: 600;
  text-decoration: none;
  min-width: 0;
  max-width: 100%;
  transition: color 0.12s ease;
}

.aw-hostname-link:hover,
.aw-mobile-hostname-link:hover {
  color: var(--aw-ledger-link);
  text-decoration: underline;
  text-underline-offset: 3px;
}

.aw-hostname-text {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* ID Bar & Controls */
.aw-id-bar {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-top: 2px;
  min-width: 0;
}

.aw-id-toggle-btn {
  min-width: 0;
  flex: 1 1 auto;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  min-height: 44px;
  min-width: 44px;
  max-width: 100%;
  padding: 4px 8px;
  border: 1px solid transparent;
  border-radius: 6px;
  background-color: var(--aw-ledger-surface-subtle);
  color: var(--aw-ledger-text-secondary);
  font-family: inherit;
  font-size: 13px;
  cursor: pointer;
  text-align: left;
  transition:
    border-color 0.12s ease,
    color 0.12s ease;
}

.aw-id-toggle-btn:hover {
  border-color: var(--aw-ledger-border-strong);
  color: var(--aw-ledger-text);
}

.aw-id-prefix {
  color: var(--aw-ledger-text-muted);
  font-weight: 500;
  white-space: nowrap;
  flex-shrink: 0;
}

.aw-id-code {
  min-width: 0;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
  color: var(--aw-ledger-text);
  max-width: 150px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.aw-id-code.is-expanded {
  max-width: none;
  white-space: normal;
  word-break: break-all;
}

.aw-copy-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 44px;
  min-height: 44px;
  padding: 0 10px;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: var(--aw-ledger-text-muted);
  cursor: pointer;
  flex-shrink: 0;
  transition:
    background-color 0.12s ease,
    color 0.12s ease;
}

.aw-copy-btn:hover {
  background-color: var(--aw-ledger-surface-subtle);
  color: var(--aw-ledger-text);
}

/* State Badge */
.aw-state-badge {
  max-width: 100%;
  overflow-wrap: anywhere;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid transparent;
  font-size: 13px;
  font-weight: 600;
  line-height: 1.2;
  white-space: normal;
  flex-shrink: 0;
}

.aw-state-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}

.aw-state-badge.is-tone-success {
  background-color: var(--aw-tone-success-bg);
  color: var(--aw-tone-success-text);
  border-color: var(--aw-tone-success-border);
}
.aw-state-badge.is-tone-success .aw-state-dot {
  background-color: var(--aw-tone-success-dot);
}

.aw-state-badge.is-tone-warning {
  background-color: var(--aw-tone-warning-bg);
  color: var(--aw-tone-warning-text);
  border-color: var(--aw-tone-warning-border);
}
.aw-state-badge.is-tone-warning .aw-state-dot {
  background-color: var(--aw-tone-warning-dot);
}

.aw-state-badge.is-tone-danger {
  background-color: var(--aw-tone-danger-bg);
  color: var(--aw-tone-danger-text);
  border-color: var(--aw-tone-danger-border);
}
.aw-state-badge.is-tone-danger .aw-state-dot {
  background-color: var(--aw-tone-danger-dot);
}

.aw-state-badge.is-tone-info {
  background-color: var(--aw-tone-info-bg);
  color: var(--aw-tone-info-text);
  border-color: var(--aw-tone-info-border);
}
.aw-state-badge.is-tone-info .aw-state-dot {
  background-color: var(--aw-tone-info-dot);
}

.aw-state-badge.is-tone-neutral {
  background-color: var(--aw-tone-neutral-bg);
  color: var(--aw-tone-neutral-text);
  border-color: var(--aw-tone-neutral-border);
}
.aw-state-badge.is-tone-neutral .aw-state-dot {
  background-color: var(--aw-tone-neutral-dot);
}

/* Specs & Node */
.aw-spec-inline {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 5px;
  font-size: 14px;
  color: var(--aw-ledger-text);
  font-variant-numeric: tabular-nums;
}

.aw-spec-token {
  font-weight: 500;
}

.aw-spec-sep {
  color: var(--aw-ledger-text-muted);
}

.aw-node-badge {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 5px;
  background-color: var(--aw-ledger-surface-subtle);
  color: var(--aw-ledger-text-secondary);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
  font-weight: 500;
  word-break: break-word;
}

/* Action Link */
.aw-cell-action {
  text-align: right;
}

.aw-details-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
  min-height: 44px;
  min-width: 44px;
  padding: 0 10px;
  border-radius: 6px;
  color: var(--aw-ledger-link);
  font-size: 14px;
  font-weight: 600;
  text-decoration: none;
  white-space: nowrap;
  transition:
    background-color 0.12s ease,
    color 0.12s ease;
}

.aw-details-link:hover {
  background-color: var(--aw-ledger-surface-subtle);
  color: var(--aw-ledger-link-hover);
}

.aw-icon-xs {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
}

.aw-icon-sm {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

/* Mobile Continuous Ledger (Hidden on Desktop) */
.aw-ledger-mobile {
  display: none;
  list-style: none;
  margin: 0;
  padding: 0;
  width: 100%;
}

/* Focus Visibility */
.aw-hostname-link:focus-visible,
.aw-mobile-hostname-link:focus-visible,
.aw-id-toggle-btn:focus-visible,
.aw-copy-btn:focus-visible,
.aw-details-link:focus-visible {
  outline: 2px solid var(--aw-ledger-focus);
  outline-offset: 2px;
}

/* Responsive Switch: <=768px (Covers 320px, 375px, 430px) */
@media (max-width: 768px) {
  .aw-ledger-desktop {
    display: none;
  }

  .aw-ledger-mobile {
    display: block;
  }

  .aw-mobile-item {
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    gap: 6px;
    width: 100%;
    padding: 10px 12px;
    border-bottom: 1px solid var(--aw-ledger-border);
  }

  .aw-mobile-item:last-child {
    border-bottom: none;
  }

  /* Line 1: Hostname + State */
  .aw-mobile-line-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    min-width: 0;
  }

  .aw-mobile-hostname-link .aw-hostname-text {
    white-space: normal;
    overflow-wrap: anywhere;
  }

  .aw-mobile-line-top .aw-state-badge {
    max-width: 44%;
  }

  .aw-mobile-hostname-link {
    flex: 1 1 auto;
    min-width: 0;
  }

  /* Line 2: Specs + Node */
  .aw-mobile-line-meta {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 6px 12px;
    font-size: 14px;
    color: var(--aw-ledger-text-secondary);
  }

  .aw-mobile-spec-group {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
    min-width: 0;
    color: var(--aw-ledger-text);
  }

  .aw-mobile-node-group {
    min-width: 0;
    max-width: 100%;
    overflow-wrap: anywhere;
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-size: 13px;
  }

  .aw-node-label-prefix {
    white-space: nowrap;
    flex-shrink: 0;
    color: var(--aw-ledger-text-muted);
  }

  /* Line 3: ID Expand/Copy + Details Anchor */
  .aw-mobile-line-actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
    min-width: 0;
  }

  .aw-mobile-id-controls {
    display: flex;
    align-items: center;
    gap: 4px;
    min-width: 0;
    flex: 1 1 auto;
  }

  .aw-id-code-short {
    font-family:
      ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 13px;
    color: var(--aw-ledger-text);
    max-width: 96px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .aw-mobile-details-link {
    padding: 0 8px;
    flex-shrink: 0;
  }

  /* Full ID Expanded Drawer */
  .aw-mobile-id-drawer {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 8px 10px;
    border-radius: 6px;
    background-color: var(--aw-ledger-surface-subtle);
    border: 1px solid var(--aw-ledger-border-strong);
  }

  .aw-id-drawer-label {
    font-size: 12px;
    font-weight: 600;
    color: var(--aw-ledger-text-muted);
  }

  .aw-id-drawer-value {
    font-family:
      ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 13px;
    color: var(--aw-ledger-text);
    word-break: break-all;
    white-space: normal;
  }
}

/* Ultra-narrow safety (320px) */
@media (max-width: 359px) {
  .aw-mobile-item {
    padding: 8px 8px;
  }

  .aw-id-code-short {
    max-width: 68px;
  }
}

/* Reduced Motion */
@media (prefers-reduced-motion: reduce) {
  .aw-ledger-row,
  .aw-hostname-link,
  .aw-mobile-hostname-link,
  .aw-id-toggle-btn,
  .aw-copy-btn,
  .aw-details-link {
    transition: none;
  }
}
</style>
