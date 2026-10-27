<script setup lang="ts">
import { computed, useId } from "vue";
import {
  AlertTriangle,
  FileSearch,
  Lock,
  Loader2,
  CheckCircle2,
} from "@lucide/vue";
import UiButton from "./UiButton.vue";

export type IdentityNoticeState =
  "conflict" | "uncertain" | "blocked" | "busy" | "confirmed";

export interface IdentityOperationNoticeProps {
  state: IdentityNoticeState;
  labels: Record<string, string>;
  operationId?: string;
  targetLabel?: string;
  baseRevision?: number;
  currentRevision?: number;
  busy: boolean;
}

/**
 * Expected `labels` keys (supports state-prefixed or generic keys):
 * - title / `${state}Title`: Headline for current state
 * - body / `${state}Body`: Primary operational explanation
 * - hint / `${state}Hint`: Secondary rule note (e.g. reload discards draft, receipt scope)
 * - targetPrefix: Label prefix for target account
 * - baseRevisionLabel / currentRevisionLabel: Labels for revision comparison
 * - operationIdLabel: Label for operation ID metadata row
 * - reloadAction: Button label for explicit reload in 'conflict' state
 * - inspectAction: Button label for verifying original operation in 'uncertain' state
 * - noticeAriaLabel: Accessible region label fallback
 */
const props = defineProps<IdentityOperationNoticeProps>();

const emit = defineEmits<{
  (e: "inspect"): void;
  (e: "reload"): void;
}>();

const uid = useId();
const titleId = `${uid}-title`;
const bodyId = `${uid}-body`;

const isBusyState = computed<boolean>(() => {
  return props.state === "busy" || Boolean(props.busy);
});

const titleText = computed<string>(() => {
  return props.labels[`${props.state}Title`] || props.labels.title || "";
});

const bodyText = computed<string>(() => {
  return (
    props.labels[`${props.state}Body`] ||
    props.labels.body ||
    props.labels.description ||
    ""
  );
});

const hintText = computed<string>(() => {
  return props.labels[`${props.state}Hint`] || props.labels.hint || "";
});

const reloadButtonLabel = computed<string>(() => {
  return props.labels.reloadAction || props.labels.reloadLabel || "";
});

const inspectButtonLabel = computed<string>(() => {
  return props.labels.inspectAction || props.labels.inspectLabel || "";
});

const showRevisionMeta = computed<boolean>(() => {
  return (
    props.state === "conflict" &&
    (props.baseRevision !== undefined || props.currentRevision !== undefined)
  );
});

const showDetailRow = computed<boolean>(() => {
  return Boolean(
    props.targetLabel ||
    showRevisionMeta.value ||
    (props.operationId && props.operationId.trim()),
  );
});

function handleReload(): void {
  if (props.busy || props.state !== "conflict") return;
  emit("reload");
}

function handleInspect(): void {
  if (props.busy || props.state !== "uncertain") return;
  emit("inspect");
}
</script>

<template>
  <section
    class="aw-op-notice"
    :class="[`is-state-${state}`, { 'is-busy': isBusyState }]"
    role="status"
    aria-live="polite"
    :aria-busy="isBusyState ? 'true' : 'false'"
    :aria-labelledby="titleText ? titleId : undefined"
    :aria-describedby="bodyText ? bodyId : undefined"
    :aria-label="!titleText ? labels.noticeAriaLabel : undefined"
  >
    <div class="aw-notice-main">
      <!-- Leading State Icon -->
      <div class="aw-notice-glyph" aria-hidden="true">
        <Loader2 v-if="state === 'busy'" class="aw-icon aw-spin" />
        <AlertTriangle v-else-if="state === 'conflict'" class="aw-icon" />
        <FileSearch v-else-if="state === 'uncertain'" class="aw-icon" />
        <Lock v-else-if="state === 'blocked'" class="aw-icon" />
        <CheckCircle2 v-else class="aw-icon" />
      </div>

      <!-- Primary Copy & Consequence Explanation -->
      <div class="aw-notice-copy">
        <h4 v-if="titleText" :id="titleId" class="aw-notice-title">
          {{ titleText }}
        </h4>

        <p v-if="bodyText" :id="bodyId" class="aw-notice-body">
          {{ bodyText }}
        </p>

        <p v-if="hintText" class="aw-notice-hint">
          {{ hintText }}
        </p>
      </div>

      <!-- Strictly Gated Single Action Slot (Only conflict->reload or uncertain->inspect) -->
      <div
        v-if="state === 'conflict' || state === 'uncertain'"
        class="aw-notice-actions"
      >
        <UiButton
          v-if="state === 'conflict'"
          variant="secondary"
          :busy="busy"
          :disabled="busy"
          @click="handleReload"
        >
          {{ reloadButtonLabel }}
        </UiButton>

        <UiButton
          v-else-if="state === 'uncertain'"
          variant="primary"
          :busy="busy"
          :disabled="busy"
          @click="handleInspect"
        >
          {{ inspectButtonLabel }}
        </UiButton>
      </div>
    </div>

    <!-- Secondary Ledger Detail Bar: Target, Revisions & Wrappable Operation ID -->
    <dl v-if="showDetailRow" class="aw-notice-details">
      <div v-if="targetLabel" class="aw-detail-item">
        <dt v-if="labels.targetPrefix" class="aw-detail-term">
          {{ labels.targetPrefix }}
        </dt>
        <dd class="aw-detail-val aw-detail-target">{{ targetLabel }}</dd>
      </div>

      <div
        v-if="showRevisionMeta && baseRevision !== undefined"
        class="aw-detail-item"
      >
        <dt v-if="labels.baseRevisionLabel" class="aw-detail-term">
          {{ labels.baseRevisionLabel }}
        </dt>
        <dd class="aw-detail-val aw-detail-code">#{{ baseRevision }}</dd>
      </div>

      <div
        v-if="showRevisionMeta && currentRevision !== undefined"
        class="aw-detail-item"
      >
        <dt v-if="labels.currentRevisionLabel" class="aw-detail-term">
          {{ labels.currentRevisionLabel }}
        </dt>
        <dd class="aw-detail-val aw-detail-code">#{{ currentRevision }}</dd>
      </div>

      <div v-if="operationId" class="aw-detail-item aw-detail-opid">
        <dt v-if="labels.operationIdLabel" class="aw-detail-term">
          {{ labels.operationIdLabel }}
        </dt>
        <dd class="aw-detail-val">
          <code class="aw-opid-code">{{ operationId }}</code>
        </dd>
      </div>
    </dl>
  </section>
</template>

<style scoped>
.aw-op-notice {
  --aw-ledger-bg: var(--surface);
  --aw-ledger-surface: var(--subtle);
  --aw-ledger-border: var(--border);
  --aw-ledger-border-strong: var(--control-border);
  --aw-ledger-text: var(--text);
  --aw-ledger-text-secondary: var(--secondary);
  --aw-ledger-text-muted: var(--secondary);

  /* Default / Busy (Info Tone) */
  --aw-notice-bg: #eff6ff;
  --aw-notice-border: #bfdbfe;
  --aw-notice-bar: #2563eb;
  --aw-notice-title: #1e3a8a;
  --aw-notice-icon: #2563eb;
  --aw-notice-meta-bg: rgba(255, 255, 255, 0.72);

  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 100%;
  border-top: 1px solid var(--aw-notice-border);
  border-bottom: 1px solid var(--aw-notice-border);
  border-left: 3px solid var(--aw-notice-bar);
  background-color: var(--aw-notice-bg);
  color: var(--aw-ledger-text);
  font-family:
    -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC",
    "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* State Tone Overrides (Light) */
.aw-op-notice.is-state-conflict,
.aw-op-notice.is-state-uncertain {
  --aw-notice-bg: #fffbeb;
  --aw-notice-border: #fde68a;
  --aw-notice-bar: #d97706;
  --aw-notice-title: #78350f;
  --aw-notice-icon: #d97706;
}

.aw-op-notice.is-state-blocked {
  --aw-notice-bg: #fef2f2;
  --aw-notice-border: #fecaca;
  --aw-notice-bar: #dc2626;
  --aw-notice-title: #7f1d1d;
  --aw-notice-icon: #dc2626;
}

.aw-op-notice.is-state-confirmed {
  --aw-notice-bg: #ecfdf5;
  --aw-notice-border: #a7f3d0;
  --aw-notice-bar: #10b981;
  --aw-notice-title: #064e3b;
  --aw-notice-icon: #059669;
}

/* Dark Theme Tokens */
:global([data-theme="dark"] .aw-op-notice),
.aw-op-notice[data-theme="dark"] {
  --aw-ledger-bg: var(--surface);
  --aw-ledger-surface: var(--subtle);
  --aw-ledger-border: var(--border);
  --aw-ledger-border-strong: var(--control-border);
  --aw-ledger-text: var(--text);
  --aw-ledger-text-secondary: var(--secondary);
  --aw-ledger-text-muted: var(--secondary);

  --aw-notice-bg: rgba(37, 99, 235, 0.12);
  --aw-notice-border: rgba(96, 165, 250, 0.32);
  --aw-notice-bar: #60a5fa;
  --aw-notice-title: #dbeafe;
  --aw-notice-icon: #60a5fa;
  --aw-notice-meta-bg: rgba(15, 23, 42, 0.55);
}

:global([data-theme="dark"] .aw-op-notice.is-state-conflict),
:global([data-theme="dark"] .aw-op-notice.is-state-uncertain),
.aw-op-notice[data-theme="dark"].is-state-conflict,
.aw-op-notice[data-theme="dark"].is-state-uncertain {
  --aw-notice-bg: rgba(245, 158, 11, 0.12);
  --aw-notice-border: rgba(251, 191, 36, 0.32);
  --aw-notice-bar: #fbbf24;
  --aw-notice-title: #fef3c7;
  --aw-notice-icon: #fbbf24;
}

:global([data-theme="dark"] .aw-op-notice.is-state-blocked),
.aw-op-notice[data-theme="dark"].is-state-blocked {
  --aw-notice-bg: rgba(239, 68, 68, 0.12);
  --aw-notice-border: rgba(248, 113, 113, 0.35);
  --aw-notice-bar: #f87171;
  --aw-notice-title: #fee2e2;
  --aw-notice-icon: #f87171;
}

:global([data-theme="dark"] .aw-op-notice.is-state-confirmed),
.aw-op-notice[data-theme="dark"].is-state-confirmed {
  --aw-notice-bg: rgba(16, 185, 129, 0.12);
  --aw-notice-border: rgba(52, 211, 153, 0.32);
  --aw-notice-bar: #34d399;
  --aw-notice-title: #d1fae5;
  --aw-notice-icon: #34d399;
}

/* Main Notice Row */
.aw-notice-main {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  min-width: 0;
}

.aw-notice-glyph {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 20px;
  height: 22px;
  color: var(--aw-notice-icon);
  flex-shrink: 0;
}

.aw-icon {
  width: 18px;
  height: 18px;
}

.aw-notice-copy {
  display: flex;
  flex-direction: column;
  gap: 4px;
  flex: 1 1 auto;
  min-width: 0;
}

.aw-notice-title {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
  line-height: 1.4;
  color: var(--aw-notice-title);
  word-break: break-word;
}

.aw-notice-body {
  margin: 0;
  font-size: 14px;
  color: var(--aw-ledger-text);
  word-break: break-word;
}

.aw-notice-hint {
  margin: 0;
  font-size: 13px;
  color: var(--aw-ledger-text-secondary);
  word-break: break-word;
}

.aw-notice-actions {
  display: flex;
  align-items: center;
  flex-shrink: 0;
  min-height: 44px;
}

.aw-notice-actions :deep(button) {
  min-height: 44px;
  min-width: 44px;
}

/* Secondary Metadata Ledger Strip */
.aw-notice-details {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 6px 16px;
  margin: 0;
  padding: 8px 14px 8px 44px;
  border-top: 1px solid var(--aw-notice-border);
  background-color: var(--aw-notice-meta-bg);
  font-size: 12px;
  line-height: 1.4;
}

.aw-detail-item {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 4px;
  min-width: 0;
}

.aw-detail-opid {
  flex: 1 1 100%;
}

.aw-detail-term {
  font-weight: 500;
  color: var(--aw-ledger-text-muted);
  white-space: nowrap;
}

.aw-detail-val {
  margin: 0;
  color: var(--aw-ledger-text-secondary);
  min-width: 0;
}

.aw-detail-target {
  font-weight: 600;
  word-break: break-word;
}

.aw-detail-code,
.aw-opid-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  color: var(--aw-ledger-text);
}

.aw-opid-code {
  word-break: break-all;
  white-space: normal;
}

@keyframes aw-notice-spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

.aw-spin {
  animation: aw-notice-spin 0.9s linear infinite;
}

/* Mobile Layout (320px / 375px / 390px / 430px) */
@media (max-width: 640px) {
  .aw-notice-main {
    flex-wrap: wrap;
    padding: 10px 12px;
  }

  .aw-notice-copy {
    flex: 1 1 calc(100% - 32px);
  }

  .aw-notice-actions {
    width: 100%;
    padding-left: 30px;
    margin-top: 4px;
  }

  .aw-notice-actions :deep(button) {
    width: 100%;
    justify-content: center;
  }

  .aw-notice-details {
    padding: 8px 12px;
    gap: 4px 12px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .aw-spin {
    animation: none;
  }
}
</style>
