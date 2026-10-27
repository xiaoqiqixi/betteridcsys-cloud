<script setup lang="ts">
import { computed, useId } from "vue";
import { LogOut, ShieldAlert, Server } from "@lucide/vue";
import UiOverlay from "./UiOverlay.vue";
import UiButton from "./UiButton.vue";

export interface IdentitySessionRevocationProps {
  open: boolean;
  targetLabel: string;
  targetId: string;
  self: boolean;
  reason: string;
  disabled: boolean;
  busy: boolean;
  labels: Record<string, string>;
}

const MAX_REASON_CODE_POINTS = 500;

const props = defineProps<IdentitySessionRevocationProps>();

const emit = defineEmits<{
  (e: "open"): void;
  (e: "close"): void;
  (e: "update:reason", value: string): void;
  (e: "confirm"): void;
}>();

const uid = useId();
const rowTitleId = `${uid}-row-title`;
const rowDescId = `${uid}-row-desc`;
const reasonInputId = `${uid}-reason-input`;
const reasonHintId = `${uid}-reason-hint`;

const reasonCodePoints = computed<number>(() => {
  return Array.from(props.reason || "").length;
});

const isNearLimit = computed<boolean>(() => {
  return reasonCodePoints.value >= 450;
});

const hasValidReason = computed<boolean>(() => {
  return Boolean(
    props.reason &&
    props.reason.trim() === props.reason &&
    Array.from(props.reason).length <= 500 &&
    !/[\p{Cc}\p{Cs}\u2028\u2029]/u.test(props.reason),
  );
});

const isDirty = computed<boolean>(() => {
  return hasValidReason.value;
});

const canConfirm = computed<boolean>(() => {
  return !props.disabled && !props.busy && hasValidReason.value;
});

const rowDescriptionText = computed<string>(() => {
  if (props.self && props.labels.rowSelfDescription) {
    return props.labels.rowSelfDescription;
  }
  return props.labels.rowDescription || "";
});

const scopeNoticeText = computed<string>(() => {
  if (props.self && props.labels.selfScopeNotice) {
    return props.labels.selfScopeNotice;
  }
  return props.labels.scopeNotice || "";
});

const confirmButtonText = computed<string>(() => {
  if (props.self && props.labels.confirmSelfAction) {
    return props.labels.confirmSelfAction;
  }
  return props.labels.confirmAction || "";
});

function handleOpen(): void {
  if (props.disabled || props.busy) return;
  emit("open");
}

function handleClose(): void {
  if (props.busy) return;
  emit("close");
}

function handleReasonInput(event: Event): void {
  if (props.disabled || props.busy) return;
  const target = event.target as HTMLInputElement;
  const codePoints = Array.from(target.value || "");
  const clipped =
    codePoints.length > MAX_REASON_CODE_POINTS
      ? codePoints.slice(0, MAX_REASON_CODE_POINTS).join("")
      : target.value;
  if (target.value !== clipped) {
    target.value = clipped;
  }
  emit("update:reason", clipped);
}

function handleConfirm(): void {
  if (!canConfirm.value) return;
  emit("confirm");
}
</script>

<template>
  <section
    class="aw-session-revoke"
    :aria-labelledby="rowTitleId"
    :aria-describedby="rowDescriptionText ? rowDescId : undefined"
  >
    <!-- Outer Low-Interference High-Consequence Ledger Row -->
    <div class="aw-revoke-ledger-row" :class="{ 'is-disabled': disabled }">
      <div class="aw-revoke-copy">
        <div class="aw-revoke-title-line">
          <LogOut class="aw-icon-row" aria-hidden="true" />
          <h4 :id="rowTitleId" class="aw-revoke-title">
            {{ labels.rowTitle }}
          </h4>
        </div>
        <p v-if="rowDescriptionText" :id="rowDescId" class="aw-revoke-desc">
          {{ rowDescriptionText }}
        </p>
      </div>

      <div class="aw-revoke-trigger">
        <UiButton
          variant="secondary"
          :busy="busy && !open"
          :disabled="disabled || busy"
          @click="handleOpen"
        >
          {{ labels.openAction }}
        </UiButton>
      </div>
    </div>

    <!-- Confirmation Overlay via Contract UiOverlay -->
    <UiOverlay
      :open="open"
      :title="labels.modalTitle"
      :busy="busy"
      :dirty="isDirty"
      :close-label="labels.closeLabel"
      :discard-label="labels.discardLabel"
      :continue-label="labels.continueLabel"
      @close="handleClose"
    >
      <div class="aw-revoke-dialog-body">
        <slot name="notice" />
        <!-- Target Identity Metadata Ledger (Read-only, wrappable) -->
        <dl class="aw-target-ledger">
          <div class="aw-target-row">
            <dt class="aw-target-term">{{ labels.targetAccountLabel }}</dt>
            <dd class="aw-target-val aw-target-name">{{ targetLabel }}</dd>
          </div>
          <div class="aw-target-row">
            <dt class="aw-target-term">{{ labels.targetIdLabel }}</dt>
            <dd class="aw-target-val">
              <code class="aw-target-id-code">{{ targetId }}</code>
            </dd>
          </div>
        </dl>

        <!-- Session Scope & Workload Safety Explanation -->
        <div class="aw-impact-ledger" role="note">
          <div
            class="aw-impact-item aw-impact-warn"
            :class="{ 'is-self': self }"
          >
            <ShieldAlert class="aw-icon-impact" aria-hidden="true" />
            <p class="aw-impact-text">{{ scopeNoticeText }}</p>
          </div>

          <div v-if="labels.vmSafeNotice" class="aw-impact-item aw-impact-safe">
            <Server class="aw-icon-impact" aria-hidden="true" />
            <p class="aw-impact-text">{{ labels.vmSafeNotice }}</p>
          </div>
        </div>

        <!-- Single-Line Mandatory Reason Input (500 Unicode Code Points) -->
        <div class="aw-reason-field">
          <div class="aw-reason-head">
            <label class="aw-reason-label" :for="reasonInputId">
              {{ labels.reasonLabel }}
            </label>
            <span
              class="aw-char-counter"
              :class="{ 'is-near-limit': isNearLimit }"
              aria-live="polite"
            >
              {{ reasonCodePoints }} / {{ MAX_REASON_CODE_POINTS }}
              <template v-if="labels.reasonCountSuffix">
                {{ labels.reasonCountSuffix }}
              </template>
            </span>
          </div>

          <input
            :id="reasonInputId"
            type="text"
            class="aw-reason-input"
            :value="reason"
            :placeholder="labels.reasonPlaceholder"
            :disabled="disabled || busy"
            autocomplete="off"
            required
            :aria-describedby="labels.reasonHint ? reasonHintId : undefined"
            @input="handleReasonInput"
            @keyup.enter="handleConfirm"
          />

          <p v-if="labels.reasonHint" :id="reasonHintId" class="aw-reason-hint">
            {{ labels.reasonHint }}
          </p>
        </div>
      </div>

      <template #footer>
        <div class="aw-revoke-footer-actions">
          <UiButton
            variant="secondary"
            :busy="false"
            :disabled="busy"
            @click="handleClose"
          >
            {{ labels.cancelAction }}
          </UiButton>

          <UiButton
            variant="danger"
            :busy="busy"
            :disabled="!canConfirm"
            @click="handleConfirm"
          >
            {{ confirmButtonText }}
          </UiButton>
        </div>
      </template>
    </UiOverlay>
  </section>
</template>

<style scoped>
.aw-session-revoke,
.aw-revoke-dialog-body {
  --aw-ledger-bg: var(--surface);
  --aw-ledger-surface: var(--subtle);
  --aw-ledger-border: var(--border);
  --aw-ledger-border-strong: var(--control-border);
  --aw-ledger-text: var(--text);
  --aw-ledger-text-secondary: var(--secondary);
  --aw-ledger-text-muted: var(--secondary);
  --aw-ledger-focus: var(--accent);

  --aw-warn-bg: var(--warning-bg);
  --aw-warn-border: var(--border);
  --aw-warn-text: var(--warning);
  --aw-warn-icon: var(--warning);

  --aw-danger-soft-bg: var(--danger-bg);
  --aw-danger-soft-border: var(--danger-border);
  --aw-danger-text: var(--danger);
  --aw-danger-icon: var(--danger);

  box-sizing: border-box;
  width: 100%;
  max-width: 100%;
  color: var(--aw-ledger-text);
  font-family:
    -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC",
    "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

:global([data-theme="dark"] .aw-session-revoke),
.aw-session-revoke[data-theme="dark"],
:global([data-theme="dark"] .aw-revoke-dialog-body),
.aw-revoke-dialog-body[data-theme="dark"] {
  --aw-ledger-bg: var(--surface);
  --aw-ledger-surface: var(--subtle);
  --aw-ledger-border: var(--border);
  --aw-ledger-border-strong: var(--control-border);
  --aw-ledger-text: var(--text);
  --aw-ledger-text-secondary: var(--secondary);
  --aw-ledger-text-muted: var(--secondary);
  --aw-ledger-focus: var(--accent);

  --aw-warn-bg: var(--warning-bg);
  --aw-warn-border: var(--border);
  --aw-warn-text: var(--warning);
  --aw-warn-icon: var(--warning);

  --aw-danger-soft-bg: var(--danger-bg);
  --aw-danger-soft-border: var(--danger-border);
  --aw-danger-text: var(--danger);
  --aw-danger-icon: var(--danger);
}

/* Outer Ledger Action Row */
.aw-revoke-ledger-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 0;
  border-top: 1px solid var(--aw-ledger-border);
  border-bottom: 1px solid var(--aw-ledger-border);
}

.aw-revoke-ledger-row.is-disabled {
  opacity: 0.72;
}

.aw-revoke-copy {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
  flex: 1 1 auto;
}

.aw-revoke-title-line {
  display: flex;
  align-items: center;
  gap: 8px;
}

.aw-icon-row {
  width: 16px;
  height: 16px;
  color: var(--aw-warn-icon);
  flex-shrink: 0;
}

.aw-revoke-title {
  margin: 0;
  font-size: 14px;
  font-weight: 600;
  color: var(--aw-ledger-text);
}

.aw-revoke-desc {
  margin: 0;
  font-size: 13px;
  color: var(--aw-ledger-text-secondary);
  word-break: break-word;
}

.aw-revoke-trigger {
  flex-shrink: 0;
}

.aw-revoke-trigger :deep(button),
.aw-revoke-footer-actions :deep(button) {
  min-height: 44px;
  min-width: 44px;
}

/* Overlay Body */
.aw-revoke-dialog-body {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

/* Target Identity Ledger */
.aw-target-ledger {
  margin: 0;
  border-top: 1px solid var(--aw-ledger-border-strong);
  border-bottom: 1px solid var(--aw-ledger-border-strong);
  background-color: var(--aw-ledger-surface);
}

.aw-target-row {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 4px 12px;
  padding: 9px 12px;
  border-bottom: 1px solid var(--aw-ledger-border);
}

.aw-target-row:last-child {
  border-bottom: none;
}

.aw-target-term {
  font-size: 13px;
  font-weight: 500;
  color: var(--aw-ledger-text-muted);
}

.aw-target-val {
  margin: 0;
  font-size: 14px;
  color: var(--aw-ledger-text);
  min-width: 0;
}

.aw-target-name {
  font-weight: 600;
  word-break: break-word;
}

.aw-target-id-code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 13px;
  color: var(--aw-ledger-text-secondary);
  word-break: break-all;
  white-space: normal;
}

/* Impact Notice Strip */
.aw-impact-ledger {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.aw-impact-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 12px;
  border-left: 3px solid transparent;
  font-size: 13px;
  line-height: 1.45;
}

.aw-impact-warn {
  background-color: var(--aw-warn-bg);
  border-top: 1px solid var(--aw-warn-border);
  border-bottom: 1px solid var(--aw-warn-border);
  border-left-color: var(--aw-warn-icon);
  color: var(--aw-warn-text);
}

.aw-impact-warn.is-self {
  background-color: var(--aw-danger-soft-bg);
  border-top-color: var(--aw-danger-soft-border);
  border-bottom-color: var(--aw-danger-soft-border);
  border-left-color: var(--aw-danger-icon);
  color: var(--aw-danger-text);
}

.aw-impact-safe {
  background-color: var(--aw-ledger-surface);
  border-top: 1px solid var(--aw-ledger-border);
  border-bottom: 1px solid var(--aw-ledger-border);
  border-left-color: var(--aw-ledger-border-strong);
  color: var(--aw-ledger-text-secondary);
}

.aw-icon-impact {
  width: 16px;
  height: 16px;
  margin-top: 2px;
  flex-shrink: 0;
}

.aw-impact-text {
  margin: 0;
  word-break: break-word;
}

/* Single-Line Reason Input */
.aw-reason-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.aw-reason-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
}

.aw-reason-label {
  font-size: 14px;
  font-weight: 600;
  color: var(--aw-ledger-text);
}

.aw-char-counter {
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  color: var(--aw-ledger-text-muted);
}

.aw-char-counter.is-near-limit {
  color: var(--aw-warn-icon);
  font-weight: 600;
}

.aw-reason-input {
  box-sizing: border-box;
  width: 100%;
  min-height: 44px;
  padding: 9px 12px;
  border: 1px solid var(--aw-ledger-border-strong);
  border-radius: 6px;
  background-color: var(--aw-ledger-bg);
  color: var(--aw-ledger-text);
  font-family: inherit;
  font-size: 15px;
  line-height: 1.4;
  transition: border-color 0.14s ease;
}

.aw-reason-input::placeholder {
  color: var(--aw-ledger-text-muted);
}

.aw-reason-input:hover:not(:disabled) {
  border-color: var(--aw-ledger-text-muted);
}

.aw-reason-input:focus-visible {
  outline: 2px solid var(--aw-ledger-focus);
  outline-offset: -1px;
}

.aw-reason-input:disabled {
  background-color: var(--aw-ledger-surface);
  color: var(--aw-ledger-text-muted);
  cursor: not-allowed;
}

.aw-reason-hint {
  margin: 0;
  font-size: 13px;
  color: var(--aw-ledger-text-muted);
}

/* Footer Actions */
.aw-revoke-footer-actions {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  width: 100%;
}

/* Mobile 320px / 375px / 430px Safety */
@media (max-width: 640px) {
  .aw-revoke-ledger-row {
    flex-direction: column;
    align-items: stretch;
    gap: 10px;
  }

  .aw-revoke-trigger :deep(button) {
    width: 100%;
    justify-content: center;
  }

  .aw-revoke-footer-actions {
    flex-direction: column-reverse;
    align-items: stretch;
  }

  .aw-revoke-footer-actions :deep(button) {
    width: 100%;
    justify-content: center;
  }
}

@media (prefers-reduced-motion: reduce) {
  .aw-reason-input {
    transition: none;
  }
}
</style>
