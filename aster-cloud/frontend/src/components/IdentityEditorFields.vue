<script setup lang="ts">
import { computed, useId } from "vue";
import { Lock, Check } from "@lucide/vue";
import UiSelect from "./UiSelect.vue";

export interface IdentityEditorModel {
  name: string;
  email: string;
  password: string;
  role: string;
  enabled: boolean;
  permissions: string[];
  reason: string;
}

export interface IdentityOptionItem {
  value: string;
  label: string;
}

export interface IdentityEditorFieldsProps {
  modelValue: IdentityEditorModel;
  editing: boolean;
  self: boolean;
  disabled: boolean;
  roleOptions: IdentityOptionItem[];
  permissionOptions: IdentityOptionItem[];
  labels: Record<string, string>;
}

const REASON_MAX_LENGTH = 500;
const uid = useId();

const props = defineProps<IdentityEditorFieldsProps>();

const emit = defineEmits<{
  (e: "update:modelValue", value: IdentityEditorModel): void;
}>();

const accessLocked = computed<boolean>(() => {
  return Boolean(props.disabled || props.self);
});

const reasonLength = computed<number>(() => {
  return props.modelValue.reason
    ? Array.from(props.modelValue.reason).length
    : 0;
});

const isReasonNearLimit = computed<boolean>(() => {
  return reasonLength.value >= 450;
});

function cloneAndEmit(patch: Partial<IdentityEditorModel>): void {
  if (props.disabled) return;

  const clonedPermissions =
    patch.permissions !== undefined
      ? [...patch.permissions]
      : [...props.modelValue.permissions];

  const nextModel: IdentityEditorModel = {
    name: patch.name !== undefined ? patch.name : props.modelValue.name,
    email: patch.email !== undefined ? patch.email : props.modelValue.email,
    password:
      patch.password !== undefined ? patch.password : props.modelValue.password,
    role: patch.role !== undefined ? patch.role : props.modelValue.role,
    enabled:
      patch.enabled !== undefined ? patch.enabled : props.modelValue.enabled,
    permissions: clonedPermissions,
    reason: patch.reason !== undefined ? patch.reason : props.modelValue.reason,
  };

  emit("update:modelValue", nextModel);
}

function handleNameInput(event: Event): void {
  const target = event.target as HTMLInputElement;
  cloneAndEmit({ name: target.value });
}

function handleEmailInput(event: Event): void {
  const target = event.target as HTMLInputElement;
  cloneAndEmit({ email: target.value });
}

function handlePasswordInput(event: Event): void {
  const target = event.target as HTMLInputElement;
  cloneAndEmit({ password: target.value });
}

function handleRoleUpdate(nextRole: string): void {
  if (accessLocked.value) return;
  cloneAndEmit({ role: nextRole });
}

function handleToggleEnabled(): void {
  if (accessLocked.value || !props.editing) return;
  cloneAndEmit({ enabled: !props.modelValue.enabled });
}

function hasPermission(permValue: string): boolean {
  return props.modelValue.permissions.includes(permValue);
}

function handleTogglePermission(permValue: string): void {
  if (accessLocked.value || props.modelValue.role !== "custom") return;
  const current = [...props.modelValue.permissions];
  const index = current.indexOf(permValue);
  if (index >= 0) {
    current.splice(index, 1);
  } else {
    current.push(permValue);
  }
  cloneAndEmit({ permissions: current });
}

function handleReasonInput(event: Event): void {
  const target = event.target as HTMLTextAreaElement;
  const clipped = Array.from(target.value).slice(0, REASON_MAX_LENGTH).join("");
  if (target.value !== clipped) target.value = clipped;
  cloneAndEmit({ reason: clipped });
}
</script>

<template>
  <div
    class="aw-identity-fields"
    :class="{ 'is-disabled': disabled }"
    role="group"
    :aria-label="labels.formAriaLabel || labels.sectionIdentity"
  >
    <!-- Section 1: Identity & Credentials -->
    <section
      class="aw-ledger-section"
      :aria-labelledby="
        labels.sectionIdentity ? `${uid}-aw-sec-identity` : undefined
      "
    >
      <header v-if="labels.sectionIdentity" class="aw-section-header">
        <h4 :id="`${uid}-aw-sec-identity`" class="aw-section-title">
          {{ labels.sectionIdentity }}
        </h4>
      </header>

      <div class="aw-field-grid">
        <!-- Name Field -->
        <div class="aw-field">
          <label class="aw-label" :for="`${uid}-aw-identity-name`">
            {{ labels.nameLabel }}
          </label>
          <input
            :id="`${uid}-aw-identity-name`"
            type="text"
            class="aw-input"
            :value="modelValue.name"
            :placeholder="labels.namePlaceholder"
            :disabled="disabled"
            autocomplete="name"
            spellcheck="false"
            @input="handleNameInput"
          />
        </div>

        <!-- Email Field -->
        <div class="aw-field">
          <label class="aw-label" :for="`${uid}-aw-identity-email`">
            {{ labels.emailLabel }}
          </label>
          <input
            :id="`${uid}-aw-identity-email`"
            type="email"
            class="aw-input"
            :value="modelValue.email"
            :placeholder="labels.emailPlaceholder"
            :disabled="disabled"
            inputmode="email"
            autocomplete="username"
            autocapitalize="none"
            spellcheck="false"
            @input="handleEmailInput"
          />
        </div>
      </div>

      <!-- Password Field (Write-only, never echoed in summaries) -->
      <div class="aw-field">
        <label class="aw-label" :for="`${uid}-aw-identity-password`">
          {{ labels.passwordLabel }}
        </label>
        <input
          :id="`${uid}-aw-identity-password`"
          type="password"
          class="aw-input"
          :value="modelValue.password"
          :placeholder="labels.passwordPlaceholder"
          :disabled="disabled"
          autocomplete="new-password"
          spellcheck="false"
          :aria-describedby="
            labels.passwordHint ? `${uid}-aw-identity-password-hint` : undefined
          "
          @input="handlePasswordInput"
        />
        <p
          v-if="labels.passwordHint"
          :id="`${uid}-aw-identity-password-hint`"
          class="aw-field-hint"
        >
          {{ labels.passwordHint }}
        </p>
      </div>
    </section>

    <!-- Section 2: Role, Account State & Granular Permissions -->
    <section
      class="aw-ledger-section"
      :aria-labelledby="
        labels.sectionAccess ? `${uid}-aw-sec-access` : undefined
      "
    >
      <header
        v-if="labels.sectionAccess || (self && labels.selfLockNotice)"
        class="aw-section-header"
      >
        <h4
          v-if="labels.sectionAccess"
          :id="`${uid}-aw-sec-access`"
          class="aw-section-title"
        >
          {{ labels.sectionAccess }}
        </h4>

        <!-- Self-Account Privilege Lock Banner -->
        <div
          v-if="self && labels.selfLockNotice"
          class="aw-self-lock-banner"
          role="note"
        >
          <Lock class="aw-icon-lock" aria-hidden="true" />
          <span>{{ labels.selfLockNotice }}</span>
        </div>
      </header>

      <!-- Role Selection via Contract UiSelect -->
      <div class="aw-field">
        <UiSelect
          :model-value="modelValue.role"
          :options="roleOptions"
          :label="labels.roleLabel"
          :disabled="accessLocked"
          @update:model-value="handleRoleUpdate"
        />
      </div>

      <!-- Account Enabled Switch (Shown only when editing === true) -->
      <div v-if="editing" class="aw-field">
        <div
          class="aw-switch-ledger-row"
          :class="{ 'is-locked': accessLocked }"
        >
          <div class="aw-switch-copy">
            <span :id="`${uid}-aw-identity-enabled-label`" class="aw-label">
              {{ labels.enabledLabel }}
            </span>
            <span
              v-if="labels.enabledHint"
              :id="`${uid}-aw-identity-enabled-hint`"
              class="aw-field-hint"
            >
              {{ labels.enabledHint }}
            </span>
          </div>

          <button
            type="button"
            role="switch"
            class="aw-switch-btn"
            :class="{ 'is-on': modelValue.enabled }"
            :aria-checked="modelValue.enabled ? 'true' : 'false'"
            :aria-labelledby="`${uid}-aw-identity-enabled-label`"
            :aria-describedby="
              labels.enabledHint ? `${uid}-aw-identity-enabled-hint` : undefined
            "
            :disabled="accessLocked"
            @click="handleToggleEnabled"
          >
            <span class="aw-switch-track" aria-hidden="true">
              <span class="aw-switch-thumb"></span>
            </span>
            <span class="aw-switch-state-text">
              {{ modelValue.enabled ? labels.enabledOn : labels.enabledOff }}
            </span>
          </button>
        </div>
      </div>

      <!-- Authorizable Permissions Ledger Matrix -->
      <div class="aw-field">
        <div class="aw-field-head">
          <span :id="`${uid}-aw-identity-perms-label`" class="aw-label">
            {{ labels.permissionsLabel }}
          </span>
          <span
            v-if="labels.permissionsHint"
            :id="`${uid}-aw-identity-perms-hint`"
            class="aw-field-hint"
          >
            {{ labels.permissionsHint }}
          </span>
        </div>

        <div
          v-if="permissionOptions.length"
          class="aw-perm-ledger"
          role="group"
          :aria-labelledby="`${uid}-aw-identity-perms-label`"
          :aria-describedby="
            labels.permissionsHint ? `${uid}-aw-identity-perms-hint` : undefined
          "
        >
          <button
            v-for="perm in permissionOptions"
            :key="perm.value"
            type="button"
            role="checkbox"
            class="aw-perm-row"
            :class="{
              'is-checked': hasPermission(perm.value),
              'is-locked': accessLocked || modelValue.role !== 'custom',
            }"
            :aria-checked="hasPermission(perm.value) ? 'true' : 'false'"
            :disabled="accessLocked || modelValue.role !== 'custom'"
            @click="handleTogglePermission(perm.value)"
          >
            <span class="aw-perm-check" aria-hidden="true">
              <Check v-if="hasPermission(perm.value)" class="aw-icon-check" />
            </span>
            <span class="aw-perm-main">
              <span class="aw-perm-label">{{ perm.label }}</span>
              <code class="aw-perm-code">{{ perm.value }}</code>
            </span>
          </button>
        </div>

        <div v-else class="aw-perm-empty">
          {{ labels.permissionsEmpty }}
        </div>
      </div>
    </section>

    <!-- Section 3: Mandatory Change Reason (500 character limit) -->
    <section
      class="aw-ledger-section aw-ledger-section-last"
      :aria-labelledby="
        labels.sectionReason ? `${uid}-aw-sec-reason` : undefined
      "
    >
      <header v-if="labels.sectionReason" class="aw-section-header">
        <h4 :id="`${uid}-aw-sec-reason`" class="aw-section-title">
          {{ labels.sectionReason }}
        </h4>
      </header>

      <div class="aw-field">
        <div class="aw-reason-label-bar">
          <label class="aw-label" :for="`${uid}-aw-identity-reason`">
            {{ labels.reasonLabel }}
          </label>
          <span
            class="aw-char-counter"
            :class="{ 'is-near-limit': isReasonNearLimit }"
            aria-live="polite"
          >
            {{ reasonLength }} / {{ REASON_MAX_LENGTH }}
            <template v-if="labels.reasonCountSuffix">
              {{ labels.reasonCountSuffix }}
            </template>
          </span>
        </div>

        <textarea
          :id="`${uid}-aw-identity-reason`"
          class="aw-textarea"
          rows="3"
          :maxlength="REASON_MAX_LENGTH * 2"
          :value="modelValue.reason"
          :placeholder="labels.reasonPlaceholder"
          :disabled="disabled"
          required
          :aria-describedby="
            labels.reasonHint ? `${uid}-aw-identity-reason-hint` : undefined
          "
          @input="handleReasonInput"
        ></textarea>

        <p
          v-if="labels.reasonHint"
          :id="`${uid}-aw-identity-reason-hint`"
          class="aw-field-hint"
        >
          {{ labels.reasonHint }}
        </p>
      </div>
    </section>
  </div>
</template>

<style scoped>
.aw-identity-fields {
  --aw-ed-bg: var(--surface);
  --aw-ed-surface: var(--subtle);
  --aw-ed-surface-hover: var(--hover);
  --aw-ed-border: var(--border);
  --aw-ed-border-strong: var(--control-border);
  --aw-ed-text: var(--text);
  --aw-ed-text-secondary: var(--secondary);
  --aw-ed-text-muted: var(--secondary);
  --aw-ed-accent: var(--accent);
  --aw-ed-accent-soft: var(--accent-bg);
  --aw-ed-accent-border: var(--accent);
  --aw-ed-lock-bg: var(--warning-bg);
  --aw-ed-lock-border: var(--border);
  --aw-ed-lock-text: var(--warning);
  --aw-ed-success: var(--success);
  --aw-ed-warn: var(--warning);
  --aw-ed-focus: var(--accent);

  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  width: 100%;
  max-width: 100%;
  color: var(--aw-ed-text);
  font-family:
    -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC",
    "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

:global([data-theme="dark"] .aw-identity-fields),
.aw-identity-fields[data-theme="dark"] {
  --aw-ed-bg: var(--surface);
  --aw-ed-surface: var(--subtle);
  --aw-ed-surface-hover: var(--hover);
  --aw-ed-border: var(--border);
  --aw-ed-border-strong: var(--control-border);
  --aw-ed-text: var(--text);
  --aw-ed-text-secondary: var(--secondary);
  --aw-ed-text-muted: var(--secondary);
  --aw-ed-accent: var(--accent);
  --aw-ed-accent-soft: var(--accent-bg);
  --aw-ed-accent-border: var(--accent);
  --aw-ed-lock-bg: var(--warning-bg);
  --aw-ed-lock-border: var(--border);
  --aw-ed-lock-text: var(--warning);
  --aw-ed-success: var(--success);
  --aw-ed-warn: var(--warning);
  --aw-ed-focus: var(--accent);
}

/* Continuous Ledger Sections */
.aw-ledger-section {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 16px 0;
  border-bottom: 1px solid var(--aw-ed-border);
}

.aw-ledger-section:first-child {
  padding-top: 4px;
}

.aw-ledger-section-last {
  border-bottom: none;
  padding-bottom: 4px;
}

.aw-section-header {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.aw-section-title {
  margin: 0;
  font-size: 13px;
  font-weight: 600;
  color: var(--aw-ed-text-secondary);
  letter-spacing: 0.01em;
}

/* Self Lock Notice */
.aw-self-lock-banner {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 6px;
  background-color: var(--aw-ed-lock-bg);
  border: 1px solid var(--aw-ed-lock-border);
  color: var(--aw-ed-lock-text);
  font-size: 13px;
  line-height: 1.45;
}

.aw-icon-lock {
  width: 15px;
  height: 15px;
  margin-top: 2px;
  flex-shrink: 0;
}

/* Fields & Grid */
.aw-field-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.aw-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
}

.aw-field-head {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.aw-label {
  font-size: 14px;
  font-weight: 600;
  color: var(--aw-ed-text);
}

.aw-field-hint {
  margin: 0;
  font-size: 13px;
  color: var(--aw-ed-text-muted);
  line-height: 1.4;
}

.aw-input,
.aw-textarea {
  box-sizing: border-box;
  width: 100%;
  min-height: 44px;
  padding: 9px 12px;
  border: 1px solid var(--aw-ed-border-strong);
  border-radius: 6px;
  background-color: var(--aw-ed-bg);
  color: var(--aw-ed-text);
  font-family: inherit;
  font-size: 15px;
  line-height: 1.4;
  transition:
    border-color 0.14s ease,
    background-color 0.14s ease;
}

.aw-textarea {
  min-height: 92px;
  resize: vertical;
}

.aw-input::placeholder,
.aw-textarea::placeholder {
  color: var(--aw-ed-text-muted);
}

.aw-input:hover:not(:disabled),
.aw-textarea:hover:not(:disabled) {
  border-color: var(--aw-ed-text-muted);
}

.aw-input:disabled,
.aw-textarea:disabled {
  background-color: var(--aw-ed-surface);
  color: var(--aw-ed-text-muted);
  cursor: not-allowed;
}

/* Enabled Switch Row */
.aw-switch-ledger-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 12px;
  border: 1px solid var(--aw-ed-border-strong);
  border-radius: 6px;
  background-color: var(--aw-ed-surface);
}

.aw-switch-ledger-row.is-locked {
  opacity: 0.72;
}

.aw-switch-copy {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

.aw-switch-btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-height: 44px;
  min-width: 44px;
  padding: 4px 10px;
  border: 1px solid var(--aw-ed-border-strong);
  border-radius: 999px;
  background-color: var(--aw-ed-bg);
  color: var(--aw-ed-text-secondary);
  font-family: inherit;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  flex-shrink: 0;
  transition:
    border-color 0.14s ease,
    background-color 0.14s ease;
}

.aw-switch-btn:disabled {
  cursor: not-allowed;
}

.aw-switch-track {
  position: relative;
  display: inline-flex;
  align-items: center;
  width: 34px;
  height: 20px;
  border-radius: 999px;
  background-color: var(--aw-ed-border-strong);
  transition: background-color 0.14s ease;
}

.aw-switch-thumb {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background-color: #ffffff;
  transform: translateX(3px);
  transition: transform 0.14s ease;
}

.aw-switch-btn.is-on {
  border-color: var(--aw-ed-accent-border);
  color: var(--aw-ed-text);
}

.aw-switch-btn.is-on .aw-switch-track {
  background-color: var(--aw-ed-success);
}

.aw-switch-btn.is-on .aw-switch-thumb {
  transform: translateX(17px);
}

/* Permissions Ledger Matrix */
.aw-perm-ledger {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--aw-ed-border-strong);
  border-radius: 6px;
  background-color: var(--aw-ed-bg);
  overflow: hidden;
}

.aw-perm-row {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  min-height: 44px;
  padding: 8px 12px;
  border: none;
  border-bottom: 1px solid var(--aw-ed-border);
  background: transparent;
  color: var(--aw-ed-text);
  font-family: inherit;
  font-size: 14px;
  text-align: left;
  cursor: pointer;
  transition: background-color 0.12s ease;
}

.aw-perm-row:last-child {
  border-bottom: none;
}

.aw-perm-row:hover:not(:disabled) {
  background-color: var(--aw-ed-surface-hover);
}

.aw-perm-row.is-checked {
  background-color: var(--aw-ed-accent-soft);
}

.aw-perm-row.is-locked {
  cursor: not-allowed;
  opacity: 0.72;
}

.aw-perm-check {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  border: 1px solid var(--aw-ed-border-strong);
  border-radius: 4px;
  background-color: var(--aw-ed-bg);
  color: #ffffff;
  flex-shrink: 0;
}

.aw-perm-row.is-checked .aw-perm-check {
  background-color: var(--aw-ed-accent);
  border-color: var(--aw-ed-accent);
}

.aw-icon-check {
  width: 13px;
  height: 13px;
}

.aw-perm-main {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 4px 10px;
  flex: 1 1 auto;
  min-width: 0;
}

.aw-perm-label {
  font-weight: 500;
  color: var(--aw-ed-text);
  word-break: break-word;
}

.aw-perm-code {
  padding: 2px 6px;
  border-radius: 4px;
  background-color: var(--aw-ed-surface);
  color: var(--aw-ed-text-secondary);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  word-break: break-all;
}

.aw-perm-empty {
  padding: 14px 12px;
  border: 1px dashed var(--aw-ed-border-strong);
  border-radius: 6px;
  color: var(--aw-ed-text-muted);
  font-size: 13px;
  text-align: center;
}

/* Reason Label Bar & Counter */
.aw-reason-label-bar {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
}

.aw-char-counter {
  font-size: 12px;
  font-variant-numeric: tabular-nums;
  color: var(--aw-ed-text-muted);
}

.aw-char-counter.is-near-limit {
  color: var(--aw-ed-warn);
  font-weight: 600;
}

/* Focus Visibility */
.aw-input:focus-visible,
.aw-textarea:focus-visible,
.aw-switch-btn:focus-visible,
.aw-perm-row:focus-visible {
  outline: 2px solid var(--aw-ed-focus);
  outline-offset: -1px;
}

/* Mobile Responsive (320px / 375px / 390px / 430px) */
@media (max-width: 640px) {
  .aw-field-grid {
    grid-template-columns: 1fr;
  }

  .aw-switch-ledger-row {
    flex-direction: column;
    align-items: stretch;
  }

  .aw-switch-btn {
    align-self: flex-start;
  }
}

/* Reduced Motion */
@media (prefers-reduced-motion: reduce) {
  .aw-input,
  .aw-textarea,
  .aw-switch-btn,
  .aw-switch-track,
  .aw-switch-thumb,
  .aw-perm-row {
    transition: none;
  }
}
</style>
