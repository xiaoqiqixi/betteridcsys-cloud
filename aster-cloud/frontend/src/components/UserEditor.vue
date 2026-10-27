<script setup lang="ts">
import {
  computed,
  nextTick,
  onScopeDispose,
  reactive,
  shallowRef,
  useId,
  useTemplateRef,
  watch,
} from "vue";
import type { Role, User } from "../api/types";
import { ApiError, userResponse } from "../api/client";
import {
  identityReason,
  publicIdentityIntent,
  validActionIntent,
} from "../api/identity";
import { useConsole } from "../context";
import { useIdentityMutation } from "../composables/identity-mutation";
import {
  identityFieldLabels,
  identityNoticeLabels,
  identityRevocationLabels,
} from "../identity-copy";
import { permissionNames } from "../format";
import UiOverlay from "./UiOverlay.vue";
import UiButton from "./UiButton.vue";
import StateBlock from "./StateBlock.vue";
import InlineError from "./InlineError.vue";
import IdentityEditorFields, {
  type IdentityEditorModel,
} from "./IdentityEditorFields.vue";
import IdentityOperationNotice from "./IdentityOperationNotice.vue";
import IdentitySessionRevocation from "./IdentitySessionRevocation.vue";
const props = defineProps<{
  open: boolean;
  user: User | null;
  roles: Role[];
}>();
const emit = defineEmits<{ close: []; saved: [] }>();
const {
    api,
    session,
    prefs: { tr },
    notify,
  } = useConsole(),
  mutation = useIdentityMutation(),
  id = useId();
const form = reactive<IdentityEditorModel>({
  name: "",
  email: "",
  password: "",
  role: "viewer",
  enabled: true,
  permissions: [],
  reason: "",
});
const latest = shallowRef<User | null>(null),
  loading = shallowRef(false),
  loadError = shallowRef("");
const revokeOpen = shallowRef(false),
  revokeReason = shallowRef("");
const editorFeedback = useTemplateRef<HTMLElement>("editorFeedback"),
  revocationFeedback = useTemplateRef<HTMLElement>("revocationFeedback");
let original = "",
  ticket = 0,
  abort: AbortController | undefined;
const self = computed(
  () => !!latest.value && latest.value.id === session.user.value?.id,
);
const roleNames: Record<string, [string, string]> = {
  admin: ["管理员", "Administrator"],
  operator: ["操作员", "Operator"],
  viewer: ["只读成员", "Viewer"],
  custom: ["自定义", "Custom"],
};
const options = computed(() =>
  props.roles
    .filter(
      (r) =>
        session.user.value?.role === "admin" ||
        (r.id !== "admin" && r.permissions.every((p) => session.can(p))),
    )
    .map((r) => ({
      value: r.id,
      label: roleNames[r.id] ? tr(...roleNames[r.id]!) : r.name,
    })),
);
const permissionOptions = computed(() =>
  [...new Set(props.roles.flatMap((r) => r.permissions))]
    .filter((p) => session.can(p))
    .sort()
    .map((value) => ({
      value,
      label: permissionNames[value] ? tr(...permissionNames[value]!) : value,
    })),
);
const shownForm = computed(() => ({
  ...form,
  permissions:
    form.role === "custom"
      ? [...form.permissions]
      : [...(props.roles.find((r) => r.id === form.role)?.permissions ?? [])],
}));
const fieldLabels = computed(() =>
    identityFieldLabels(tr, !!props.user, form.role === "custom"),
  ),
  noticeLabels = computed(() => identityNoticeLabels(tr)),
  revokeLabels = computed(() => identityRevocationLabels(tr));
const dirty = computed(() => original !== JSON.stringify(form));
const profileChanged = computed(() => {
  if (!latest.value) return true;
  const u = latest.value;
  return (
    form.name !== u.name ||
    form.email !== u.email ||
    !!form.password ||
    form.role !== u.role ||
    form.enabled !== u.enabled ||
    (form.role === "custom" &&
      JSON.stringify([...form.permissions].sort()) !==
        JSON.stringify(u.permissions))
  );
});
const pending = computed(() =>
  mutation.pending.value.find((p) =>
    props.user
      ? p.target === props.user.id
      : p.action === "identity.user_created" &&
        p.target === form.email.trim().toLowerCase(),
  ),
);
const noticeState = computed(() =>
  mutation.busy.value
    ? "busy"
    : mutation.blocked.value
      ? "blocked"
      : pending.value
        ? "uncertain"
        : mutation.error.value === "revision"
          ? "conflict"
          : null,
);
watch(
  [noticeState, revokeOpen, () => props.open, loading],
  async ([state, , open, isLoading], _previous, onCleanup) => {
    if (!open || isLoading || !state || state === "busy") return;
    let current = true;
    onCleanup(() => (current = false));
    await nextTick();
    if (!current) return;
    // A submit button can be far below the result. Reveal the result only
    // in the active dialog, never by stealing focus from its nested child.
    const feedback = revokeOpen.value
      ? revocationFeedback.value
      : editorFeedback.value;
    if (!feedback || feedback.closest("[inert]")) return;
    feedback.focus({ preventScroll: true });
    feedback.scrollIntoView({ block: "start", behavior: "instant" });
  },
  { immediate: true, flush: "post" },
);
const managerAllowed = computed(
  () =>
    !latest.value ||
    session.user.value?.role === "admin" ||
    (latest.value.role !== "admin" &&
      latest.value.permissions.every((p) => session.can(p))),
);
const frozen = computed(
  () =>
    loading.value ||
    !!loadError.value ||
    !managerAllowed.value ||
    mutation.unavailable.value ||
    mutation.busy.value ||
    !!mutation.inspecting.value ||
    !!pending.value ||
    mutation.error.value === "revision",
);
function update(value: IdentityEditorModel) {
  if (frozen.value) return;
  const roleChanged = value.role !== form.role;
  Object.assign(form, {
    ...value,
    permissions: roleChanged ? [] : [...value.permissions],
  });
}
function body() {
  return {
    name: form.name,
    email: form.email.trim().toLowerCase(),
    role: form.role,
    ...(latest.value
      ? { enabled: form.enabled, revision: latest.value.revision }
      : {}),
    ...(form.password ? { password: form.password } : {}),
    ...(form.role === "custom"
      ? { permissions: [...form.permissions].sort() }
      : {}),
    reason: form.reason,
  };
}
const valid = computed(() => {
  const projection = publicIdentityIntent(body());
  return (
    !!projection &&
    validActionIntent(
      props.user ? "identity.user_updated" : "identity.user_created",
      projection,
    ) &&
    options.value.some((o) => o.value === form.role) &&
    (!props.user || !!latest.value) &&
    profileChanged.value
  );
});
function reset(u: User | null) {
  latest.value = u;
  Object.assign(form, {
    name: u?.name ?? "",
    email: u?.email ?? "",
    password: "",
    role:
      u?.role ??
      (options.value.some((r) => r.value === "viewer")
        ? "viewer"
        : options.value.some((r) => r.value === "custom")
          ? "custom"
          : (options.value[0]?.value ?? "")),
    enabled: u?.enabled ?? true,
    permissions: u?.role === "custom" ? [...u.permissions] : [],
    reason: "",
  });
  original = JSON.stringify(form);
  revokeOpen.value = false;
  revokeReason.value = "";
}
async function load() {
  abort?.abort();
  abort = new AbortController();
  const version = ++ticket,
    epoch = session.epoch.value;
  loadError.value = "";
  mutation.clearError();
  if (!props.open || !session.can("users.manage")) {
    reset(null);
    loading.value = false;
    return;
  }
  if (!props.user) {
    reset(null);
    loading.value = false;
    return;
  }
  const target = props.user.id;
  loading.value = true;
  try {
    const result = await api.get(
      `/users/${target}`,
      userResponse,
      abort.signal,
    );
    if (version !== ticket || session.epoch.value !== epoch) return;
    if (result.user.id !== target) throw new ApiError("invalid");
    reset(result.user);
  } catch (cause) {
    if (version === ticket && session.epoch.value === epoch) {
      loadError.value = cause instanceof ApiError ? cause.kind : "network";
      if (loadError.value === "unauthorized") session.invalidate();
    }
  } finally {
    if (version === ticket) loading.value = false;
  }
}
watch(
  [() => props.open, () => props.user?.id, () => session.epoch.value],
  () => {
    form.password = "";
    void load();
  },
  { immediate: true },
);
onScopeDispose(() => {
  ticket++;
  abort?.abort();
  form.password = "";
  revokeReason.value = "";
});
async function submit() {
  if (frozen.value || !valid.value) return;
  const target = latest.value;
  const result = await mutation.execute(
    target ? "identity.user_updated" : "identity.user_created",
    target,
    body(),
    () => props.open,
  );
  form.password = "";
  if (result) {
    original = JSON.stringify(form);
    notify(
      target
        ? tr("成员已更新。", "Member updated.")
        : tr("成员已创建。", "Member created."),
    );
    emit("saved");
    emit("close");
  }
}
async function revoke() {
  if (frozen.value || !latest.value || !identityReason(revokeReason.value))
    return;
  const result = await mutation.execute(
    "identity.sessions_revoked",
    latest.value,
    { revision: latest.value.revision, reason: revokeReason.value },
    () => props.open && revokeOpen.value,
  );
  if (result) {
    notify(tr("已撤销全部会话。", "All sessions revoked."));
    revokeOpen.value = false;
    emit("saved");
    emit("close");
  }
}
async function inspect() {
  if (pending.value && (await mutation.inspect(pending.value))) {
    notify(
      tr(
        "原操作已核实，请查看最新成员资料。",
        "Original operation verified. Check the latest member details.",
      ),
    );
    emit("saved");
    emit("close");
  }
}
</script>
<template>
  <UiOverlay
    :open="open"
    :title="user ? tr('编辑成员', 'Edit member') : tr('新增成员', 'Add member')"
    :busy="mutation.busy.value || !!mutation.inspecting.value"
    :dirty="dirty && !pending"
    drawer
    :close-label="tr('关闭', 'Close')"
    :discard-label="tr('放弃未保存的更改', 'Discard unsaved changes')"
    :continue-label="tr('继续编辑', 'Continue editing')"
    @close="emit('close')"
  >
    <StateBlock
      v-if="loading || loadError"
      :loading="loading"
      :error="loadError"
      @reload="load"
    />
    <template v-else>
      <form
        key="identity-form"
        :id="`${id}-form`"
        class="identity-editor-form"
        novalidate
        @submit.prevent="submit"
      >
        <div
          v-if="noticeState && !revokeOpen"
          ref="editorFeedback"
          class="identity-editor-feedback"
          tabindex="-1"
        >
          <IdentityOperationNotice
            :state="noticeState"
            :labels="noticeLabels"
            :operation-id="pending?.key"
            :target-label="latest?.email || form.email"
            :base-revision="latest?.revision"
            :busy="mutation.busy.value || !!mutation.inspecting.value"
            @reload="load"
            @inspect="inspect"
          />
        </div>
        <p v-if="!managerAllowed" class="identity-access-error" role="alert">
          {{
            tr(
              "该成员的权限已变化，你不能再管理此账户。",
              "This member’s access has changed. You can no longer manage this account.",
            )
          }}
        </p>
        <IdentityEditorFields
          key="identity-fields"
          :model-value="shownForm"
          :editing="!!user"
          :self="self"
          :disabled="frozen"
          :role-options="options"
          :permission-options="permissionOptions"
          :labels="fieldLabels"
          @update:model-value="update"
        />
        <InlineError
          v-if="mutation.error.value && !noticeState"
          :error="mutation.error.value"
        />
      </form>
      <IdentitySessionRevocation
        v-if="latest"
        :open="revokeOpen"
        :target-label="latest.name + ' · ' + latest.email"
        :target-id="latest.id"
        :self="self"
        :reason="revokeReason"
        :disabled="frozen || profileChanged"
        :busy="mutation.busy.value || !!mutation.inspecting.value"
        :labels="revokeLabels"
        @open="revokeOpen = true"
        @close="
          revokeOpen = false;
          revokeReason = '';
        "
        @update:reason="revokeReason = $event"
        @confirm="revoke"
      >
        <template #notice>
          <div
            v-if="noticeState || mutation.error.value"
            ref="revocationFeedback"
            class="identity-editor-feedback"
            tabindex="-1"
          >
            <IdentityOperationNotice
              v-if="noticeState"
              :state="noticeState"
              :labels="noticeLabels"
              :operation-id="pending?.key"
              :target-label="latest.email"
              :base-revision="latest.revision"
              :busy="mutation.busy.value || !!mutation.inspecting.value"
              @reload="load"
              @inspect="inspect"
            />
            <InlineError
              v-else-if="mutation.error.value"
              :error="mutation.error.value"
            />
          </div>
        </template>
      </IdentitySessionRevocation>
    </template>
    <template #footer="{ close }"
      ><UiButton
        :disabled="mutation.busy.value || !!mutation.inspecting.value"
        @click="close"
        >{{ tr("取消", "Cancel") }}</UiButton
      ><UiButton
        type="submit"
        :form="`${id}-form`"
        variant="primary"
        :busy="mutation.busy.value"
        :disabled="frozen || !valid"
        >{{
          user
            ? tr("保存更改", "Save changes")
            : tr("创建成员", "Create member")
        }}</UiButton
      ></template
    >
  </UiOverlay>
</template>
<style scoped>
.identity-editor-form {
  display: grid;
  gap: 20px;
}
.identity-editor-feedback {
  min-width: 0;
  scroll-margin-block: 12px;
}
.identity-editor-feedback:focus {
  outline: 2px solid var(--accent);
  outline-offset: 4px;
  border-radius: 6px;
}
.identity-access-error {
  color: var(--danger);
  font-size: 14px;
  line-height: 1.6;
}
</style>
