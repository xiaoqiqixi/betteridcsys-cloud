<script setup lang="ts">
import { computed, nextTick, shallowRef, useTemplateRef, watch } from "vue";
import { Plus, RefreshCw, Users } from "@lucide/vue";
import { useConsole } from "../context";
import { useQuery } from "../composables/query";
import { useUsersPage } from "../composables/users-page";
import { validRoles } from "../api/client";
import type { User } from "../api/types";
import UiButton from "../components/UiButton.vue";
import StateBlock from "../components/StateBlock.vue";
import StatusBadge from "../components/StatusBadge.vue";
import UserEditor from "../components/UserEditor.vue";
import IdentityPendingTray from "../components/IdentityPendingTray.vue";
const {
  prefs: { tr },
  session,
} = useConsole();
const list = useUsersPage(),
  roles = useQuery(() => "/roles", validRoles);
const heading = useTemplateRef<HTMLHeadingElement>("membersHeading");
const editorOpen = shallowRef(false),
  selected = shallowRef<User | null>(null);
const roleNames: Record<string, [string, string]> = {
  admin: ["管理员", "Administrator"],
  operator: ["操作员", "Operator"],
  viewer: ["只读成员", "Viewer"],
  custom: ["自定义", "Custom"],
};
const canEdit = computed(
  () =>
    session.can("users.manage") &&
    !list.denied.value &&
    !list.loading.value &&
    !list.error.value &&
    !!list.data.value &&
    !!roles.data.value,
);
function canEditUser(user: User) {
  return (
    canEdit.value &&
    (session.user.value?.role === "admin" ||
      (user.role !== "admin" && user.permissions.every((p) => session.can(p))))
  );
}
function edit(user: User | null) {
  if (!canEdit.value || (user && !canEditUser(user))) return;
  selected.value = user;
  editorOpen.value = true;
}
watch(
  [() => session.epoch.value, () => list.denied.value],
  () => {
    editorOpen.value = false;
    selected.value = null;
  },
  { flush: "sync" },
);
async function navigate(direction: "previous" | "next") {
  if (editorOpen.value) return;
  const page = list.page.value,
    identity = session.epoch.value;
  await list[direction]();
  if (
    identity !== session.epoch.value ||
    list.error.value ||
    list.page.value === page
  )
    return;
  await nextTick();
  heading.value?.focus({ preventScroll: true });
  heading.value?.scrollIntoView?.({ block: "start", behavior: "auto" });
}
async function saved() {
  const created = selected.value === null;
  await session.refresh();
  if (created) await list.refreshFirst();
  else await list.reload();
}
</script>
<template>
  <section class="page">
    <header class="page-heading">
      <div>
        <h1 ref="membersHeading" tabindex="-1">
          {{ tr("成员与权限", "Members & access") }}
        </h1>
        <p>
          {{
            tr(
              "管理登录账户，为每位成员分配恰当的权限。",
              "Manage sign-in accounts and assign appropriate access.",
            )
          }}
        </p>
      </div>
      <div class="heading-actions">
        <UiButton
          :busy="list.loading.value || roles.loading.value"
          :disabled="editorOpen"
          @click="
            list.refreshFirst();
            roles.reload();
          "
          ><RefreshCw :size="16" aria-hidden="true" />{{
            tr("刷新", "Refresh")
          }}</UiButton
        ><UiButton variant="primary" :disabled="!canEdit" @click="edit(null)"
          ><Plus :size="16" aria-hidden="true" />{{
            tr("新增成员", "Add member")
          }}</UiButton
        >
      </div>
    </header>
    <IdentityPendingTray @verified="list.reload()" />
    <StateBlock
      :loading="(!list.data.value && list.loading.value) || roles.loading.value"
      :error="(!list.data.value && list.error.value) || roles.error.value"
      :empty="!list.data.value?.items.length"
      :title="tr('暂无成员', 'No members yet')"
      @reload="
        list.reload();
        roles.reload();
      "
      ><div
        v-if="list.data.value && list.loading.value"
        class="members-progress"
        role="status"
        :aria-label="tr('正在加载', 'Loading')"
      >
        {{ tr("正在加载成员…", "Loading members…") }}
      </div>
      <div
        v-if="list.data.value && list.error.value"
        class="members-retry"
        role="alert"
      >
        <p>
          {{
            tr(
              "未能加载，请重试。当前仍显示上次读取的内容。",
              "Could not load members. The last loaded page is still shown.",
            )
          }}
        </p>
        <UiButton @click="list.reload()">{{
          tr("重新加载", "Reload")
        }}</UiButton>
      </div>
      <div class="resource-list" :aria-busy="list.loading.value || undefined">
        <article
          v-for="user in list.data.value?.items"
          :key="user.id"
          class="member-row"
        >
          <div class="member-avatar" aria-hidden="true">
            {{ (user.name || user.email).slice(0, 1).toLocaleUpperCase() }}
          </div>
          <div class="member-name">
            <h2>
              {{ user.name
              }}<span v-if="user.id === session.user.value?.id">{{
                tr("你", "You")
              }}</span>
            </h2>
            <p>{{ user.email }}</p>
          </div>
          <span class="member-role">{{
            roleNames[user.role] ? tr(...roleNames[user.role]!) : user.role
          }}</span
          ><StatusBadge
            :state="user.enabled ? 'enabled' : 'disabled'"
          /><UiButton
            variant="quiet"
            :disabled="!canEditUser(user)"
            @click="edit(user)"
            >{{ tr("编辑", "Edit") }}</UiButton
          >
        </article>
      </div></StateBlock
    >
    <nav
      v-if="list.data.value && !list.denied.value"
      class="members-pagination"
      :aria-label="tr('成员列表分页', 'Member list pagination')"
    >
      <p role="status" aria-live="polite">
        {{
          tr(
            `第 ${list.page.value} 页 · ${list.data.value.items.length} 位成员`,
            `Page ${list.page.value} · ${list.data.value.items.length} members`,
          )
        }}
      </p>
      <div class="pagination-actions">
        <UiButton
          :disabled="!list.canPrevious.value || editorOpen"
          @click="navigate('previous')"
          >{{ tr("上一页", "Previous") }}</UiButton
        >
        <UiButton
          :disabled="!list.canNext.value || editorOpen"
          @click="navigate('next')"
          >{{ tr("下一页", "Next") }}</UiButton
        >
      </div>
    </nav>
    <aside class="access-note">
      <Users :size="18" aria-hidden="true" />
      <p>
        {{
          tr(
            "管理员拥有完整权限；操作员处理日常实例与存储操作；只读成员只可查看资源。自定义角色可逐项授权。",
            "Administrators have full access. Operators handle routine instance and storage tasks. Viewers can only inspect resources. Custom roles use explicit grants.",
          )
        }}
      </p>
    </aside>
    <UserEditor
      :open="editorOpen"
      :user="selected"
      :roles="roles.data.value?.items || []"
      @close="editorOpen = false"
      @saved="saved"
    />
  </section>
</template>
<style scoped>
.member-row {
  display: grid;
  align-items: center;
  gap: 16px;
  padding: 16px 0;
  border-bottom: 1px solid var(--border);
  grid-template-columns:
    36px minmax(180px, 1.6fr) minmax(100px, 1fr)
    100px 70px;
}
.member-row > .status-badge {
  justify-self: start;
}
.member-row:last-child {
  border-bottom: 0;
}
.member-avatar {
  width: 36px;
  height: 36px;
  border-radius: 6px;
  display: grid;
  place-items: center;
  background: var(--subtle);
  border: 1px solid var(--border);
  font-size: 14px;
  font-weight: 500;
  flex-shrink: 0;
}
.member-name {
  flex: 1;
  min-width: 0;
}
.member-name h2 {
  font-size: 15px;
  margin: 0 0 7px;
  overflow-wrap: anywhere;
}
.member-name h2 span {
  font-size: 11px;
  color: var(--secondary);
  font-weight: 400;
  margin-left: 8px;
}
.member-name p {
  font-size: 13px;
  color: var(--secondary);
  margin: 0;
  overflow-wrap: anywhere;
}
.member-role {
  font-size: 14px;
  color: var(--secondary);
}
.access-note {
  display: flex;
  gap: 12px;
  margin-top: 22px;
  color: var(--secondary);
  align-items: flex-start;
  max-width: 740px;
}
.access-note svg {
  flex-shrink: 0;
  margin-top: 2px;
}
.access-note p {
  font-size: 13px;
  line-height: 1.7;
  margin: 0;
}
.members-progress,
.members-retry {
  padding: 12px 0;
  font-size: 14px;
  color: var(--secondary);
}
.members-retry {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  align-items: center;
  color: var(--danger);
}
.members-retry p {
  margin: 0;
  flex: 1 1 220px;
}
.members-pagination {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.pagination-actions {
  display: flex;
  gap: 8px;
}
.members-pagination p {
  font-size: 12px;
  color: var(--secondary);
  margin-top: 16px;
}
@media (max-width: 760px) {
  .member-row {
    grid-template-columns: 36px minmax(0, 1fr) auto;
    gap: 10px 12px;
    padding: 16px 0;
  }
  .member-name {
    grid-column: 2 / 4;
  }
  .member-row > .status-badge {
    grid-column: 2;
    grid-row: 2;
    justify-self: start;
  }
  .member-role {
    grid-column: 2;
    grid-row: 3;
  }
  .member-row > .ui-button {
    grid-column: 3;
    grid-row: 2 / 4;
  }
  .member-avatar {
    grid-row: 1 / 3;
  }
}
</style>
