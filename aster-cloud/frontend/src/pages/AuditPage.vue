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
import {
  isNavigationFailure,
  NavigationFailureType,
  useRoute,
  useRouter,
} from "vue-router";
import { ChevronDown, ListFilter, RefreshCw } from "@lucide/vue";
import { useConsole } from "../context";
import { ApiError, validAudit, validPage } from "../api/client";
import type { Audit, Page } from "../api/types";
import {
  auditFilterKeys,
  auditRequestPath,
  auditRouteQuery,
  emptyAuditFilters,
  parseAuditQuery,
  type AuditFilterKey,
  type AuditQueryError,
} from "../audit-query";
import { auditNames, actionNames } from "../format";
import UiButton from "../components/UiButton.vue";
import UiSelect from "../components/UiSelect.vue";
import StateBlock from "../components/StateBlock.vue";
const {
  api,
  session,
  prefs: { tr, locale },
} = useConsole();
const route = useRoute(),
  router = useRouter(),
  id = useId();
const applied = computed(() => parseAuditQuery(route.query));
const filtered = computed(() =>
  auditFilterKeys.some((key) => applied.value.filters[key] !== ""),
);
const draft = reactive(emptyAuditFilters()),
  form = useTemplateRef<HTMLFormElement>("form");
const filtersOpen = shallowRef(false),
  draftError = shallowRef<AuditQueryError | null>(null),
  navigationError = shallowRef(false);
const data = shallowRef<Page<Audit> | null>(null),
  loading = shallowRef(false),
  error = shallowRef(""),
  serverQueryError = shallowRef(false);
const sourceOptions = computed(() => [
  { value: "", label: tr("全部事件", "All events") },
  { value: "identity", label: tr("账户安全", "Account security") },
  { value: "resource", label: tr("资源操作", "Resource operations") },
]);
const fieldNames = computed<
  Record<AuditFilterKey | "cursor" | "query", string>
>(() => ({
  source: tr("事件类别", "Event category"),
  action: tr("动作代码", "Action code"),
  actor: tr("操作者", "Actor"),
  target: tr("操作对象", "Target"),
  from: tr("开始时间", "Start time"),
  until: tr("结束时间", "End time"),
  cursor: tr("分页参数", "Page cursor"),
  query: tr("筛选参数", "Filter parameters"),
}));
function issueText(issue: AuditQueryError) {
  if (issue.reason === "range")
    return tr(
      "结束时间必须晚于开始时间。",
      "End time must be later than start time.",
    );
  const field = fieldNames.value[issue.field];
  if (issue.field === "from" || issue.field === "until")
    return tr(
      `${field}需使用带时区的完整时间，例如 2026-10-23T00:00:00Z，最多 6 位小数。`,
      `${field} must include a timezone, for example 2026-10-23T00:00:00Z, with at most 6 fractional digits.`,
    );
  if (issue.reason === "single" || issue.reason === "empty")
    return tr(
      `${field}不能重复或留空；不需要的条件应移除。`,
      `${field} must appear once and cannot be empty. Remove unused parameters.`,
    );
  if (issue.reason === "length")
    return tr(
      `${field}过长，请缩短后重新查询。`,
      `${field} is too long. Shorten it before searching again.`,
    );
  if (issue.field === "source")
    return tr(
      "事件类别无效，请选择全部、账户安全或资源操作。",
      "Choose all events, account security or resource operations.",
    );
  if (issue.field === "cursor")
    return tr(
      "分页参数无效，请回到筛选结果首页。",
      "The page cursor is invalid. Return to the first results page.",
    );
  if (issue.field === "query")
    return tr(
      "链接包含不支持的筛选参数。",
      "The link contains unsupported filter parameters.",
    );
  return tr(
    `${field}只接受英文字母、数字、点、下划线、冒号和连字符，不含空格。`,
    `${field} accepts letters, numbers, dots, underscores, colons and hyphens, without spaces.`,
  );
}
let revision = 0,
  abort: AbortController | undefined;
async function reload() {
  abort?.abort();
  abort = new AbortController();
  const ticket = ++revision,
    identity = session.epoch.value,
    path = auditRequestPath(applied.value);
  data.value = null;
  error.value = "";
  serverQueryError.value = false;
  if (!path || !session.user.value) {
    loading.value = false;
    return;
  }
  loading.value = true;
  try {
    const result = await api.get(
      path,
      (value): value is Page<Audit> => validPage(value, validAudit),
      abort.signal,
    );
    if (ticket === revision && identity === session.epoch.value)
      data.value = result;
  } catch (cause) {
    if (ticket !== revision || identity !== session.epoch.value) return;
    error.value = cause instanceof ApiError ? cause.kind : "network";
    serverQueryError.value =
      cause instanceof ApiError &&
      cause.status === 400 &&
      cause.code === "INVALID_QUERY";
    if (cause instanceof ApiError && cause.kind === "unauthorized")
      session.invalidate();
  } finally {
    if (ticket === revision) loading.value = false;
  }
}
watch(
  () => route.fullPath,
  () => {
    Object.assign(draft, applied.value.filters);
    draftError.value = null;
    navigationError.value = false;
    if (filtered.value || applied.value.error) filtersOpen.value = true;
  },
  { immediate: true },
);
watch([() => route.fullPath, session.epoch], () => void reload(), {
  immediate: true,
});
onScopeDispose(() => {
  revision++;
  abort?.abort();
});
async function navigate(query: Record<string, string>) {
  navigationError.value = false;
  try {
    const result = await router.push({ path: route.path, query });
    if (
      isNavigationFailure(result) &&
      !isNavigationFailure(result, NavigationFailureType.duplicated)
    )
      navigationError.value = true;
    else if (isNavigationFailure(result, NavigationFailureType.duplicated))
      await reload();
  } catch {
    navigationError.value = true;
  }
}
async function applyFilters() {
  const next = parseAuditQuery(auditRouteQuery(draft));
  draftError.value = next.error;
  if (next.error) {
    await nextTick();
    const field = next.error.field;
    (field === "source"
      ? form.value?.querySelector<HTMLElement>('[role="combobox"]')
      : form.value?.querySelector<HTMLElement>(`[name="${field}"]`)
    )?.focus();
    return;
  }
  await navigate(auditRouteQuery(next.filters));
}
async function clearFilters() {
  Object.assign(draft, emptyAuditFilters());
  draftError.value = null;
  await navigate({});
}
function page(cursor = "") {
  void navigate(auditRouteQuery(applied.value.filters, cursor));
}
function timeText(raw: string) {
  const date = new Date(raw);
  return Number.isFinite(date.valueOf())
    ? new Intl.DateTimeFormat(locale.value === "en" ? "en-GB" : "zh-CN", {
        dateStyle: "medium",
        timeStyle: "medium",
        timeZone: "UTC",
      }).format(date)
    : "—";
}
</script>
<template>
  <section class="page">
    <header class="page-heading">
      <div>
        <h1>{{ tr("审计记录", "Audit log") }}</h1>
        <p>
          {{
            tr(
              "追溯账户管理与资源操作。",
              "Review account administration and resource operations.",
            )
          }}
        </p>
      </div>
      <UiButton :busy="loading" :disabled="!!applied.error" @click="reload"
        ><RefreshCw :size="16" aria-hidden="true" />{{
          tr("刷新", "Refresh")
        }}</UiButton
      >
    </header>
    <section class="audit-filters">
      <button
        type="button"
        class="filter-toggle"
        :aria-expanded="filtersOpen"
        :aria-controls="`${id}-filters`"
        @click="filtersOpen = !filtersOpen"
      >
        <ListFilter :size="18" aria-hidden="true" /><span
          ><strong>{{ tr("筛选记录", "Filter records") }}</strong
          ><small>{{
            filtered
              ? tr("已应用筛选", "Filters applied")
              : tr(
                  "事件类别、操作者与 UTC 时间",
                  "Event category, actor and UTC time",
                )
          }}</small></span
        ><ChevronDown
          :size="18"
          :class="{ expanded: filtersOpen }"
          aria-hidden="true"
        />
      </button>
      <form
        v-if="filtersOpen"
        :id="`${id}-filters`"
        ref="form"
        class="filter-form"
        @submit.prevent="applyFilters"
      >
        <p :id="`${id}-exact`" class="filter-note">
          {{
            tr(
              "各条件同时生效；动作、操作者和对象按完整代码精确匹配，区分大小写。",
              "All conditions apply together. Action, actor and target are exact, case-sensitive codes.",
            )
          }}
        </p>
        <div class="filter-grid">
          <label class="field"
            >{{ fieldNames.source
            }}<UiSelect
              :model-value="draft.source"
              :options="sourceOptions"
              :label="fieldNames.source"
              @update:model-value="draft.source = $event"
          /></label>
          <label class="field"
            >{{ fieldNames.action
            }}<input
              v-model="draft.action"
              name="action"
              type="text"
              maxlength="64"
              autocomplete="off"
              spellcheck="false"
              placeholder="operation.succeeded"
              :aria-invalid="draftError?.field === 'action' || undefined"
              :aria-describedby="`${id}-exact`"
          /></label>
          <label class="field"
            >{{ fieldNames.actor
            }}<input
              v-model="draft.actor"
              name="actor"
              type="text"
              maxlength="80"
              autocomplete="off"
              spellcheck="false"
              placeholder="user:0123456789abcdef0123456789abcdef"
              :aria-invalid="draftError?.field === 'actor' || undefined"
              :aria-describedby="`${id}-exact`"
          /></label>
          <label class="field"
            >{{ fieldNames.target
            }}<input
              v-model="draft.target"
              name="target"
              type="text"
              maxlength="128"
              autocomplete="off"
              spellcheck="false"
              placeholder="0123456789abcdef0123456789abcdef"
              :aria-invalid="draftError?.field === 'target' || undefined"
              :aria-describedby="`${id}-exact`"
          /></label>
          <label class="field"
            >{{ tr("开始时间（UTC）", "Start time (UTC)")
            }}<input
              v-model="draft.from"
              name="from"
              type="text"
              maxlength="40"
              autocomplete="off"
              spellcheck="false"
              placeholder="2026-10-23T00:00:00Z"
              :aria-invalid="draftError?.field === 'from' || undefined"
              :aria-describedby="`${id}-time`"
          /></label>
          <label class="field"
            >{{ tr("结束时间（UTC）", "End time (UTC)")
            }}<input
              v-model="draft.until"
              name="until"
              type="text"
              maxlength="40"
              autocomplete="off"
              spellcheck="false"
              placeholder="2026-10-24T00:00:00Z"
              :aria-invalid="draftError?.field === 'until' || undefined"
              :aria-describedby="`${id}-time`"
          /></label>
        </div>
        <p :id="`${id}-time`" class="filter-note">
          {{
            tr(
              "开始时间包含在内，结束时间不包含。带时区偏移的输入会转为 UTC。",
              "Start time is inclusive; end time is exclusive. Timezone offsets are converted to UTC.",
            )
          }}
        </p>
        <p
          v-if="draftError"
          :id="`${id}-error`"
          class="filter-error"
          role="alert"
        >
          {{ issueText(draftError) }}
        </p>
        <div class="filter-actions">
          <UiButton type="submit" variant="primary">{{
            tr("应用筛选", "Apply filters")
          }}</UiButton
          ><UiButton @click="clearFilters">{{
            tr("清除筛选", "Clear filters")
          }}</UiButton>
        </div>
      </form>
    </section>
    <div
      v-if="applied.error || serverQueryError"
      class="query-error"
      role="alert"
    >
      <h2>{{ tr("筛选链接无效", "Invalid filter link") }}</h2>
      <p>
        {{
          applied.error
            ? issueText(applied.error)
            : tr(
                "筛选条件或分页参数无法使用，请回到结果首页或清除筛选。",
                "The filters or page cursor could not be used. Return to the first results page or clear the filters.",
              )
        }}
      </p>
      <div class="filter-actions">
        <UiButton v-if="applied.cursor" @click="page()">{{
          tr("回到结果首页", "First results page")
        }}</UiButton
        ><UiButton @click="clearFilters">{{
          tr("清除筛选", "Clear filters")
        }}</UiButton>
      </div>
    </div>
    <div v-else-if="navigationError" class="query-error" role="alert">
      <p>
        {{
          tr(
            "无法更新筛选链接，请重试或重新加载。",
            "The filter link could not be updated. Try again or reload.",
          )
        }}
      </p>
    </div>
    <StateBlock
      v-else
      :loading="loading"
      :error="error"
      :empty="!data?.items.length"
      :title="
        filtered
          ? tr('没有符合条件的记录', 'No matching records')
          : tr('暂无审计记录', 'No audit records yet')
      "
      :description="
        filtered
          ? tr(
              '试着调整条件或清除筛选。',
              'Adjust the conditions or clear the filters.',
            )
          : tr(
              '账户管理与资源操作记录会显示在这里。',
              'Account administration and resource operations will appear here.',
            )
      "
      @reload="reload"
    >
      <template #empty
        ><UiButton v-if="filtered" @click="clearFilters">{{
          tr("清除筛选", "Clear filters")
        }}</UiButton></template
      >
      <div class="resource-list">
        <article
          v-for="entry in data?.items"
          :key="`${entry.source}:${entry.id}`"
          class="audit-row"
        >
          <div class="audit-time">
            <span class="timeline-dot" aria-hidden="true" />
            <div>
              <time :datetime="entry.created_at">{{
                timeText(entry.created_at)
              }}</time
              ><span class="utc-label">UTC</span>
            </div>
          </div>
          <div class="audit-content">
            <span class="audit-category">{{
              entry.source === "identity"
                ? tr("账户安全", "Account security")
                : tr("资源操作", "Resource operations")
            }}</span>
            <h2>
              {{
                auditNames[entry.action]
                  ? tr(...auditNames[entry.action]!)
                  : entry.action.startsWith("operation.") &&
                      actionNames[entry.action.slice(10)]
                    ? tr(...actionNames[entry.action.slice(10)]!)
                    : entry.action
              }}
            </h2>
            <code class="audit-action">{{ entry.action }}</code>
            <dl>
              <div>
                <dt>{{ tr("操作者", "Actor") }}</dt>
                <dd>{{ entry.actor }}</dd>
              </div>
              <div>
                <dt>{{ tr("操作对象", "Target") }}</dt>
                <dd>{{ entry.target }}</dd>
              </div>
              <template v-if="entry.identity_detail">
                <div>
                  <dt>{{ tr("变更说明", "Reason") }}</dt>
                  <dd>{{ entry.identity_detail.reason }}</dd>
                </div>
                <div>
                  <dt>{{ tr("账户版本", "Account revision") }}</dt>
                  <dd>
                    {{ entry.identity_detail.base_revision }} →
                    {{ entry.identity_detail.result_revision }}
                  </dd>
                </div>
                <div>
                  <dt>{{ tr("操作 ID", "Operation ID") }}</dt>
                  <dd>{{ entry.identity_detail.operation_id }}</dd>
                </div>
              </template>
            </dl>
          </div>
        </article>
      </div>
    </StateBlock>
    <div
      v-if="data && !error && !applied.error && !navigationError"
      class="pagination"
    >
      <UiButton v-if="applied.cursor" @click="page()">{{
        tr("回到首页", "First page")
      }}</UiButton
      ><UiButton v-if="data.next_cursor" @click="page(data.next_cursor!)">{{
        tr("下一页", "Next page")
      }}</UiButton>
    </div>
  </section>
</template>
<style scoped>
.audit-filters {
  border: 0;
  border-radius: 0;
  background: var(--surface);
  margin-bottom: 20px;
  overflow: hidden;
  border-block: 1px solid var(--border);
}
.filter-toggle {
  display: flex;
  align-items: center;
  gap: 12px;
  width: 100%;
  min-height: 60px;
  padding: 12px 0;
  border: 0;
  background: transparent;
  color: var(--text);
  text-align: left;
}
.filter-toggle > span {
  flex: 1;
  min-width: 0;
}
.filter-toggle strong {
  display: block;
  font-size: 14px;
  font-weight: 600;
}
.filter-toggle small {
  display: block;
  margin-top: 5px;
  font-size: 12px;
  color: var(--secondary);
  line-height: 1.5;
}
.filter-toggle > svg:last-child {
  transition: transform 0.14s;
}
.filter-toggle > svg.expanded {
  transform: rotate(180deg);
}
.filter-toggle:focus-visible {
  outline-offset: -4px;
}
.filter-form {
  border-top: 1px solid var(--border);
  padding: 16px 0;
}
.filter-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 16px;
  margin: 16px 0;
}
.filter-note {
  margin: 0;
  color: var(--secondary);
  font-size: 12px;
  line-height: 1.7;
}
.filter-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-top: 16px;
}
.filter-error {
  font-size: 13px;
  line-height: 1.6;
  color: var(--danger);
  margin: 16px 0 0;
}
.query-error {
  padding: 18px;
  border: 1px solid var(--danger-border);
  border-radius: 6px;
  background: var(--danger-bg);
  color: var(--danger);
}
.query-error h2 {
  font-size: 16px;
  margin: 0 0 10px;
}
.query-error p {
  font-size: 14px;
  line-height: 1.7;
  margin: 0;
}
.audit-row {
  padding: 18px 0;
  display: grid;
  grid-template-columns: 160px minmax(0, 1fr);
  gap: 20px;
  border-bottom: 1px solid var(--border);
}
.audit-row:last-child {
  border-bottom: 0;
}
.audit-time {
  color: var(--secondary);
  font-size: 13px;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding-top: 4px;
  line-height: 1.5;
}
.utc-label {
  display: block;
  margin-top: 4px;
  font-size: 11px;
}
.timeline-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--muted);
  flex-shrink: 0;
  margin-top: 4px;
}
.audit-category {
  display: block;
  color: var(--secondary);
  font-size: 12px;
  margin-bottom: 0;
  grid-column: 1;
  grid-row: 1;
}
.audit-content h2 {
  font-size: 15px;
  margin: 0;
  overflow-wrap: anywhere;
  grid-column: 1;
  grid-row: 2;
}
.audit-action {
  display: block;
  color: var(--secondary);
  font-size: 12px;
  overflow-wrap: anywhere;
  margin-bottom: 0;
  grid-column: 1;
  grid-row: 3;
}
.audit-content dl {
  display: grid;
  flex-wrap: wrap;
  gap: 18px;
  margin: 0;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  grid-column: 2;
  grid-row: 1 / 4;
}
.audit-content dl > div {
  min-width: 0;
  max-width: 100%;
}
.audit-content dt {
  font-size: 12px;
  color: var(--secondary);
  margin-bottom: 5px;
}
.audit-content dd {
  margin: 0;
  font-size: 14px;
  overflow-wrap: anywhere;
}
@media (max-width: 560px) {
  .filter-grid {
    grid-template-columns: 1fr;
    gap: 18px;
  }
  .filter-actions > .ui-button {
    flex: 1 1 auto;
  }
}
@media (prefers-reduced-motion: reduce) {
  .filter-toggle > svg:last-child {
    transition: none;
  }
}
.audit-content {
  display: grid;
  grid-template-columns: minmax(150px, 1fr) minmax(0, 2fr);
  gap: 6px 22px;
  min-width: 0;
}
@media (max-width: 1100px) {
  .filter-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .audit-row {
    grid-template-columns: 140px minmax(0, 1fr);
  }
  .audit-content {
    display: block;
  }
  .audit-content h2 {
    margin-top: 4px;
  }
  .audit-action {
    margin-top: 5px;
  }
  .audit-content dl {
    margin-top: 12px;
  }
}
@media (max-width: 700px) {
  .audit-row {
    grid-template-columns: minmax(0, 1fr);
    gap: 10px;
    padding: 18px 0;
  }
  .audit-time {
    padding-top: 0;
  }
  .audit-time > div {
    display: flex;
    align-items: baseline;
    gap: 8px;
  }
  .utc-label {
    margin-top: 0;
  }
  .audit-content {
    padding-left: 0;
  }
  .audit-content dl {
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 14px;
  }
}
@media (max-width: 560px) {
  .filter-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
