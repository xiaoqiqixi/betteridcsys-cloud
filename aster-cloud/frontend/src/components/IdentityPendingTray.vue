<script setup lang="ts">
import { computed } from "vue";
import { useConsole } from "../context";
import { useIdentityMutation } from "../composables/identity-mutation";
import { identityNoticeLabels } from "../identity-copy";
import IdentityOperationNotice from "./IdentityOperationNotice.vue";
const emit = defineEmits<{ verified: [] }>();
const {
    prefs: { tr },
    notify,
  } = useConsole(),
  mutation = useIdentityMutation();
const labels = computed(() => identityNoticeLabels(tr));
async function inspect(entry: (typeof mutation.pending.value)[number]) {
  if (await mutation.inspect(entry)) {
    notify(
      tr(
        "原操作已核实，成员资料已重新读取。",
        "Original operation verified. Member details have been reloaded.",
      ),
    );
    emit("verified");
  }
}
</script>
<template>
  <section
    v-if="mutation.pending.value.length || mutation.blocked.value"
    class="identity-pending-tray"
    :aria-label="
      tr('待核对的账户操作', 'Account operations awaiting verification')
    "
  >
    <IdentityOperationNotice
      v-if="mutation.blocked.value"
      state="blocked"
      :labels="labels"
      :busy="false"
    />
    <IdentityOperationNotice
      v-for="entry in mutation.pending.value"
      :key="entry.key"
      state="uncertain"
      :labels="labels"
      :operation-id="entry.key"
      :target-label="entry.intent.email || entry.target_email"
      :base-revision="entry.intent.revision"
      :busy="!!mutation.inspecting.value"
      @inspect="inspect(entry)"
    />
  </section>
</template>
<style scoped>
.identity-pending-tray {
  display: grid;
  gap: 12px;
  margin-bottom: 24px;
}
</style>
