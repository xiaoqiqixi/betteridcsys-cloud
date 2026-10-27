<script setup lang="ts">
import { onMounted, reactive, useTemplateRef } from "vue";
import { Server } from "@lucide/vue";
import { useConsole } from "../context";
import UiButton from "../components/UiButton.vue";
import InlineError from "../components/InlineError.vue";
const {
  session,
  prefs: { tr },
} = useConsole();
const form = reactive({ email: "", password: "" });
const emailInput = useTemplateRef<HTMLInputElement>("email");
onMounted(() => emailInput.value?.focus());
async function submit() {
  if (!form.email || !form.password || session.busy.value) return;
  await session.login(form.email, form.password);
  form.password = "";
}
</script>
<template>
  <main class="login-shell">
    <div class="login-intro">
      <div class="login-brand">
        <Server :size="24" aria-hidden="true" /><span>Aster</span>
      </div>
      <h1>
        {{ tr("你的基础设施。", "Your infrastructure.") }}<br /><span>{{
          tr("尽在掌握。", "In clear view.")
        }}</span>
      </h1>
      <p>
        {{
          tr(
            "管理实例、节点与每一次操作。",
            "Manage instances, nodes and every operation.",
          )
        }}
      </p>
      <div class="architectural-lines" aria-hidden="true">
        <span /><span /><span /><span />
      </div>
    </div>
    <div class="login-form-wrap">
      <form class="login-form" @submit.prevent="submit">
        <h2>{{ tr("登录管理控制台", "Sign in to your console") }}</h2>
        <p class="secondary">
          {{
            tr(
              "使用管理员分配的账户登录。",
              "Use the account provided by your administrator.",
            )
          }}
        </p>
        <label class="field"
          >{{ tr("邮箱", "Email")
          }}<input
            ref="email"
            v-model="form.email"
            type="email"
            autocomplete="username"
            required
            maxlength="254"
            :disabled="session.busy.value"
            placeholder="name@company.com" /></label
        ><label class="field"
          >{{ tr("密码", "Password")
          }}<input
            v-model="form.password"
            type="password"
            autocomplete="current-password"
            required
            maxlength="1024"
            :disabled="session.busy.value"
        /></label>
        <div v-if="session.pendingAuth.value" class="callout" role="alert">
          <p>
            {{
              tr(
                "登录状态尚未确认，请先检查状态，不要重复提交。",
                "Your sign-in state is not yet confirmed. Check it before submitting again.",
              )
            }}
          </p>
          <UiButton @click="session.refresh">{{
            tr("检查登录状态", "Check sign-in state")
          }}</UiButton>
        </div>
        <InlineError v-else :error="session.error.value" /><UiButton
          variant="primary"
          type="submit"
          :busy="session.busy.value"
          :disabled="
            !form.email || !form.password || !!session.pendingAuth.value
          "
          >{{ tr("登录", "Sign in") }}</UiButton
        >
      </form>
    </div>
  </main>
</template>
<style scoped>
.login-shell {
  min-height: 100dvh;
  display: grid;
  grid-template-columns: 1fr 1fr;
}
.login-intro {
  position: relative;
  padding: clamp(32px, 7vw, 112px);
  background: var(--sidebar-bg);
  color: var(--sidebar-text);
  overflow: hidden;
  display: flex;
  flex-direction: column;
  justify-content: center;
}
.login-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 22px;
  font-weight: 650;
  margin-bottom: 72px;
}
.login-intro h1 {
  font-size: clamp(32px, 4vw, 56px);
  font-weight: 600;
  letter-spacing: -0.045em;
  line-height: 1.28;
  margin: 0 0 24px;
}
.login-intro h1 span {
  color: var(--sidebar-secondary);
}
.login-intro > p {
  color: var(--sidebar-secondary);
  font-size: 15px;
  line-height: 1.7;
  margin: 0;
}
.architectural-lines {
  position: absolute;
  bottom: 0;
  right: 0;
  width: 70%;
  height: 24%;
  display: flex;
  gap: 16px;
  transform: skewY(-20deg);
  opacity: 0.13;
  pointer-events: none;
}
.architectural-lines span {
  border: 1px solid currentColor;
  flex: 1;
  border-radius: 6px 6px 0 0;
}
.architectural-lines span:nth-child(2) {
  margin-top: 32px;
}
.architectural-lines span:nth-child(3) {
  margin-top: 64px;
}
.architectural-lines span:nth-child(4) {
  margin-top: 96px;
}
.login-form-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 72px 32px;
}
.login-form {
  width: 100%;
  max-width: 360px;
}
.login-form h2 {
  font-size: 24px;
  letter-spacing: -0.025em;
  margin: 0 0 12px;
}
.login-form > .secondary {
  font-size: 14px;
  margin: 0 0 32px;
}
.login-form .field {
  margin-bottom: 20px;
}
.login-form > .ui-button {
  width: 100%;
  margin-top: 8px;
}
@media (max-width: 800px) {
  .login-shell {
    grid-template-columns: 1fr;
  }
  .login-intro {
    min-height: auto;
    padding: 32px 24px;
  }
  .login-brand {
    margin-bottom: 28px;
  }
  .login-intro h1 {
    font-size: 32px;
    margin-bottom: 12px;
  }
  .login-form-wrap {
    padding: 36px 24px 64px;
  }
  .architectural-lines {
    display: none;
  }
}
</style>
