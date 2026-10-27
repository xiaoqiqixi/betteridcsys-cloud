import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it, expect } from "vitest";
import { compileStyle, parse } from "@vue/compiler-sfc";
import { auditNames } from "../src/format";
const root = resolve(import.meta.dirname, "../src");
const css = readFileSync(resolve(root, "style.css"), "utf8");
function luminance(hex: string) {
  const c = hex
    .replace("#", "")
    .match(/../g)!
    .slice(0, 3)
    .map((v) => parseInt(v, 16) / 255)
    .map((v) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0]! + 0.7152 * c[1]! + 0.0722 * c[2]!;
}
function ratio(a: string, b: string) {
  const x = luminance(a),
    y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}
const themes = [
  ...css.matchAll(/:root(?:\[data-theme=["']?dark["']?\])?\s*\{([^}]+)\}/g),
].map((m) =>
  Object.fromEntries(
    [...m[1]!.matchAll(/(--[\w-]+)\s*:\s*(#[a-f\d]{6})(?=;|\s|\})/gi)].map(
      (v) => [v[1]!, v[2]!],
    ),
  ),
);
describe("design contracts (static tokens, not browser computed)", () => {
  it("defines revocation tokens on the teleported confirmation, not only its former parent", () => {
    const { descriptor } = parse(
      readFileSync(
        resolve(root, "components/IdentitySessionRevocation.vue"),
        "utf8",
      ),
    );
    const result = compileStyle({
      source: descriptor.styles[0]!.content,
      id: "data-v-revocation-tokens",
      filename: "IdentitySessionRevocation.vue",
      scoped: true,
    });
    expect(result.errors).toEqual([]);
    const tokens = [...result.code.matchAll(/([^{}]+)\{([^{}]*)\}/g)].find(
      ([, selectors, declarations]) =>
        selectors!.includes(
          ".aw-revoke-dialog-body[data-v-revocation-tokens]",
        ) && declarations!.includes("--aw-ledger-border-strong:"),
    )?.[2];
    expect(tokens).toContain(
      "--aw-ledger-border-strong: var(--control-border)",
    );
    expect(tokens).toContain("--aw-warn-bg: var(--warning-bg)");
    expect(tokens).toContain("--aw-warn-icon: var(--warning)");
    expect(tokens).toContain("--aw-danger-text: var(--danger)");
  });
  it.each([
    "IdentityEditorFields",
    "IdentityOperationNotice",
    "IdentitySessionRevocation",
  ])(
    "keeps %s dark selectors on their component, never the entire document",
    (name) => {
      const { descriptor } = parse(
        readFileSync(resolve(root, `components/${name}.vue`), "utf8"),
      );
      const result = compileStyle({
        source: descriptor.styles[0]!.content,
        id: "data-v-identity-contract",
        filename: `${name}.vue`,
        scoped: true,
      });
      expect(result.errors).toEqual([]);
      expect(result.code).not.toMatch(/\[data-theme="dark"\]\s*(?:,|\{)/);
      expect(result.code).toMatch(/\[data-theme="dark"\]\s+\.aw-/);
    },
  );
  it("compiles the modal notification rule without hiding the entire application", () => {
    const source = readFileSync(
      resolve(root, "components/ToastStack.vue"),
      "utf8",
    );
    const { descriptor } = parse(source);
    const style = descriptor.styles.find((entry) => entry.scoped)!;
    const result = compileStyle({
      source: style.content,
      filename: "ToastStack.vue",
      id: "data-v-toast-contract",
      scoped: true,
    });
    expect(result.errors).toEqual([]);
    expect(result.code).toMatch(/#app\[inert\]\s+\.toast-stack/);
    expect(result.code).toMatch(/#app\[inert\]\s+\.toast-item/);
    expect(result.code).not.toMatch(/#app\[inert\]\s*\{/);
  });
  it("reserves one-line NAT status badges while long network identities may wrap", () => {
    const source = readFileSync(
      resolve(root, "components/OverlaySnapshotPanel.vue"),
      "utf8",
    );
    const badge = source.match(
      /\.nat-summary header > \.status-badge\s*\{([^}]+)\}/,
    )?.[1];
    expect(badge).toContain("flex-shrink: 0");
    expect(badge).toContain("align-self: flex-start");
    expect(badge).toContain("white-space: nowrap");
    expect(
      source.match(/\.nat-summary header > div\s*\{([^}]+)\}/)?.[1],
    ).toContain("min-width: 0");
  });
  it("gives mobile public-IP heading actions a full row while preserving wrapping and 44px targets", () => {
    const source = readFileSync(
      resolve(root, "pages/PublicIPsPage.vue"),
      "utf8",
    );
    const { descriptor } = parse(source);
    const style = descriptor.styles.find((entry) => entry.scoped)!.content;
    const mobile = style.match(
      /@media \(max-width: 600px\)\s*\{([\s\S]*?)\n\}/,
    )?.[1];
    expect(mobile).toMatch(
      /\.page-heading > \.ip-actions,\s*\.ip-record-actions \.ip-actions\s*\{\s*width: 100%;/,
    );
    expect(mobile).toMatch(/\.ip-actions > \.ui-button\s*\{\s*flex: 1;/);
    const actions = style.match(/\.ip-actions\s*\{([^}]+)\}/)?.[1];
    expect(actions).toContain("flex-wrap: wrap");
    expect(actions).not.toContain("nowrap");
    expect(css).toMatch(/\.page button\.ui-button\s*\{\s*min-height: 44px;/);
  });
  it("wraps long recovery identities without squeezing egress modes or stacking the count rows", () => {
    const source = readFileSync(
      resolve(root, "components/OverlayEpochDialog.vue"),
      "utf8",
    );
    const { descriptor } = parse(source);
    const style = descriptor.styles.find((entry) => entry.scoped)!;
    const result = compileStyle({
      source: style.content,
      filename: "OverlayEpochDialog.vue",
      id: "data-v-recovery-layout",
      scoped: true,
    });
    expect(result.errors).toEqual([]);
    for (const tag of ["dt", "dd"]) {
      expect(result.code).toContain(
        `.recovery-summary ${tag}[data-v-recovery-layout]`,
      );
    }
    const wrapping = source.match(
      /\.recovery-summary dt,\s*\.recovery-summary dd\s*\{([^}]+)\}/,
    )?.[1];
    expect(wrapping).toContain("min-width: 0");
    expect(wrapping).toContain("overflow-wrap: anywhere");
    const mode = source.match(/\.recovery-policy > dd\s*\{([^}]+)\}/)?.[1];
    expect(mode).toContain("flex-shrink: 0");
    expect(mode).toContain("white-space: nowrap");
    const mobilePolicy = source.match(
      /@media \(max-width: 600px\)\s*\{\s*\.recovery-summary > \.recovery-policy\s*\{([^}]+)\}/,
    )?.[1];
    expect(mobilePolicy).toContain("flex-direction: column");
    expect(mobilePolicy).toContain("align-items: flex-start");
    expect(result.code).toContain(
      ".recovery-summary > .recovery-policy[data-v-recovery-layout]",
    );
  });
  it("keeps mobile navigation on the overlay surface and names the compact preferences control", () => {
    const nav = readFileSync(resolve(root, "components/NavLinks.vue"), "utf8");
    const app = readFileSync(resolve(root, "App.vue"), "utf8");
    const surface = nav.match(/\.nav-links\.tone-surface\s*\{([^}]+)\}/)?.[1];
    expect(surface).toBeDefined();
    expect(surface).toContain("--nav-text: var(--secondary)");
    expect(surface).toContain("--nav-hover: var(--hover)");
    expect(surface).toContain("--nav-current-text: var(--accent-text)");
    expect(surface).toContain("--nav-current-bg: var(--accent-bg)");
    expect(app).not.toContain("mobile-nav-surface");
    expect(app).toContain('<NavLinks tone="surface"');
    expect(app).toContain('<NavLinks v-slot="{ items }">');
    const header = readFileSync(
      resolve(root, "components/WorkbenchHeader.vue"),
      "utf8",
    );
    expect(app).toContain(
      `:preferences-label="tr('语言与外观', 'Language & appearance')"`,
    );
    const trigger = header.match(
      /<button[\s\S]*?class="aw-rail-action aw-pref-trigger"[\s\S]+?<\/button>/,
    )?.[0];
    expect(trigger).toContain("preferencesLabel");
    expect(trigger).toContain(":aria-label");
    expect(trigger).toContain(":title");
  });
  it("uses one sticky 52px command rail with a separately scrolling horizontal nav and compact disclosure", () => {
    const app = readFileSync(resolve(root, "App.vue"), "utf8");
    const header = readFileSync(
      resolve(root, "components/WorkbenchHeader.vue"),
      "utf8",
    );
    expect(app).not.toContain("<aside");
    expect(app).not.toContain('class="topbar"');
    expect(app).toContain("<WorkbenchHeader");
    const rail = header.match(/\.aw-command-rail\s*\{([^}]+)\}/)?.[1];
    expect(rail).toContain("position: sticky");
    expect(rail).toContain("height: 52px");
    expect(rail).toContain("--aw-rail-text: var(--text)");
    const nav = header.match(/\.aw-rail-nav\s*\{([^}]+)\}/)?.[1];
    expect(nav).toContain("min-width: 0");
    expect(nav).toContain("overflow-x: auto");
    expect(nav).toContain("overscroll-behavior-x: contain");
    expect(header).toContain("@media (max-width: 1024px)");
    expect(header).toContain('aria-haspopup="dialog"');
    expect(header).toContain(':aria-expanded="navigationOpen"');
    expect(app).not.toContain("margin-left: 232px");
  });
  it("lets drawer content fill remaining height and lets closing surfaces stop intercepting new input", () => {
    const overlay = readFileSync(
      resolve(root, "components/UiOverlay.vue"),
      "utf8",
    );
    expect(
      overlay.match(/\.as-drawer \.overlay-body\s*\{([^}]+)\}/)?.[1],
    ).toContain("flex: 1");
    expect(
      overlay.match(/\.overlay-leave-active\s*\{([^}]+)\}/)?.[1],
    ).toContain("pointer-events: none");
    const chrome = overlay.match(
      /\.overlay-header,\s*\.overlay-footer\s*\{([^}]+)\}/,
    )?.[1];
    expect(chrome).toContain("flex-shrink: 0");
    const body = overlay.match(/\.overlay-body\s*\{([^}]+)\}/)?.[1];
    expect(body).toContain("overflow: auto");
    expect(body).toContain("min-height: 0");
  });
  it("distinguishes staff audit requests from the controller dispatch commit", () => {
    expect(auditNames["operation.dispatch_requested"]).toEqual([
      "请求派发任务",
      "Task dispatch requested",
    ]);
    expect(auditNames["operation.reconcile_requested"]).toEqual([
      "请求核对任务",
      "Task reconciliation requested",
    ]);
    expect(auditNames["operation.dispatch_committed"]).toEqual([
      "任务派发已提交",
      "Task dispatch committed",
    ]);
  });
  for (const [index, theme] of themes.entries()) {
    for (const surface of [
      "--canvas",
      "--surface",
      "--surface-raised",
      "--subtle",
    ])
      for (const text of ["--text", "--secondary", "--muted"])
        it(`${index === 0 ? "light" : "dark"} ${text} on ${surface} is AA`, () =>
          expect(ratio(theme[text]!, theme[surface]!)).toBeGreaterThanOrEqual(
            4.5,
          ));
    for (const [text, bg] of [
      ["--accent-text", "--accent-bg"],
      ["--on-accent", "--accent"],
      ["--success", "--success-bg"],
      ["--danger", "--danger-bg"],
      ["--warning", "--warning-bg"],
      ["--sidebar-text", "--sidebar-bg"],
      ["--sidebar-secondary", "--sidebar-bg"],
    ])
      it(`${index} semantic ${text} on ${bg}`, () =>
        expect(ratio(theme[text!]!, theme[bg!]!)).toBeGreaterThanOrEqual(4.5));
  }
  it("has both complete palettes", () => expect(themes).toHaveLength(2));
  it("has no browser-native select, alert/confirm, mocked data imports or credential storage in production", () => {
    const walk = (p: string): string[] =>
      readdirSync(p, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory()
          ? walk(resolve(p, e.name))
          : /\.(?:vue|ts)$/.test(e.name)
            ? [resolve(p, e.name)]
            : [],
      );
    for (const f of walk(root)) {
      const text = readFileSync(f, "utf8");
      expect(text, f).not.toMatch(
        /<select\b|\b(?:alert|confirm)\s*\(|from\s+['"][^'"]*(?:fixtures|demo|mock)/,
      );
      expect(text, f).not.toMatch(
        /(?:localStorage|sessionStorage)\.setItem\([^\n]*(?:password|csrf_token)/,
      );
    }
  });
  it("honors reduced motion and safe areas", () => {
    expect(css).toContain("prefers-reduced-motion");
    expect(
      readFileSync(resolve(root, "components/ToastStack.vue"), "utf8"),
    ).toContain("env(safe-area-inset-bottom)");
  });
});
