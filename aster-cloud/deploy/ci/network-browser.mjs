// Real browser acceptance for the isolated MySQL-backed console fixture.
// All mutations go through visible UI controls. Evidence fetches below are GET-only.
// Never persist cookies, storageState, HAR, credentials, raw response bodies or DOM.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { sidebarBrowserAcceptance } from './sidebar-browser.mjs';
import { membersBrowserAcceptance } from './members-browser.mjs';

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}
const base = new URL(required('BASE_URL'));
assert.equal(base.protocol, 'https:');
assert(['localhost', '127.0.0.1', '[::1]'].includes(base.hostname));
assert(!base.username && !base.password && base.pathname === '/');
const output = path.resolve(required('BROWSER_ARTIFACT_DIR'));
fs.mkdirSync(output, { recursive: true, mode: 0o700 });
const credentials = JSON.parse(fs.readFileSync(required('BROWSER_CREDENTIALS_FILE'), 'utf8'));
assert(typeof credentials.email === 'string' && credentials.email.endsWith('@example.invalid'));
assert(typeof credentials.password === 'string' && credentials.password.length >= 16);
assert(/^[a-f0-9]{32}$/.test(credentials.owner_ref));
const { firefox } = await import(pathToFileURL(path.join(required('PLAYWRIGHT_MODULE_DIR'), 'playwright', 'index.mjs')).href);
const report = {
  schema: 1, status: 'running', passed: false, strict_tls: true, real_mysql: true,
  node_rpc: 'Isolated deterministic test substitute; no real KVM or host networking actions.',
  checks: [], screenshots: [], console_errors: [], requests: [], public_ingress_write_attempts: [], public_ip_write_attempts: [], public_ip_failed_writes: [],
};
let phase = 'launch', context, page, signedIn = false;
const sensitive = new Set([credentials.password, credentials.members_page?.viewer_password]);
// Do not output a Playwright stack/call log: fill() diagnostics can contain secrets.
function safeMessage(error) {
  let value = String(error instanceof Error ? error.message : error).split('\n')[0].slice(0,500);
  for (const secret of sensitive) if (secret) value = value.split(secret).join('[redacted]');
  return value.replace(/(?:password|csrf|cookie|authorization)\s*[:=]\s*[^\s,;]+/gi, '[redacted]');
}
function check(name, data = {}) {
  report.checks.push({ name, ...data });
  console.log(`PASS ${name}`);
}
function posts(suffix) {
  return report.requests.filter(r => r.method === 'POST' && (!suffix || r.path.endsWith(suffix))).length;
}
async function screenshot(name, fullPage = true) {
  assert(signedIn, 'Screenshots must not include the sign-in form');
  // Never capture an unexpected sign-in page after a session failure.
  assert.equal(await page.locator('input[type="password"]').count(), 0);
  await page.screenshot({ path: path.join(output, `${name}.png`), fullPage, animations: 'disabled' });
  report.screenshots.push(`${name}.png`);
}
async function noOverflow(name) {
  const size = await page.evaluate(() => ({
    width: innerWidth, scroll: document.documentElement.scrollWidth,
    dialog_regions: [...document.querySelectorAll('[role="dialog"], [role="dialog"] .overlay-body')].map(el => ({
      width: el.clientWidth, scroll: el.scrollWidth,
    })),
  }));
  assert(size.scroll <= size.width, `${name}: ${JSON.stringify(size)}`);
  assert(size.dialog_regions.every(region => region.scroll <= region.width + 1), `${name}: dialog content must not scroll horizontally: ${JSON.stringify(size)}`);
  check(name, size);
}
async function recoveryValueOneLine(name) {
  const value = page.getByRole('dialog').locator('.recovery-policy dd');
  assert.equal(await value.count(), 1);
  await value.scrollIntoViewIfNeeded();
  const evidence = await value.evaluate(dd => {
    const row = dd.closest('.recovery-policy');
    const dialog = dd.closest('[role="dialog"]');
    const title = row?.querySelector('dt');
    const box = dd.getBoundingClientRect();
    const rowBox = row?.getBoundingClientRect();
    const dialogBox = dialog?.getBoundingClientRect();
    const style = getComputedStyle(dd);
    const walker = document.createTreeWalker(dd, NodeFilter.SHOW_TEXT);
    const lines = new Set();
    let hasText = false, textWithinValue = true;
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (!node.textContent?.trim()) continue;
      hasText = true;
      const range = document.createRange();
      range.selectNodeContents(node);
      for (const rect of range.getClientRects()) {
        if (rect.width <= 0 || rect.height <= 0) continue;
        lines.add(Number(rect.y.toFixed(2)));
        textWithinValue &&= rect.left >= box.left - 1 && rect.right <= box.right + 1;
      }
    }
    return {
      width: innerWidth, has_text: hasText, text_lines: lines.size,
      long_profile_present: !!title?.textContent?.includes('w'.repeat(64)),
      public_value_present: dd.textContent?.trim() === '公网 IPv4',
      text_within_value: textWithinValue,
      value_within_row_and_dialog: !!rowBox && !!dialogBox && box.left >= rowBox.left - 1 && box.right <= rowBox.right + 1 && box.left >= dialogBox.left - 1 && box.right <= dialogBox.right + 1,
      value_rendered: style.display !== 'none' && style.visibility !== 'hidden' && Number(style.opacity) !== 0 && box.width > 0 && box.height > 0,
      vertically_stacked: !!title && box.top >= title.getBoundingClientRect().bottom - 1,
    };
  });
  assert.equal(evidence.long_profile_present, true);
  assert.equal(evidence.public_value_present, true);
  assert.equal(evidence.has_text, true);
  assert.equal(evidence.text_lines, 1, 'The actual public egress text must stay on one rendered line, not a narrow vertical column');
  assert.equal(evidence.text_within_value, true, 'The public egress text must not be clipped or overflow its value box');
  assert.equal(evidence.value_within_row_and_dialog, true);
  assert.equal(evidence.value_rendered, true);
  assert.equal(evidence.vertically_stacked, true, 'The long-profile mobile recovery row must stack its label and value');
  check(name, evidence);
}
async function publicPoolHeadingActions() {
  const viewports = [];
  for (const width of [390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    const actions = page.locator('.page-heading > .ip-actions');
    await actions.waitFor({ state: 'visible' });
    await actions.scrollIntoViewIfNeeded();
    assert.equal(await actions.locator(':scope > button.ui-button').count(), 2);
    const evidence = await actions.evaluate(async element => {
      await document.fonts.ready;
      await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const heading = element.closest('.page-heading');
      const headingBox = heading.getBoundingClientRect();
      const headingStyle = getComputedStyle(heading);
      const contentLeft = headingBox.left + parseFloat(headingStyle.borderLeftWidth) + parseFloat(headingStyle.paddingLeft);
      const contentRight = headingBox.right - parseFloat(headingStyle.borderRightWidth) - parseFloat(headingStyle.paddingRight);
      const box = element.getBoundingClientRect();
      const buttons = [...element.querySelectorAll(':scope > button.ui-button')].map(button => {
        const buttonBox = button.getBoundingClientRect();
        const style = getComputedStyle(button);
        const lines = [];
        let hasText = false, textWithinButton = true;
        const walker = document.createTreeWalker(button, NodeFilter.SHOW_TEXT);
        for (let node = walker.nextNode(); node; node = walker.nextNode()) {
          if (!node.textContent?.trim()) continue;
          hasText = true;
          const range = document.createRange();
          range.selectNodeContents(node);
          for (const rect of range.getClientRects()) {
            if (rect.width <= 0 || rect.height <= 0) continue;
            if (!lines.some(y => Math.abs(y - rect.y) <= 1)) lines.push(rect.y);
            textWithinButton &&= rect.left >= buttonBox.left - 1 && rect.right <= buttonBox.right + 1 && rect.top >= buttonBox.top - 1 && rect.bottom <= buttonBox.bottom + 1;
          }
        }
        return {
          width: buttonBox.width, height: buttonBox.height, top: buttonBox.top, bottom: buttonBox.bottom,
          rendered: style.display !== 'none' && style.visibility !== 'hidden' && Number(style.opacity) !== 0 && buttonBox.width > 0 && buttonBox.height > 0,
          in_actions_and_viewport: buttonBox.left >= box.left - 1 && buttonBox.right <= box.right + 1 && buttonBox.left >= 0 && buttonBox.right <= innerWidth && buttonBox.top >= 0 && buttonBox.bottom <= innerHeight,
          has_text: hasText, text_lines: lines.length, text_within_button: textWithinButton,
        };
      });
      return {
        width: innerWidth, document_scroll_width: document.documentElement.scrollWidth,
        actions_width: box.width, heading_content_width: contentRight - contentLeft,
        fills_heading_content: Math.abs(box.left - contentLeft) <= 1 && Math.abs(box.right - contentRight) <= 1,
        below_heading_text: box.top >= heading.firstElementChild.getBoundingClientRect().bottom - 1,
        buttons,
      };
    });
    assert.equal(evidence.width, width);
    assert(evidence.document_scroll_width <= width);
    assert.equal(evidence.fills_heading_content, true, 'Mobile public pool actions must fill the actual heading content row');
    assert.equal(evidence.below_heading_text, true);
    assert.equal(evidence.buttons.length, 2);
    for (const button of evidence.buttons) {
      assert(button.width >= 44 && button.height >= 44, 'Both heading actions retain actual 44px targets');
      assert(button.rendered && button.in_actions_and_viewport && button.has_text && button.text_within_button);
      assert.equal(button.text_lines, 1, 'Each actual heading-action label must remain on one visible text line');
    }
    assert(Math.abs(evidence.buttons[0].top - evidence.buttons[1].top) <= 1 && Math.abs(evidence.buttons[0].bottom - evidence.buttons[1].bottom) <= 1, 'Both heading actions must align on the same row');
    viewports.push(evidence);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  check('390px and 320px public pool heading actions fill a row with single-line 44px buttons', { viewports });
}
async function singleInfoNotice(name) {
  // Ignore the outgoing 150 ms transition, but never wait long enough for the
  // five-second expiry to disguise a stack of newly emitted success notices.
  await page.waitForFunction(() => document.querySelectorAll('.toast-item.info:not(.toast-leave-active)').length <= 1, undefined, { timeout: 600 });
  const count = await page.locator('.toast-item.info:not(.toast-leave-active)').count();
  assert(count <= 1);
  check(name, { active_info_notices: count });
}
async function dialogExcludesNotices(name) {
  await page.getByRole('dialog').waitFor();
  const evidence = await page.evaluate(() => {
    const dialog = document.querySelector('[role="dialog"]');
    const shade = dialog?.closest('.overlay-shade');
    const stack = document.querySelector('.toast-stack');
    const app = document.querySelector('#app');
    if (!dialog || !shade) return { dialog_present: false };
    const stackStyle = stack ? getComputedStyle(stack) : null;
    const hidden = !stack || stackStyle.display === 'none' || stackStyle.visibility === 'hidden' || Number(stackStyle.opacity) === 0;
    const behind = hidden || Number(stackStyle.zIndex) < Number(getComputedStyle(shade).zIndex);
    const items = [...document.querySelectorAll('.toast-item')];
    const pointerReachable = items.some(item => {
      const box = item.getBoundingClientRect();
      const x = Math.max(0, Math.min(innerWidth - 1, box.x + box.width / 2));
      const y = Math.max(0, Math.min(innerHeight - 1, box.y + box.height / 2));
      const top = document.elementFromPoint(x, y);
      return !!top && item.contains(top);
    });
    const keyboardExcluded = items.every(item => hidden || !!item.closest('[inert]') || [...item.querySelectorAll('button,a,input,[tabindex]')].every(control => control.matches(':disabled') || control.tabIndex < 0));
    return { dialog_present: true, notice_count: items.length, below_or_hidden: behind,
      background_app_visible: !!app && getComputedStyle(app).visibility !== 'hidden',
      pointer_excluded: !pointerReachable, keyboard_excluded: keyboardExcluded,
      focus_excluded: !document.activeElement?.closest('.toast-stack') };
  });
  assert.equal(evidence.dialog_present, true);
  assert.equal(evidence.background_app_visible, true, 'The modal background app must stay visible, not disappear with its notices');
  assert.equal(evidence.below_or_hidden, true, 'A notice must never paint above the modal');
  assert.equal(evidence.pointer_excluded, true, 'A modal must block notice hit targets');
  assert.equal(evidence.keyboard_excluded, true, 'A modal must exclude notice buttons from tab focus');
  assert.equal(evidence.focus_excluded, true);
  check(name, evidence);
}
async function noticesExpireNaturally(name) {
  // Moving the real pointer away lets the production hover-pause timer resume.
  // No close click, clock mocking, DOM hiding or application-state mutation.
  await page.mouse.move(0, 0);
  assert.equal(await page.evaluate(() => !!document.activeElement?.closest('.toast-stack')), false);
  await page.waitForFunction(() => document.querySelectorAll('.toast-item').length === 0, undefined, { timeout: 8000 });
  check(name);
}
async function languageChangeClearsNotice() {
  const notice = page.locator('.toast-item.info:not(.toast-leave-active)');
  await notice.waitFor({ state: 'attached', timeout: 1000 });
  assert.equal(await notice.count(), 1, 'Locale cleanup must be tested with a real pending notice');
  const previousTitle = await notice.locator('p').innerText();
  assert(/[\u3400-\u9fff]/.test(previousTitle), 'Expected the genuine Chinese action notice');
  await page.getByRole('button', { name: '语言与外观', exact: true }).click();
  await dialogExcludesNotices('language dialog suppresses the existing action notice');
  await pick('界面语言', 'English');
  // This must be locale cleanup, not a five-second expiry coincidence.
  await page.waitForFunction(title => ![...document.querySelectorAll('.toast-item:not(.toast-leave-active) p')].some(item => item.textContent === title), previousTitle, { timeout: 600 });
  assert.equal(await page.locator('.toast-item:not(.toast-leave-active)').count(), 0);
  await pick('Language', '简体中文');
  await page.getByRole('button', { name: '完成', exact: true }).click();
  await dialogClosed();
  check('language switch removes the genuine previous-language notice immediately');
}
async function read(suffix) {
  assert(/^\/(overlays|public-ips|public-ingress-operations|instances|operations)\//.test(suffix) && !suffix.includes('://'));
  return page.evaluate(async suffix => {
    const response = await fetch(`/console/v1${suffix}`, { method: 'GET', credentials: 'same-origin' });
    if (!response.ok) throw new Error(`Read-only evidence request failed (${response.status})`);
    return response.json();
  }, suffix);
}
async function dialogClosed() {
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  // UiOverlay removes its same-URL history entry on close.
  await page.waitForFunction(() => !history.state?.asterOverlay);
}
async function pick(label, option) {
  await page.getByRole('combobox', { name: label, exact: true }).click();
  await page.getByRole('option', { name: option, exact: true }).click();
}
async function networkOverview({ requireCanPlan = true } = {}) {
  await page.getByRole('link', { name: '返回网络管理', exact: true }).click();
  await page.getByRole('heading', { name: 'VPC 与路由', exact: true }).waitFor();
  await page.locator('.network-tabs').waitFor();
  // Reading pool/lease safety state must work during a pending epoch, when the
  // production UI correctly forbids creating another network configuration.
  // Existing planning callers keep their stricter readiness gate by default.
  if (requireCanPlan) await page.getByRole('button', { name: '配置网络', exact: true }).waitFor();
}
async function submitNetworkPlan(expectedEpoch) {
  const before = posts('/overlays/epochs');
  await page.getByRole('dialog').locator('.confirmation input').fill('cluster-fixture');
  await page.getByRole('button', { name: '应用网络配置', exact: true }).click();
  await dialogClosed();
  await page.waitForURL(/#\/networks\/epochs\/[a-f0-9]{32}$/);
  const id = page.url().split('/').at(-1);
  const detail = await read(`/overlays/epochs/${id}`);
  assert.equal(posts('/overlays/epochs') - before, 1);
  assert.equal(detail.epoch.epoch, expectedEpoch);
  return { id, detail };
}
async function publicOverview(label, english = false) {
  const card = page.locator('.nat-summary');
  assert.equal(await card.count(), 1);
  assert((await card.innerText()).includes('8.8.4.2'));
  assert((await card.innerText()).includes(english ? 'Public IPv4 Internet egress selected' : '公网 IPv4 出口已选择'));
  check(label);
}
async function refreshDetail(id) {
  await Promise.all([
    page.waitForResponse(r => new URL(r.url()).pathname === `/console/v1/overlays/epochs/${id}` && r.request().method() === 'GET' && r.status() === 200),
    page.getByRole('button', { name: '刷新', exact: true }).click(),
  ]);
  // StateBlock temporarily unmounts the detail while reloading. Wait for the
  // response to be rendered before asserting controls or taking a screenshot.
  await page.getByRole('heading', { name: /网络变更/ }).waitFor();
}
async function action(label, submit, id) {
  await page.getByRole('button', { name: label, exact: true }).click();
  await dialogExcludesNotices('operation confirmation excludes background notices');
  await page.getByRole('dialog').locator('input').fill(id);
  await page.getByRole('button', { name: submit, exact: true }).click();
  await dialogClosed();
  await refreshDetail(id);
  await singleInfoNotice('consecutive confirmed actions keep at most one info notice');
}
async function advanceUntilStopped(id) {
  let detail = await read(`/overlays/epochs/${id}`);
  const before = posts('/advance');
  if (detail.epoch.state === 'pending') {
    // One explicit continuation starts the production asynchronous coordinator.
    // Never loop POSTs while it is working or retry an uncertain original task.
    await action('继续执行', '确认继续', id);
  }
  const deadline = Date.now() + 45000;
  while (Date.now() < deadline) {
    detail = await read(`/overlays/epochs/${id}`);
    if (detail.epoch.state !== 'pending') {
      await refreshDetail(id);
      assert(posts('/advance') - before <= 1);
      return detail;
    }
    await page.waitForTimeout(250); // GET-only bounded observation, not a write retry.
  }
  throw new Error('Network coordinator did not settle within 45 seconds');
}

function receiptProof(detail) {
  return detail.tasks.map(t => ({
    operation_id: t.operation_id, node_id: t.node_id, phase: t.phase,
    request_sha256: t.request_sha256, result: t.result,
  })).sort((a,b) => a.operation_id.localeCompare(b.operation_id));
}

try {
  context = await firefox.launchPersistentContext(required('FIREFOX_PROFILE_DIR'), {
    headless: true,
    firefoxUserPrefs: { 'security.enterprise_roots.enabled': false },
    ...(process.env.FIREFOX_EXECUTABLE_PATH ? { executablePath: process.env.FIREFOX_EXECUTABLE_PATH } : {}),
    ignoreHTTPSErrors: false,
    viewport: { width: 1440, height: 1000 },
    colorScheme: 'light', locale: 'zh-CN', timezoneId: 'Asia/Shanghai',
  });
  page = context.pages()[0] || await context.newPage();
  for (const extra of context.pages().filter(p => p !== page)) await extra.close();
  page.setDefaultTimeout(15000);
  page.on('pageerror', error => report.console_errors.push(safeMessage(error)));
  page.on('response', response => {
    const url = new URL(response.url()), request = response.request();
    if (url.origin === base.origin && /^\/console\/v1\/(overlays|public-ips|public-ingress-operations|instances|operations)(?:\/|$)/.test(url.pathname)) {
      // Deliberately no headers, bodies, query strings or cookie data.
      report.requests.push({ method: request.method(), path: url.pathname, status: response.status() });
    }
  });

  page.on('request', request => {
    const policyURL = new URL(request.url());
    if (policyURL.origin === base.origin && request.method() === 'POST' && /^\/console\/v1\/instances\/[a-f0-9]{32}\/public-ingress$/.test(policyURL.pathname)) report.public_ingress_write_attempts.push({method:'POST',path:policyURL.pathname});
    const url = new URL(request.url());
    if (url.origin === base.origin && url.pathname.startsWith('/console/v1/public-ips/') && request.method() === 'POST') {
      // Count UI write attempts even when a committed response is intentionally
      // lost. No request headers, idempotency key or body enters the artifact.
      report.public_ip_write_attempts.push({ method: request.method(), path: url.pathname });
    }
  });

  page.on('requestfailed', request => {
    const url = new URL(request.url());
    if (url.origin === base.origin && url.pathname.startsWith('/console/v1/public-ips/') && request.method() === 'POST') {
      // Observe the actual transport failure, not an assumed response event:
      // Firefox may suppress response when the HTTP/2 body is reset. Persist
      // only the safe route/method, never transport diagnostics or payloads.
      report.public_ip_failed_writes.push({ method: request.method(), path: url.pathname });
    }
  });

  phase = 'sign-in';
  await page.goto(new URL('#/networks/overlays', base).href, { waitUntil: 'networkidle' });
  await page.getByLabel('邮箱', { exact: true }).fill(credentials.email);
  await page.getByLabel('密码', { exact: true }).fill(credentials.password);
  await page.getByRole('button', { name: '登录', exact: true }).click();
  await page.getByRole('heading', { name: 'VPC 与路由', exact: true }).waitFor();
  await page.getByRole('button', { name: '配置网络', exact: true }).waitFor();
  signedIn = true;
  // Keep secrets only in memory for error redaction; never serialize them.
  for (const cookie of await context.cookies()) sensitive.add(cookie.value);
  check('real session sign-in');
  const initialOptions = await read('/overlays/options?cluster_id=cluster-fixture');
  const initialID = initialOptions.latest_epoch.id;
  const initial = await read(`/overlays/epochs/${initialID}`);
  assert.equal(initial.epoch.state, 'succeeded');
  assert.equal(initial.epoch.snapshot.nat_policies.length, 1);
  assert.equal(initial.epoch.snapshot.nat_policies[0].internet_egress_enabled ?? false, false);
  assert.equal(initialOptions.nat_profiles[0].allow_internet_egress, true);
  assert.equal(initialOptions.nat_profiles[0].public_ipv4, '8.8.4.2');
  check('root-approved public Internet option does not rewrite the initial legacy epoch');

  phase = 'responsive-overview';
  await noOverflow('desktop overview has no horizontal overflow');
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow('mobile overview has no horizontal overflow');
  await page.getByRole('button', { name: '新建 VPC', exact: true }).click();
  await screenshot('mobile-vpc-create', false);
  await page.getByRole('dialog').getByRole('button', { name: '关闭', exact: true }).focus();
  for (let i = 0; i < 12; i++) {
    await page.keyboard.press(i < 6 ? 'Tab' : 'Shift+Tab');
    assert(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')));
  }
  await page.keyboard.press('Escape');
  await dialogClosed();
  assert(await page.getByRole('button', { name: '新建 VPC', exact: true }).evaluate(el => el === document.activeElement));
  check('dialog keyboard focus trap, Escape and focus restoration');
  await page.getByRole('button', { name: '新建 VPC', exact: true }).click();
  await page.goBack();
  await dialogClosed();
  assert(page.url().includes('#/networks/overlays'));
  check('browser Back closes a clean dialog without leaving network management');

  phase = 'create-vpc';
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('button', { name: '新建 VPC', exact: true }).click();
  await page.getByLabel('名称', { exact: true }).fill('备份隔离网');
  await page.getByLabel('客户归属 ID', { exact: false }).fill(credentials.owner_ref);
  await page.getByLabel('IPv4 网段', { exact: true }).fill('10.44.0.0/24');
  await page.getByLabel('VNI', { exact: false }).fill('504');
  await screenshot('desktop-vpc-create', false);
  const vpcBefore = posts('/overlays/vpcs');
  await page.getByRole('button', { name: '创建 VPC', exact: true }).click();
  await dialogClosed();
  await page.getByRole('heading', { name: '备份隔离网', exact: true }).waitFor();
  const vpcs = await read('/overlays/vpcs?cluster_id=cluster-fixture');
  assert(vpcs.items.some(v => v.name === '备份隔离网' && v.cidr === '10.44.0.0/24' && v.vni === 504));
  assert.equal(posts('/overlays/vpcs') - vpcBefore, 1);
  check('one UI VPC creation is persisted in real MySQL', { vpc_count: vpcs.items.length });
  await singleInfoNotice('VPC creation keeps at most one info notice');

  phase = 'edit-route-nat';
  await page.getByRole('button', { name: '配置网络', exact: true }).click();
  await dialogExcludesNotices('network editor excludes the VPC-created notice');
  await page.getByLabel('目标网段，每行一个', { exact: false }).fill('192.0.2.0/25');
  await page.getByLabel('公开端口', { exact: true }).fill('40002');
  await page.getByLabel('目标端口', { exact: true }).fill('2222');
  await page.getByLabel('允许访问的来源网段', { exact: false }).fill('192.0.2.0/26');
  await pick('出口范围', '公网 IPv4');
  assert.equal((await page.getByRole('combobox', { name: '出口范围', exact: true }).innerText()).trim(), '公网 IPv4');
  check('public Internet mode is selected with the real custom egress control');
  await page.getByRole('button', { name: '添加端口映射', exact: true }).click();
  assert.equal(await page.getByLabel('公开端口', { exact: true }).count(), 2);
  await page.getByRole('button', { name: '删除端口映射 2', exact: true }).click();
  assert.equal(await page.getByLabel('公开端口', { exact: true }).count(), 1);
  check('NAT mapping add and remove controls preserve the intended mapping');
  await page.getByRole('dialog').locator('.forwarding').scrollIntoViewIfNeeded();
  await screenshot('desktop-nat-editor', false);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('dialog').locator('.forwarding').scrollIntoViewIfNeeded();
  await screenshot('mobile-nat-editor', false);
  await noOverflow('mobile NAT dialog has no horizontal overflow');
  const protocol = page.getByRole('combobox', { name: '协议', exact: true });
  await protocol.focus();
  await page.keyboard.press('Enter');
  await page.getByRole('option', { name: 'TCP', exact: true }).waitFor();
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('dialog').count(), 1);
  assert.equal(await protocol.getAttribute('aria-expanded'), 'false');
  assert.equal(await page.locator('select').count(), 0);
  check('custom select is keyboard operable and Escape preserves the parent dialog');
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: '继续编辑', exact: true }).click();
  assert.equal(await page.getByLabel('公开端口', { exact: true }).inputValue(), '40002');
  check('dirty form discard prompt preserves unsaved NAT edits');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('dialog').locator('.confirmation input').fill('cluster-fixture');
  assert.equal(await page.getByRole('button', { name: '应用网络配置', exact: true }).isDisabled(), true);
  await page.getByRole('dialog').locator('.public-consent input[type="checkbox"]').check();
  assert.equal(await page.getByRole('button', { name: '应用网络配置', exact: true }).isEnabled(), true);
  check('public Internet plan requires explicit visible consent as well as cluster confirmation');
  const planBefore = posts('/overlays/epochs');
  await page.getByRole('button', { name: '应用网络配置', exact: true }).click();
  await dialogClosed();
  await page.waitForURL(/#\/networks\/epochs\/[a-f0-9]{32}$/);
  const epochID = page.url().split('/').at(-1);
  let detail = await read(`/overlays/epochs/${epochID}`);
  assert.equal(posts('/overlays/epochs') - planBefore, 1);
  assert.deepEqual(detail.epoch.snapshot.gateways[0].allowed_prefixes, ['192.0.2.0/25']);
  assert.equal(detail.epoch.snapshot.nat_policies[0].internet_egress_enabled, true);
  assert.equal(detail.epoch.snapshot.nat_policies[0].snat_enabled, true);
  const forwarding = detail.epoch.snapshot.nat_policies[0].forwardings[0];
  assert.equal(forwarding.public_port, 40002);
  assert.equal(forwarding.target_port, 2222);
  assert.equal(forwarding.source_cidr, '192.0.2.0/26');
  check('route and NAT changes persisted in exactly one new epoch', { epoch: detail.epoch.epoch });
  await singleInfoNotice('new network plan replaces preceding info notices');

  phase = 'lost-ack';
  detail = await advanceUntilStopped(epochID);
  assert.equal(detail.epoch.state, 'uncertain');
  await page.getByRole('button', { name: '继续执行', exact: true }).waitFor({ state: 'hidden' });
  assert.equal(await page.getByRole('button', { name: '继续执行', exact: true }).count(), 0);
  await screenshot('desktop-unknown-result');
  check('lost program ACK is shown as uncertain, never successful');
  const mutationBeforeRefresh = posts();
  await refreshDetail(epochID);
  await refreshDetail(epochID);
  assert.equal(posts(), mutationBeforeRefresh);
  check('read-only detail refresh never repeats a POST');
  const advanceBefore = posts('/advance');
  await action('核对节点回执', '核对回执', epochID);
  assert.equal(posts('/advance'), advanceBefore);
  detail = await read(`/overlays/epochs/${epochID}`);
  assert.equal(detail.epoch.state, 'pending');
  check('receipt reconciliation confirms the existing task without retrying advance');
  await languageChangeClearsNotice();
  detail = await advanceUntilStopped(epochID);
  assert.equal(detail.epoch.state, 'succeeded');
  check('explicit continuation completes the remaining phases');
  const originalReceipts = receiptProof(detail);
  const originalSnapshot = detail.epoch.snapshot;
  const originalSHA = detail.epoch.snapshot_sha256;

  phase = 'explicit-recovery';
  await page.getByRole('button', { name: '恢复网络', exact: true }).click();
  await dialogExcludesNotices('desktop recovery dialog is above and isolated from notices');
  await page.getByRole('dialog').locator('.confirmation input').fill(epochID);
  assert.equal(await page.getByRole('button', { name: '提交恢复', exact: true }).isDisabled(), true);
  await page.getByRole('dialog').locator('.public-consent input[type="checkbox"]').check();
  check('same-selection public Internet recovery requires a fresh explicit consent');
  await screenshot('desktop-recovery-dialog', false);
  await page.setViewportSize({ width: 390, height: 844 });
  await dialogExcludesNotices('mobile recovery dialog is not covered by action notices');
  await recoveryValueOneLine('390px recovery public egress value is visible on one text line with a long profile');
  await noOverflow('mobile recovery dialog has no horizontal overflow');
  await page.setViewportSize({ width: 320, height: 844 });
  await recoveryValueOneLine('320px recovery public egress value is visible on one text line with a long profile');
  await noOverflow('320px long-profile recovery dialog has no horizontal overflow');
  await page.setViewportSize({ width: 390, height: 844 });
  await noticesExpireNaturally('background notice expires before the mobile recovery dialog screenshot');
  await screenshot('mobile-recovery-dialog', false);
  await page.getByRole('button', { name: '提交恢复', exact: true }).click();
  await dialogClosed();
  await page.waitForURL(u => /#\/networks\/epochs\/[a-f0-9]{32}$/.test(u.href) && !u.href.endsWith(epochID));
  const recoveryID = page.url().split('/').at(-1);
  detail = await read(`/overlays/epochs/${recoveryID}`);
  assert(detail.epoch.recovery);
  assert.notEqual(recoveryID, epochID);
  assert.equal(detail.epoch.epoch, initial.epoch.epoch + 2);
  assert.equal(detail.epoch.snapshot.nat_policies[0].internet_egress_enabled, true);
  check('explicit recovery creates a distinct persisted epoch', { epoch: detail.epoch.epoch });
  await singleInfoNotice('recovery creation keeps at most one info notice');
  detail = await advanceUntilStopped(recoveryID);
  assert.equal(detail.epoch.state, 'succeeded');
  assert.equal(detail.tasks.length, detail.epoch.snapshot.profiles.length * 3);
  check('recovery completes every node in all three phases via UI', { tasks: detail.tasks.length });
  await noticesExpireNaturally('recovery completion notice expires before the final mobile screenshot');
  await screenshot('mobile-recovery-complete');
  await noOverflow('mobile recovery detail has no horizontal overflow');
  const original = await read(`/overlays/epochs/${epochID}`);
  assert.equal(original.epoch.superseded_by, recoveryID);
  assert.equal(original.epoch.snapshot_sha256, originalSHA);
  assert.deepEqual(original.epoch.snapshot, originalSnapshot);
  assert.deepEqual(receiptProof(original), originalReceipts);
  const untouched = await read(`/overlays/epochs/${initialID}`);
  assert.equal(untouched.epoch.snapshot_sha256, initial.epoch.snapshot_sha256);
  assert.deepEqual(untouched.epoch.snapshot, initial.epoch.snapshot);
  assert.deepEqual(receiptProof(untouched), receiptProof(initial));
  check('recovery preserves original snapshots and task receipts');

  phase = 'disable-public-egress';
  await networkOverview();
  await page.getByRole('button', { name: '配置网络', exact: true }).click();
  await dialogExcludesNotices('public egress disable editor excludes background notices');
  await pick('出站地址转换', '关闭');
  assert.equal((await page.getByRole('combobox', { name: '出口范围', exact: true }).innerText()).trim(), '仅指定网段');
  assert.equal(await page.getByRole('dialog').locator('.public-consent').count(), 0);
  await page.getByRole('button', { name: '删除端口映射 1', exact: true }).click();
  await page.getByLabel('目标网段，每行一个', { exact: false }).fill('');
  assert.equal(await page.getByLabel('公开端口', { exact: true }).count(), 0);
  const disabledPlan = await submitNetworkPlan(4);
  const disabledPolicy = disabledPlan.detail.epoch.snapshot.nat_policies[0];
  assert.equal(disabledPolicy.snat_enabled, false);
  assert.equal(disabledPolicy.internet_egress_enabled ?? false, false);
  assert.deepEqual(disabledPolicy.forwardings, []);
  assert.deepEqual(disabledPlan.detail.epoch.snapshot.gateways[0].allowed_prefixes, []);
  check('one UI plan disables SNAT and public Internet while retaining an explicit empty gateway', { epoch: 4 });
  detail = await advanceUntilStopped(disabledPlan.id);
  assert.equal(detail.epoch.state, 'succeeded');
  check('public egress disable completes every node through the real coordinator');

  phase = 'internet-without-prefix-routes';
  await networkOverview();
  await page.getByRole('button', { name: '配置网络', exact: true }).click();
  await dialogExcludesNotices('Internet-only editor excludes background notices');
  assert.equal(await page.getByLabel('目标网段，每行一个', { exact: false }).inputValue(), '');
  assert.equal(await page.getByLabel('公开端口', { exact: true }).count(), 0);
  await pick('出站地址转换', '开启');
  await pick('出口范围', '公网 IPv4');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('dialog').locator('.nat-profile .egress-fields').scrollIntoViewIfNeeded();
  await screenshot('mobile-public-egress-editor', false);
  await noOverflow('mobile Internet-only editor has no horizontal overflow');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('dialog').locator('.nat-profile .egress-fields').scrollIntoViewIfNeeded();
  await screenshot('desktop-public-egress-editor', false);
  await page.getByRole('dialog').locator('.public-consent input[type="checkbox"]').check();
  const publicPlan = await submitNetworkPlan(5);
  const publicPolicy = publicPlan.detail.epoch.snapshot.nat_policies[0];
  assert.equal(publicPolicy.snat_enabled, true);
  assert.equal(publicPolicy.internet_egress_enabled, true);
  assert.deepEqual(publicPolicy.forwardings, []);
  assert.deepEqual(publicPlan.detail.epoch.snapshot.gateways[0].allowed_prefixes, []);
  check('pure public Internet plan persists without prefix routes or DNAT mappings', { epoch: 5 });
  detail = await advanceUntilStopped(publicPlan.id);
  assert.equal(detail.epoch.state, 'succeeded');
  assert.equal(detail.tasks.length, 6);
  check('Internet-only policy completes all six node phases without a destination allowlist');
  const persistedDisabled = await read(`/overlays/epochs/${disabledPlan.id}`);
  assert.equal(persistedDisabled.epoch.snapshot.nat_policies[0].snat_enabled, false);
  assert.equal(persistedDisabled.epoch.snapshot.nat_policies[0].internet_egress_enabled ?? false, false);
  assert.deepEqual(persistedDisabled.epoch.snapshot.gateways[0].allowed_prefixes, []);
  assert.deepEqual(persistedDisabled.epoch.snapshot.nat_policies[0].forwardings, []);
  const persistedOriginal = await read(`/overlays/epochs/${epochID}`);
  assert.equal(persistedOriginal.epoch.snapshot_sha256, originalSHA);
  assert.deepEqual(persistedOriginal.epoch.snapshot, originalSnapshot);
  assert.deepEqual(receiptProof(persistedOriginal), originalReceipts);
  check('later public enablement preserves the disabled epoch and original receipt history');

  phase = 'navigation-appearance';
  await networkOverview();
  await page.goBack();
  await page.getByRole('heading', { name: /网络变更/ }).waitFor();
  await page.goForward();
  await page.getByRole('heading', { name: 'VPC 与路由', exact: true }).waitFor();
  check('browser Back and Forward restore the expected network pages');
  await noticesExpireNaturally('public overview has no stale notices before actual light screenshots');
  await page.setViewportSize({ width: 390, height: 844 });
  await publicOverview('mobile Chinese light overview displays the persisted public mode and egress address');
  await noOverflow('mobile Chinese light public overview has no horizontal overflow');
  await screenshot('mobile-network');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await publicOverview('desktop Chinese light overview displays the persisted public mode and egress address');
  await noOverflow('desktop Chinese light public overview has no horizontal overflow');
  await screenshot('desktop-network');
  phase = 'responsive-sidebar';
  await sidebarBrowserAcceptance({ page, output, report });
  phase = 'navigation-appearance';
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: '语言与外观', exact: true }).click();
  await pick('界面语言', 'English');
  await pick('Appearance', 'Dark');
  await page.getByRole('button', { name: 'Done', exact: true }).click();
  await dialogClosed();
  await noticesExpireNaturally('dark overview has no stale notices before actual screenshots');
  // Measure the rendered text itself: an inline-flex badge box can stay one
  // rectangle while its anonymous text item wraps "Enabled" into two lines.
  const natBadgeLines = await page.evaluate(() => [...document.querySelectorAll('.nat-summary header > .status-badge')].map(badge => {
    const walker = document.createTreeWalker(badge, NodeFilter.SHOW_TEXT);
    const lines = new Set();
    let hasText = false;
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      if (!node.textContent?.trim()) continue;
      hasText = true;
      const range = document.createRange();
      range.selectNodeContents(node);
      for (const rect of range.getClientRects()) {
        if (rect.width > 0 && rect.height > 0) lines.add(Number(rect.y.toFixed(2)));
      }
    }
    return { has_text: hasText, text_lines: lines.size };
  }));
  assert(natBadgeLines.length > 0, 'The real NAT fixture must render at least one status badge');
  assert(natBadgeLines.every(badge => badge.has_text && badge.text_lines === 1), 'Mobile English NAT badge text must remain on one rendered line');
  check('mobile English NAT status text does not wrap', { badges: natBadgeLines });
  await noOverflow('mobile English dark page has no horizontal overflow');
  await publicOverview('mobile English dark overview displays the persisted public mode and egress address', true);
  await screenshot('mobile-network-english-dark');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await publicOverview('desktop English dark overview displays the persisted public mode and egress address', true);
  await screenshot('desktop-network-english-dark');
  await noOverflow('desktop English dark page has no horizontal overflow');
  await sidebarBrowserAcceptance({ page, output, report, capture: false, english: true });
  // Read only rendered text to catch accidental raw ISO rendering; never serialize DOM.
  assert(!/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z/.test(await page.locator('main').innerText()));
  check('visible dates are localized, not raw microsecond ISO values');

  phase = 'public-ip-pool-ui';
  const originalFive = await Promise.all([initialID, epochID, recoveryID, disabledPlan.id, publicPlan.id].map(id => read(`/overlays/epochs/${id}`)));
  await page.getByRole('button', { name: 'Language & appearance', exact: true }).click();
  await pick('Language', '简体中文');
  await pick('外观', '浅色');
  await page.getByRole('button', { name: '完成', exact: true }).click();
  await dialogClosed();
  await page.locator('.network-tabs').getByRole('link', { name: '公网 IP', exact: true }).click();
  await page.getByRole('heading', { name: '公网 IP', exact: true }).waitFor();
  await pick('集群', 'cluster-fixture');
  const publicOptions = await read('/public-ips/options');
  assert.equal(publicOptions.complete, true);
  const publicApproval = publicOptions.approvals.find(a => a.vpc_id === credentials.vpc_id);
  assert(publicApproval);
  assert.deepEqual(publicApproval.public_ipv4s, ['8.8.4.2', '8.8.4.3', '8.8.4.4']);
  const publicVPC = publicOptions.vpcs.find(v => v.id === credentials.vpc_id);
  assert(publicVPC && publicVPC.owner_ref === credentials.owner_ref);
  const writeAttempts = suffix => report.public_ip_write_attempts.filter(r => !suffix || r.path.endsWith(suffix)).length;
  const poolCard = () => page.locator('.ip-record').filter({ has: page.getByRole('heading', { name: '公网出口池', exact: true }) });
  const leaseCard = id => page.locator('.ip-record').filter({ hasText: id });
  async function poolView() {
    if (await page.locator('.network-tabs').count() === 0) await networkOverview({ requireCanPlan: false });
    await page.locator('.network-tabs').getByRole('link', { name: '公网 IP', exact: true }).click();
    await page.getByRole('heading', { name: '公网 IP', exact: true }).waitFor();
    if ((await page.getByRole('combobox', {name:'集群',exact:true}).innerText()).trim() !== 'cluster-fixture') await pick('集群','cluster-fixture');
    await page.getByRole('button', { name: '地址池', exact: true }).click();
    await poolCard().waitFor();
  }
  async function leasesView() {
    if (await page.locator('.network-tabs').count() === 0) await networkOverview({ requireCanPlan: false });
    await page.locator('.network-tabs').getByRole('link', { name: '公网 IP', exact: true }).click();
    await page.getByRole('heading', { name: '公网 IP', exact: true }).waitFor();
    if ((await page.getByRole('combobox', {name:'集群',exact:true}).innerText()).trim() !== 'cluster-fixture') await pick('集群','cluster-fixture');
    await page.getByRole('button', { name: '分配记录', exact: true }).click();
    await page.locator('.ip-record').first().waitFor();
  }
  async function fillAllocation() {
    await poolCard().getByRole('button', { name: '分配地址', exact: true }).click();
    await pick('所属 VPC', `${publicVPC.name} · ${publicVPC.cidr}`);
    await pick('NAT 出口', `${publicApproval.node_id} · ${publicApproval.profile_id}`);
    await pick('公网 IP', '8.8.4.3');
  }
  async function setPoolState(enabled) {
    const label = enabled ? '启用分配' : '停用分配';
    await poolCard().getByRole('button', { name: label, exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: enabled ? '启用地址分配' : '停用地址分配', exact: true }).click();
    await dialogClosed();
    await poolCard().getByRole('button', { name: enabled ? '停用分配' : '启用分配', exact: true }).waitFor();
  }
  await page.getByRole('button', { name: '新建地址池', exact: true }).click();
  await page.getByLabel('地址池名称', { exact: true }).fill('公网出口池');
  await page.getByLabel('所属网段', { exact: true }).fill('8.8.4.0/24');
  await page.getByLabel('起始 IP', { exact: true }).fill('8.8.4.3');
  await page.getByLabel('结束 IP', { exact: true }).fill('8.8.4.3');
  await dialogExcludesNotices('public pool editor isolates background notices');
  await noOverflow('desktop public pool editor has no horizontal overflow');
  await screenshot('desktop-public-ip-pool-create', false);
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow('390px public pool editor has no horizontal overflow');
  await screenshot('mobile-public-ip-pool-create', false);
  await page.setViewportSize({ width: 320, height: 844 });
  await noOverflow('320px public pool editor has no horizontal overflow');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('dialog').getByRole('button', { name: '新建公网 IP 池', exact: true }).click();
  await dialogClosed();
  await poolCard().waitFor();
  const publicPools = await read('/public-ips/pools?cluster_id=cluster-fixture');
  assert.equal(publicPools.items.length, 1);
  const pool = publicPools.items[0];
  assert.deepEqual(pool.addresses, ['8.8.4.3']);
  assert.equal(pool.enabled, true);
  assert.equal(writeAttempts('/pools'), 1);
  check('one visible range-entry pool creation persists exact approved inventory in real MySQL');

  const originalPoolOperation = (await read(`/public-ips/operations/${pool.id}`)).operation;
  assert.deepEqual(originalPoolOperation.result.pool.addresses, ['8.8.4.3']);
  await poolCard().getByRole('button', { name: '补充地址', exact: true }).click();
  await page.getByLabel('起始 IP', { exact: true }).fill('8.8.4.4');
  await page.getByLabel('结束 IP', { exact: true }).fill('8.8.4.4');
  await noOverflow('desktop public pool extension editor has no horizontal overflow');
  await screenshot('desktop-public-ip-pool-extend', false);
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow('390px public pool extension editor has no horizontal overflow');
  await screenshot('mobile-public-ip-pool-extend', false);
  await page.setViewportSize({ width: 320, height: 844 });
  await noOverflow('320px public pool extension editor has no horizontal overflow');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('dialog').getByRole('button', { name: '补充公网地址', exact: true }).click();
  await dialogClosed();
  await poolCard().getByText('8.8.4.4', { exact: true }).waitFor();
  const extendedPool = (await read(`/public-ips/pools/${pool.id}`)).pool;
  assert.deepEqual(extendedPool.addresses, ['8.8.4.3', '8.8.4.4']);
  assert.deepEqual((await read(`/public-ips/operations/${pool.id}`)).operation, originalPoolOperation);
  assert.equal(writeAttempts(`/pools/${pool.id}/addresses`), 1);
  check('one append-only UI inventory extension adds a second address without changing the immutable original pool creation operation');

  await noticesExpireNaturally('public pool overview notice expires before screenshots');
  await screenshot('desktop-public-ip-pools');
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow('390px public pool overview has no horizontal overflow');
  await publicPoolHeadingActions();
  await screenshot('mobile-public-ip-pools');

  phase = 'public-ip-allocation-lost-ack';
  await fillAllocation();
  await noOverflow('390px public allocation editor has no horizontal overflow with maximum profile ID');
  await screenshot('mobile-public-ip-allocation', false);
  await page.setViewportSize({ width: 320, height: 844 });
  await noOverflow('320px public allocation editor has no horizontal overflow with maximum profile ID');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await screenshot('desktop-public-ip-allocation', false);
  const allocationBefore = writeAttempts('/leases');
  await page.getByRole('dialog').getByRole('button', { name: '分配公网 IP', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: '核对原操作', exact: true }).waitFor();
  const pendingOperationID = (await page.locator('.ip-pending code').innerText()).trim();
  assert(/^[a-f0-9]{32}$/.test(pendingOperationID));
  assert.equal(writeAttempts('/leases') - allocationBefore, 1);
  const reconciliationReads = () => report.requests.filter(r => r.method === 'GET' && r.path === `/console/v1/public-ips/operations/${pendingOperationID}`).length;
  const readsBefore = reconciliationReads();
  // Pending is intentionally published BEFORE send, so visibility alone is not
  // completion. The real button remains disabled/busy until the POST settles.
  // Playwright's click waits for that enabled state; no delay, polling GET or
  // write retry substitutes for the genuine completed-response/error boundary.
  await page.getByRole('dialog').getByRole('button', { name: '核对原操作', exact: true }).click();
  await dialogClosed();
  assert.equal(reconciliationReads() - readsBefore, 1);
  assert.equal(writeAttempts('/leases') - allocationBefore, 1);
  assert.equal(await page.locator('.ip-pending').count(), 0);
  const allocationFailures = report.public_ip_failed_writes.filter(r => r.method === 'POST' && r.path === '/console/v1/public-ips/leases');
  assert.equal(allocationFailures.length, 1, 'The original allocation must have exactly one observed failed transport, not a fabricated application success');
  const allocationResponses = report.requests.filter(r => r.method === 'POST' && r.path === '/console/v1/public-ips/leases');
  assert(allocationResponses.length <= 1, 'A failed allocation must not gain an implicit replay response');
  // A truncated HTTP/2 stream need not publish a Playwright response event.
  // When it does, only the real committed 201 is valid, never a replayed 200.
  // Server-side checked Flush + both real TLS protocol regressions independently
  // prove the genuine 201 headers; only the exact original-operation GET proves
  // the business result. A network failure by itself proves no success.
  assert(allocationResponses.every(r => r.status === 201), 'Any original response headers must be the committed 201');
  const pendingOperation = (await read(`/public-ips/operations/${pendingOperationID}`)).operation;
  assert.equal(pendingOperation.id, pendingOperationID);
  assert.equal(pendingOperation.action, 'lease.allocate');
  assert.equal(pendingOperation.target_resource_id, '');
  assert.deepEqual(pendingOperation.request, {
    pool_id: pool.id, owner_ref: credentials.owner_ref, vpc_id: credentials.vpc_id,
    node_id: publicApproval.node_id, profile_id: publicApproval.profile_id, address: '8.8.4.3',
  }, 'Only the exact immutable original allocation intent can clear unknown');
  const firstLeaseID = pendingOperation.result.lease.id;
  assert.equal(firstLeaseID, pendingOperationID);
  const firstLease = (await read(`/public-ips/leases/${firstLeaseID}`)).lease;
  assert.equal(firstLease.state, 'reserved');
  assert.equal(firstLease.binding_state, 'reserved');
  assert.equal(firstLease.address, '8.8.4.3');
  assert.equal(firstLease.owner_ref, credentials.owner_ref);
  assert.equal(firstLease.vpc_id, credentials.vpc_id);
  assert.equal(firstLease.node_id, publicApproval.node_id);
  assert.equal(firstLease.profile_id, publicApproval.profile_id);
  check('post-commit allocation response loss stays unknown until one original-operation GET confirms the unique lease without resending POST');

  phase = 'public-ip-bind-real-epoch';
  await page.locator('.network-tabs').getByRole('link', { name: 'VPC 与路由', exact: true }).click();
  await page.getByRole('heading', { name: 'VPC 与路由', exact: true }).waitFor();
  await page.getByRole('button', { name: '配置网络', exact: true }).click();
  await pick('公网地址绑定', '8.8.4.3');
  assert((await page.getByRole('combobox', { name: '公网地址绑定', exact: true }).innerText()).includes('8.8.4.3'));
  await page.getByRole('dialog').locator('.public-address-field').scrollIntoViewIfNeeded();
  await screenshot('desktop-public-ip-nat-binding', false);
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow('390px NAT pool binding editor has no horizontal overflow');
  await screenshot('mobile-public-ip-nat-binding', false);
  await page.setViewportSize({ width: 320, height: 844 });
  await noOverflow('320px NAT pool binding editor has no horizontal overflow');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.getByRole('dialog').locator('.public-consent input[type="checkbox"]').check();
  const boundPlan = await submitNetworkPlan(6);
  assert.equal(boundPlan.detail.epoch.snapshot.nat_policies[0].public_ipv4, '8.8.4.3');
  const boundDetail = await advanceUntilStopped(boundPlan.id);
  assert.equal(boundDetail.epoch.state, 'succeeded');
  assert.equal(boundDetail.tasks.length, 6);
  await leasesView();
  await leaseCard(firstLeaseID).waitFor();
  assert.equal(await leaseCard(firstLeaseID).getByRole('button', { name: '回收地址', exact: true }).isDisabled(), true);
  assert((await leaseCard(firstLeaseID).innerText()).includes('已绑定出口'));
  const boundLease = (await read(`/public-ips/leases/${firstLeaseID}`)).lease;
  assert.equal(boundLease.binding_state, 'bound');
  assert.equal(boundLease.releasable, false);
  await noticesExpireNaturally('bound allocation page notice expires before screenshots');
  await screenshot('desktop-public-ip-bound-lease');
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow('390px bound allocation page has no horizontal overflow');
  await screenshot('mobile-public-ip-bound-lease');
  check('allocated public IP binds through one complete six-task real controller epoch and cannot be reclaimed while bound', { epoch: 6 });

  phase = 'public-ip-pool-disable';
  await poolView();
  const poolStateBefore = writeAttempts(`/pools/${pool.id}/state`);
  await setPoolState(false);
  assert.equal(await poolCard().getByRole('button', { name: '分配地址', exact: true }).isDisabled(), true);
  const disabledPool = (await read(`/public-ips/pools/${pool.id}`)).pool;
  assert.equal(disabledPool.enabled, false);
  const heldLease = (await read(`/public-ips/leases/${firstLeaseID}`)).lease;
  assert.equal(heldLease.binding_state, 'bound');
  assert.equal(heldLease.state, 'reserved');
  const unchangedBound = await read(`/overlays/epochs/${boundPlan.id}`);
  assert.deepEqual(unchangedBound.epoch.snapshot, boundDetail.epoch.snapshot);
  assert.deepEqual(receiptProof(unchangedBound), receiptProof(boundDetail));
  await setPoolState(true);
  assert.equal(writeAttempts(`/pools/${pool.id}/state`) - poolStateBefore, 2);
  check('pool disabling blocks new UI allocations without altering its existing bound lease, network intent or receipts');

  phase = 'public-ip-detach-and-reclaim';
  await page.locator('.network-tabs').getByRole('link', { name: 'VPC 与路由', exact: true }).click();
  await page.getByRole('button', { name: '配置网络', exact: true }).click();
  await page.getByRole('button', { name: '移除 NAT', exact: true }).click();
  assert.equal(await page.getByRole('combobox', { name: '公网地址绑定', exact: true }).count(), 0);
  const unboundPlan = await submitNetworkPlan(7);
  assert.deepEqual(unboundPlan.detail.epoch.snapshot.nat_policies || [], []);
  // An unstarted removal is not proof of isolation or a safe release. Its
  // overview must expose recovery, not allow a conflicting new plan. Pool and
  // lease navigation remains read-only and must not require that forbidden UI.
  assert.equal(unboundPlan.detail.epoch.state, 'pending');
  await networkOverview({ requireCanPlan: false });
  const pendingRecovery = page.getByRole('link', { name: '查看变更与恢复', exact: true });
  await pendingRecovery.waitFor();
  assert((await pendingRecovery.getAttribute('href')).endsWith(`#/networks/epochs/${unboundPlan.id}`));
  assert.equal(await page.getByRole('button', { name: '配置网络', exact: true }).count(), 0);
  await leasesView();
  await leaseCard(firstLeaseID).waitFor();
  assert.equal(await leaseCard(firstLeaseID).getByRole('button', { name: '回收地址', exact: true }).isDisabled(), true);
  const pendingDetach = (await read(`/public-ips/leases/${firstLeaseID}`)).lease;
  assert.equal(pendingDetach.releasable, false);
  check('a pending NAT removal cannot prematurely free an allocated public IP');
  await page.goto(new URL(`#/networks/epochs/${unboundPlan.id}`, base).href, { waitUntil: 'networkidle' });
  await page.getByRole('heading', { name: /网络变更/ }).waitFor();
  const unboundDetail = await advanceUntilStopped(unboundPlan.id);
  assert.equal(unboundDetail.epoch.state, 'succeeded');
  assert.equal(unboundDetail.tasks.length, 6);
  await leasesView();
  await leaseCard(firstLeaseID).waitFor();
  assert.equal(await leaseCard(firstLeaseID).getByRole('button', { name: '回收地址', exact: true }).isEnabled(), true);
  const detachedLease = (await read(`/public-ips/leases/${firstLeaseID}`)).lease;
  assert.equal(detachedLease.releasable, true);
  await leaseCard(firstLeaseID).getByRole('button', { name: '回收地址', exact: true }).click();
  await page.getByLabel('输入公网 IP 以确认回收', { exact: true }).fill('8.8.4.3');
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow('390px public IP reclamation dialog has no horizontal overflow');
  await screenshot('mobile-public-ip-reclaim', false);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await screenshot('desktop-public-ip-reclaim', false);
  await page.getByRole('dialog').getByRole('button', { name: '回收公网 IP', exact: true }).click();
  await dialogClosed();
  await leaseCard(firstLeaseID).waitFor();
  assert((await leaseCard(firstLeaseID).innerText()).includes('已回收'));
  assert.equal(await leaseCard(firstLeaseID).getByRole('button', { name: '回收地址', exact: true }).count(), 0);
  const reclaimedLease = (await read(`/public-ips/leases/${firstLeaseID}`)).lease;
  assert.equal(reclaimedLease.state, 'released');
  assert.equal(reclaimedLease.binding_state, 'released');
  assert.equal(writeAttempts(`/leases/${firstLeaseID}/release`), 1);
  assert.deepEqual((await read(`/public-ips/operations/${pendingOperationID}`)).operation, pendingOperation);
  check('public IP can be reclaimed only after every unbinding phase and its original allocation operation is immutable', { epoch: 7 });

  phase = 'public-ip-reallocate-and-history';
  await poolView();
  await fillAllocation();
  await page.getByRole('dialog').getByRole('button', { name: '分配公网 IP', exact: true }).click();
  await dialogClosed();
  assert.equal(writeAttempts('/leases'), 2);
  await leasesView();
  const finalLeases = (await read('/public-ips/leases?cluster_id=cluster-fixture')).items;
  assert.equal(finalLeases.length, 2);
  const reallocatedLease = finalLeases.find(l => l.id !== firstLeaseID);
  assert(reallocatedLease);
  assert.equal(reallocatedLease.address, '8.8.4.3');
  assert.equal(reallocatedLease.state, 'reserved');
  assert.equal(reallocatedLease.binding_state, 'reserved');
  assert.equal(finalLeases.find(l => l.id === firstLeaseID).state, 'released');
  assert.notEqual(reallocatedLease.id, firstLeaseID);
  assert.equal(writeAttempts(), 7);
  for (const before of originalFive) {
    const after = await read(`/overlays/epochs/${before.epoch.id}`);
    assert.equal(after.epoch.snapshot_sha256, before.epoch.snapshot_sha256);
    assert.deepEqual(after.epoch.snapshot, before.epoch.snapshot);
    assert.deepEqual(receiptProof(after), receiptProof(before));
  }
  check('reallocation creates a new exclusive lease while retaining the reclaimed record and all original five epoch snapshots and receipts');
  await noticesExpireNaturally('lease history notice expires before final actual screenshots');
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow('390px public lease history has no horizontal overflow');
  await screenshot('mobile-public-ip-lease-history');
  await page.setViewportSize({ width: 320, height: 844 });
  await noOverflow('320px public lease history has no horizontal overflow');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await screenshot('desktop-public-ip-lease-history');
  await noOverflow('desktop public lease history has no horizontal overflow');
  await page.getByRole('button', { name: '语言与外观', exact: true }).click();
  await pick('界面语言', 'English');
  await pick('Appearance', 'Dark');
  await page.getByRole('button', { name: 'Done', exact: true }).click();
  await dialogClosed();
  await page.setViewportSize({ width: 390, height: 844 });
  await noOverflow('390px English dark public lease history has no horizontal overflow');
  await screenshot('mobile-public-ip-english-dark');
  await page.setViewportSize({ width: 1440, height: 1000 });
  await noOverflow('desktop English dark public lease history has no horizontal overflow');
  await screenshot('desktop-public-ip-english-dark');
  assert.equal(await page.locator('select').count(), 0);
  check('public pool, allocation, binding and reclamation use custom controls across mobile/desktop and Chinese/light/English/dark');
  report.public_ip_pool_managed = true;
  report.public_ip_pool_extended = true;
  report.public_ip_post_commit_ack_reconciled = true;
  report.public_ip_bound_and_detached = true;
  report.public_ip_reclaimed_and_reallocated = true;
  report.original_five_epochs_preserved = true;

  // New VM resources do not replace the historical NAT workflow above. All
  // writes below are real visible controls, followed by GET-only exact proof.
  phase = 'floating-public-allocation';
  await page.getByRole('button', { name: 'Language & appearance', exact: true }).click();
  await pick('Language', '简体中文'); await pick('外观', '浅色');
  await page.getByRole('button', {name:'完成',exact:true}).click(); await dialogClosed();
  const originalSeven = [...originalFive, await read(`/overlays/epochs/${boundPlan.id}`), await read(`/overlays/epochs/${unboundPlan.id}`)];
  const vmCard = id => page.locator(`.vm-public-resource[data-resource-id="${id}"]`);
  async function resourcesView(cluster = 'cluster-fixture') {
    await page.goto(new URL(`#/networks/public-ips?view=resources&cluster=${cluster}`, base).href, {waitUntil:'networkidle'});
    await page.getByRole('heading', {name:'实例公网地址',exact:true}).waitFor();
    await page.locator('.vm-public-panel').waitFor();
  }
  async function vmAllocation(mode, address, poolLabel, cluster = 'cluster-fixture') {
    await resourcesView(cluster);
    await pick('实例公网地址池',poolLabel);
    await page.getByRole('button',{name:'分配实例地址',exact:true}).click();
    await pick('公网地址使用方式',mode === 'floating' ? '独立浮动 IP' : '虚拟机公网直绑');
    if (mode === 'floating') await pick('浮动 IP 所属 VPC',`${publicVPC.name} · ${publicVPC.cidr}`);
    else await pick('选择客户引用', credentials.owner_ref);
    await pick('公网网络配置', mode === 'floating' ? `${publicApproval.node_id} · ${publicApproval.profile_id}` : `${credentials.direct_node_id} · normal-public-ipv4`);
    await pick('实例公网地址',address);
    await page.getByRole('dialog').getByRole('button',{name:'分配实例公网 IP',exact:true}).click();
    await dialogClosed();
    const current = (await read(`/public-ips/resources?cluster_id=${cluster}`)).items.filter(r => r.address === address && r.state === 'reserved');
    assert.equal(current.length,1); assert.equal(current[0].mode,mode); assert.equal(current[0].binding_state,'unbound'); assert.equal(current[0].binding_generation,0);
    await vmCard(current[0].id).waitFor(); return current[0];
  }
  const floating = await vmAllocation('floating','8.8.4.4','公网出口池 · 8.8.4.0/24');
  const floatingAllocationOperation = (await read(`/public-ips/resource-operations/${floating.id}`)).operation;
  const resourceOptions = await read('/public-ips/options');
  assert.equal(resourceOptions.complete,true); assert.equal(resourceOptions.approvals.find(a => a.vpc_id === credentials.vpc_id).allow_floating_ip,true);
  const floatTargets = credentials.members.map(m => resourceOptions.resource_targets.find(t => t.instance_id === m.instance_id && t.mode === 'floating'));
  assert(floatTargets.every(Boolean)); assert.notEqual(floatTargets[0].node_id,floatTargets[1].node_id);
  async function bindFloating(target, expectedEpoch, moving = false) {
    phase = moving ? 'floating-public-move' : 'floating-public-bind';
    await vmCard(floating.id).getByRole('button',{name:moving ? '更换实例' : '绑定实例',exact:true}).click();
    await pick('绑定目标实例',`${target.ipv4} · ${target.node_id} · ${target.instance_id}`);
    await page.getByRole('dialog').locator('.binding-policy-version').waitFor();
    const targetPolicy = (await read(`/instances/${target.instance_id}/public-ingress`)).policy;
    assert.equal(targetPolicy.instance_id,target.instance_id); assert.equal(targetPolicy.owner_ref,credentials.owner_ref);
    assert.equal(targetPolicy.revision,0); assert.deepEqual(targetPolicy.rules,[]); assert.equal(targetPolicy.supported,true);
    assert((await page.getByRole('dialog').locator('.binding-ingress').innerText()).includes('默认拒绝公网新入站连接'));
    assert.equal(await page.getByRole('dialog').locator('.floating-consent').count(),0);
    await page.getByRole('dialog').locator('.resource-confirmation input').fill(target.instance_id);
    const title = moving ? '确认更换绑定实例' : '确认绑定公网 IP';
    assert.equal(await page.getByRole('dialog').getByRole('button',{name:title,exact:true}).isDisabled(),false);
    if (!moving) {
      await dialogExcludesNotices('floating bind dialog isolates genuine background notices');
      await noOverflow('desktop floating bind confirmation has no overflow'); await screenshot('desktop-floating-ip-binding',false);
      await page.setViewportSize({width:390,height:844}); await noOverflow('390px floating bind confirmation has no overflow'); await screenshot('mobile-floating-ip-binding',false);
      await page.setViewportSize({width:320,height:844}); await noOverflow('320px floating bind confirmation has no overflow');
      await page.setViewportSize({width:1440,height:1000});
    }
    const bindResponse = page.waitForResponse(r => new URL(r.url()).pathname === `/console/v1/public-ips/resources/${floating.id}/binding` && r.request().method() === 'POST');
    await page.getByRole('dialog').getByRole('button',{name:title,exact:true}).click();
    const bindTransport = await bindResponse; assert.equal(bindTransport.status(),202);
    assert.deepEqual(bindTransport.request().postDataJSON(),{instance_id:target.instance_id,expected_generation:expectedEpoch-8,expected_ingress_revision:0});
    await dialogClosed();
    const r = (await read(`/public-ips/resources/${floating.id}`)).resource;
    assert.equal(r.binding_state,'pending'); assert.equal(r.instance_id,target.instance_id); assert.equal(r.binding_generation,expectedEpoch - 7); assert(r.epoch_id);
    const detail = await read(`/overlays/epochs/${r.epoch_id}`);
    assert.equal(detail.epoch.epoch,expectedEpoch); assert.equal(detail.epoch.state,'pending');
    assert.equal(detail.epoch.snapshot.floating_ips.length,1); assert.equal(detail.epoch.snapshot.floating_ips[0].instance_id,target.instance_id);
    assert.equal(detail.epoch.snapshot.floating_ips[0].public_ipv4,'8.8.4.4');
    assert.deepEqual(detail.epoch.snapshot.floating_ips[0].ingress.rules,[]);
    assert.equal(detail.epoch.snapshot.floating_ips[0].ingress.instance_id,target.instance_id);
    assert.equal(detail.epoch.snapshot.floating_ips[0].ingress.owner_ref,credentials.owner_ref);
    assert.equal(detail.epoch.snapshot.floating_ips[0].ingress.revision,0);
    assert.match(detail.epoch.snapshot.floating_ips[0].ingress.sha256,/^[a-f0-9]{64}$/);
    assert.equal(await vmCard(floating.id).getByRole('button',{name:'回收',exact:true}).isDisabled(),true);
    await page.locator('.resource-next').getByRole('link',{name:'继续关联任务',exact:true}).click();
    await page.getByRole('heading',{name:/网络变更/}).waitFor();
    const completed = await advanceUntilStopped(r.epoch_id); assert.equal(completed.epoch.state,'succeeded'); assert.equal(completed.tasks.length,6);
    const result = (await read(`/public-ips/resources/${floating.id}`)).resource;
    assert.equal(result.binding_state,'bound'); assert.equal(result.instance_id,target.instance_id); assert.equal(result.releasable,false);
    await resourcesView(); await vmCard(floating.id).waitFor(); return completed;
  }
  const floatingBound = await bindFloating(floatTargets[0],8);
  check('floating allocation binds the exact original VM through six persisted epoch8 tasks with an explicit empty default-deny policy, not a full-port checkbox');
  await noticesExpireNaturally('floating binding notice expires naturally before actual resource screenshots');
  await page.setViewportSize({width:390,height:844}); await noOverflow('390px floating bound resource has no overflow'); await screenshot('mobile-floating-ip-bound');
  await page.setViewportSize({width:1440,height:1000}); await noOverflow('desktop floating bound resource has no overflow'); await screenshot('desktop-floating-ip-bound');
  const policyProofs = [];
  async function ingressView(target, diagnosticPhase = 'public-ingress-read-policy') {
    phase = diagnosticPhase;
    await page.goto(new URL(`#/instances/${target.instance_id}?tab=public`,base).href,{waitUntil:'networkidle'});
    await page.locator('.public-ingress-panel .ingress-policy-state').waitFor();
    const policy = (await read(`/instances/${target.instance_id}/public-ingress`)).policy;
    assert.equal(policy.instance_id,target.instance_id); assert.equal(policy.owner_ref,credentials.owner_ref); assert.equal(policy.supported,true); return policy;
  }
  async function updateIngress(target, expectedRevision, expectedEpoch, rules) {
    const prior = await ingressView(target); assert.equal(prior.revision,expectedRevision); assert.equal(prior.state,'active');
    phase = 'public-ingress-open-editor';
    await page.getByRole('button',{name:'编辑入站规则',exact:true}).click();
    const dialog=page.getByRole('dialog');
    if (!rules.length) {
      phase = 'public-ingress-remove-rules';
      while(await dialog.locator('.ingress-rules .ingress-rule').count()) {
        const remove = dialog.locator('.ingress-rules .ingress-rule').first().getByRole('button',{name:/^移除允许规则 /});
        assert.equal(await remove.count(),1,'Each original rule row must expose exactly one accessible remove control');
        await remove.click();
      }
    } else {
      phase = 'public-ingress-add-rules';
      for(const rule of rules) {
        await pick('入站协议',rule.protocol==='icmp'?'ICMP 回显':rule.protocol.toUpperCase());
        await dialog.getByLabel('允许来源 CIDR',{exact:true}).fill(rule.source_cidr);
        if(rule.protocol!=='icmp') {await dialog.getByLabel('入站起始端口',{exact:true}).fill(String(rule.port_start));await dialog.getByLabel('入站结束端口',{exact:true}).fill(String(rule.port_end));}
        await dialog.getByRole('button',{name:'添加允许规则',exact:true}).click();
      }
    }
    assert.equal(await dialog.locator('.ingress-rules .ingress-rule').count(),rules.length);
    assert.equal(await dialog.locator('select,input[type="number"]').count(),0);
    phase = 'public-ingress-confirm';
    await dialog.getByLabel('确认入站规则实例 ID',{exact:true}).fill(target.instance_id);
    if(expectedEpoch===9) {
      phase = 'public-ingress-editor-layout';
      await dialogExcludesNotices('public ingress editor excludes background notices');
      await dialog.locator('.ingress-explanation').scrollIntoViewIfNeeded();
      await noOverflow('desktop public ingress custom rule editor has no overflow');await screenshot('desktop-public-ingress-editor',false);
      await page.setViewportSize({width:390,height:844});await dialog.locator('.ingress-explanation').scrollIntoViewIfNeeded();await noOverflow('390px public ingress custom rule editor has no overflow');await screenshot('mobile-public-ingress-editor',false);
      await page.setViewportSize({width:320,height:844});await noOverflow('320px public ingress custom rule editor has no overflow');await page.setViewportSize({width:1440,height:1000});
    }
    phase = 'public-ingress-submit';
    const response=page.waitForResponse(r=>new URL(r.url()).pathname===`/console/v1/instances/${target.instance_id}/public-ingress`&&r.request().method()==='POST');
    await dialog.getByRole('button',{name:'保存入站规则',exact:true}).click();const transport=await response;assert.equal(transport.status(),202);
    const request=transport.request().postDataJSON();assert.equal(request.expected_revision,expectedRevision);assert.equal(request.rules.length,rules.length);
    phase = 'public-ingress-admission-check';
    const result=await transport.json();assert.equal(result.policy.state,'pending');assert.equal(result.policy.revision,expectedRevision+1);assert.equal(result.policy.instance_id,target.instance_id);assert.equal(result.policy.effective_revision,null);
    assert.equal(result.operation.actor_id,credentials.actor_id);assert.deepEqual(result.operation.request,request);assert.equal(result.operation.target_instance_id,target.instance_id);
    await dialogClosed();await page.locator('.public-ingress-panel .ingress-policy-state').waitFor();assert((await page.locator('.public-ingress-panel').innerText()).includes('规则变更待执行'));
    assert.equal(await page.getByRole('button',{name:'编辑入站规则',exact:true}).isDisabled(),true);
    phase = 'public-ingress-release';
    await page.locator('.public-ingress-panel').getByRole('link',{name:'查看规则网络任务',exact:true}).click();await page.getByRole('heading',{name:/网络变更/}).waitFor();
    const completed=await advanceUntilStopped(result.policy.epoch_id);assert.equal(completed.epoch.epoch,expectedEpoch);assert.equal(completed.epoch.state,'succeeded');assert.equal(completed.tasks.length,6);
    const frozen=completed.epoch.snapshot.floating_ips[0].ingress;assert.equal(frozen.instance_id,target.instance_id);assert.equal(frozen.revision,expectedRevision+1);assert.deepEqual(frozen.rules,result.policy.rules);assert.equal(frozen.sha256,result.policy.sha256);
    const current=await ingressView(target,'public-ingress-effective-check');assert.equal(current.state,'active');assert.equal(current.effective_revision,expectedRevision+1);assert.deepEqual(current.rules,result.policy.rules);
    const immutable=(await read(`/public-ingress-operations/${result.operation.id}`)).operation;assert.deepEqual(immutable,result.operation);policyProofs.push(immutable);
    if(expectedEpoch===9||expectedEpoch===12) {
      phase = 'public-ingress-effective-layout';
      await noticesExpireNaturally('policy notices expire naturally before actual effective-rule screenshots');
      const suffix=expectedEpoch===9?'allowed':'revoked';
      await page.setViewportSize({width:390,height:844});await noOverflow(`390px ${suffix} ingress panel has no overflow`);await screenshot(`mobile-public-ingress-${suffix}`);
      await page.setViewportSize({width:320,height:844});await noOverflow(`320px ${suffix} ingress panel has no overflow`);await page.setViewportSize({width:1440,height:1000});await noOverflow(`desktop ${suffix} ingress panel has no overflow`);await screenshot(`desktop-public-ingress-${suffix}`);
    }
    phase = 'public-ingress-return-resources';
    await resourcesView();return completed;
  }
  const originalTargetAllowed = await updateIngress(floatTargets[0],0,9,[
    {protocol:'tcp',source_cidr:'203.0.113.10/32',port_start:443,port_end:443},
    {protocol:'udp',source_cidr:'203.0.113.0/24',port_start:5300,port_end:5310},
    {protocol:'icmp',source_cidr:'0.0.0.0/0',port_start:0,port_end:0},
  ]);
  check('independent VM0 public ingress permits only explicit TCP/UDP ranges and ICMP echo sources after epoch9, without changing binding ownership');
  const floatingMoved = await bindFloating(floatTargets[1],10,true);
  assert.notEqual(floatingMoved.epoch.snapshot.floating_ips[0].instance_id,floatingBound.epoch.snapshot.floating_ips[0].instance_id);
  assert.equal(floatingMoved.epoch.snapshot.floating_ips[0].resource_id,floating.id);
  assert.equal(floatingMoved.epoch.snapshot.floating_ips[0].public_ipv4,floating.address);
  const preservedBound = await read(`/overlays/epochs/${floatingBound.epoch.id}`);
  assert.deepEqual(preservedBound.epoch.snapshot,floatingBound.epoch.snapshot); assert.deepEqual(receiptProof(preservedBound),receiptProof(floatingBound));
  assert.deepEqual(floatingMoved.epoch.snapshot.floating_ips[0].ingress.rules,[]);
  assert.equal((await read(`/instances/${floatTargets[0].instance_id}/public-ingress`)).policy.rules.length,3);
  check('floating move preserves its address/resource in epoch10 but uses the new VM default-deny policy, never moving VM0 rules');
  const targetAllowed = await updateIngress(floatTargets[1],0,11,[{protocol:'tcp',source_cidr:'198.51.100.25/32',port_start:22,port_end:22}]);
  const targetRevoked = await updateIngress(floatTargets[1],1,12,[]);
  for(const original of [floatingBound,originalTargetAllowed,floatingMoved,targetAllowed]) {const saved=await read(`/overlays/epochs/${original.epoch.id}`);assert.deepEqual(saved.epoch.snapshot,original.epoch.snapshot);assert.deepEqual(receiptProof(saved),receiptProof(original));}
  assert.deepEqual(targetRevoked.epoch.snapshot.floating_ips[0].ingress.rules,[]);
  check('revoking all VM1 public ingress rules creates epoch12 and preserves earlier accepted policy versions and exact receipts');
  await vmCard(floating.id).getByRole('button',{name:'解绑',exact:true}).click();
  await page.getByRole('dialog').locator('.resource-confirmation input').fill(floating.address);
  await page.getByRole('dialog').getByRole('button',{name:'解绑公网地址',exact:true}).click(); await dialogClosed();
  const pendingFloatDetach = (await read(`/public-ips/resources/${floating.id}`)).resource;
  assert.equal(pendingFloatDetach.binding_state,'pending'); assert.equal(pendingFloatDetach.releasable,false); assert.equal(pendingFloatDetach.binding_generation,6);
  assert.equal(await vmCard(floating.id).getByRole('button',{name:'回收',exact:true}).isDisabled(),true);
  await page.locator('.resource-next').getByRole('link',{name:'继续关联任务',exact:true}).click(); await page.getByRole('heading',{name:/网络变更/}).waitFor();
  const floatDetached = await advanceUntilStopped(pendingFloatDetach.epoch_id);
  assert.equal(floatDetached.epoch.epoch,13); assert.equal(floatDetached.epoch.state,'succeeded'); assert.deepEqual(floatDetached.epoch.snapshot.floating_ips || [],[]);
  await resourcesView(); const detachedFloat = (await read(`/public-ips/resources/${floating.id}`)).resource;
  assert.equal(detachedFloat.binding_state,'unbound'); assert.equal(detachedFloat.releasable,true);
  await vmCard(floating.id).getByRole('button',{name:'回收',exact:true}).click(); await page.getByRole('dialog').locator('.resource-confirmation input').fill(floating.address);
  await page.getByRole('dialog').getByRole('button',{name:'回收公网地址',exact:true}).click(); await dialogClosed();
  assert.equal((await read(`/public-ips/resources/${floating.id}`)).resource.state,'released');
  const newFloating = await vmAllocation('floating','8.8.4.4','公网出口池 · 8.8.4.0/24'); assert.notEqual(newFloating.id,floating.id);
  assert.deepEqual((await read(`/public-ips/resource-operations/${floating.id}`)).operation,floatingAllocationOperation);
  check('floating unbind epoch13 must complete all node releases before reclamation; reallocation retains immutable allocation history');
  for (const before of originalSeven) {const after = await read(`/overlays/epochs/${before.epoch.id}`); assert.equal(after.epoch.snapshot_sha256,before.epoch.snapshot_sha256); assert.deepEqual(after.epoch.snapshot,before.epoch.snapshot); assert.deepEqual(receiptProof(after),receiptProof(before));}
  check('all original seven NAT/network epoch snapshots and exact receipts remain unchanged after floating bind, move, unbind and reallocation');

  phase = 'direct-public-create';
  const direct = await vmAllocation('direct','9.9.9.2','实例直绑池 · 9.9.9.0/24','public-direct');
  await page.goto(new URL('#/instances',base).href,{waitUntil:'networkidle'});
  await page.getByRole('button',{name:'创建实例',exact:true}).click();
  await page.getByRole('combobox',{name:'选择预设规格',exact:true}).click();
  await page.getByRole('option',{name:/^browser-direct-public ·/}).click();
  await page.getByLabel('主机名',{exact:false}).fill('browser-public-vm');
  await page.getByLabel('归属客户 ID',{exact:false}).fill(credentials.owner_ref);
  await pick('选择直绑公网地址','9.9.9.2');
  await noOverflow('desktop exact direct public VM creation has no overflow'); await screenshot('desktop-direct-public-create',false);
  await page.setViewportSize({width:390,height:844}); await noOverflow('390px direct public VM creation has no overflow'); await screenshot('mobile-direct-public-create',false);
  await page.setViewportSize({width:320,height:844}); await noOverflow('320px direct public VM creation has no overflow'); await page.setViewportSize({width:1440,height:1000});
  const createResponse = page.waitForResponse(r => new URL(r.url()).pathname === '/console/v1/instances' && r.request().method() === 'POST' && r.status() === 202);
  await page.getByRole('dialog').getByRole('button',{name:'创建任务',exact:true}).click();
  const createTransport = await createResponse;
  const frozenCreateBody = createTransport.request().postDataJSON();
  assert.equal(frozenCreateBody.public_ip_resource_id,direct.id); assert.equal(frozenCreateBody.public_ip_expected_generation,0); assert.equal(frozenCreateBody.owner_ref,credentials.owner_ref); assert.equal(frozenCreateBody.preset_id,'browser-direct-public');
  const createdIntent = (await createTransport.json()).operation;
  assert(createdIntent && /^[a-f0-9]{32}$/.test(createdIntent.id));
  await page.getByRole('dialog').getByRole('link',{name:'查看原任务',exact:true}).click();
  await page.getByRole('heading',{name:'任务详情',exact:true}).waitFor();
  async function dispatchNodeTask(id) {
    const before = posts('/dispatch'); const task = (await read(`/operations/${id}`)).operation; assert.equal(task.state,'accepted');
    await page.getByRole('button',{name:'派发任务',exact:true}).click(); await page.getByRole('dialog').locator('input').fill(id);
    const dispatchResponse = page.waitForResponse(r => new URL(r.url()).pathname === `/console/v1/operations/${id}/dispatch` && r.request().method() === 'POST');
    await page.getByRole('button',{name:'确认派发',exact:true}).click();
    assert.equal((await dispatchResponse).status(),202,'authorized explicit node task dispatch must be accepted');
    await dialogClosed();
    const deadline = Date.now()+30000;
    let current;
    while(Date.now()<deadline) {current = (await read(`/operations/${id}`)).operation; if(current.state === 'succeeded' || current.state === 'rejected') break; await page.waitForTimeout(200);}
    assert.equal(current.state,'succeeded'); assert.equal(posts('/dispatch') - before,1); return current;
  }
  phase = 'direct-public-create-dispatch';
  await dispatchNodeTask(createdIntent.id);
  let directCurrent = (await read(`/public-ips/resources/${direct.id}`)).resource;
  assert.equal(directCurrent.binding_state,'bound'); assert.equal(directCurrent.instance_id,createdIntent.instance_id); assert.equal(directCurrent.binding_generation,1);
  let vm = (await read(`/instances/${createdIntent.instance_id}`)).instance;
  assert.equal(vm.resources.network_type,'normal'); assert.equal(vm.node_id,credentials.direct_node_id); assert.equal(vm.state,'running');
  check('visible VM creation freezes the exact approved resource into node3 and real controller dispatch confirms its persisted binding');
  async function directInstancePanel() {
    await page.goto(new URL(`#/instances/${createdIntent.instance_id}`,base).href,{waitUntil:'networkidle'});
    await page.getByRole('tab',{name:'公网地址',exact:true}).click(); await vmCard(direct.id).waitFor();
  }
  await directInstancePanel(); await noticesExpireNaturally('direct creation notice expires before actual instance resource screenshots');
  await page.setViewportSize({width:390,height:844}); await noOverflow('390px instance direct public panel has no overflow'); await screenshot('mobile-direct-public-instance');
  await page.setViewportSize({width:1440,height:1000}); await noOverflow('desktop instance direct public panel has no overflow'); await screenshot('desktop-direct-public-instance');
  phase = 'direct-public-shutdown';
  await page.getByRole('button',{name:'关机',exact:true}).click(); await page.getByLabel('确认实例 ID',{exact:true}).fill(createdIntent.instance_id);
  const stopResponse = page.waitForResponse(r => new URL(r.url()).pathname === `/console/v1/instances/${createdIntent.instance_id}/operations` && r.request().method() === 'POST' && r.status() === 202);
  await page.getByRole('dialog').getByRole('button',{name:'创建任务',exact:true}).click(); const stopIntent = (await (await stopResponse).json()).operation;
  await page.getByRole('dialog').getByRole('link',{name:'查看原任务',exact:true}).click(); await page.getByRole('heading',{name:'任务详情',exact:true}).waitFor(); await dispatchNodeTask(stopIntent.id);
  await directInstancePanel();
  phase = 'direct-public-detach';
  await vmCard(direct.id).getByRole('button',{name:'解绑',exact:true}).click(); await page.getByRole('dialog').locator('.resource-confirmation input').fill(direct.address);
  await page.getByRole('dialog').getByRole('button',{name:'解绑公网地址',exact:true}).click(); await dialogClosed();
  directCurrent = (await read(`/public-ips/resources/${direct.id}`)).resource;
  assert.equal(directCurrent.binding_state,'pending'); assert.equal(directCurrent.binding_generation,2); assert.equal(directCurrent.epoch_id,''); assert(directCurrent.operation_id);
  assert.equal(await vmCard(direct.id).getByRole('button',{name:'回收',exact:true}).isDisabled(),true);
  // The instance refresh can remount its public-resource panel after admission.
  // Continue through the durable row link, not an ephemeral local ACK banner.
  const detachTaskLink = vmCard(direct.id).getByRole('link',{name:'查看关联任务',exact:true});
  const detachTaskURL = new URL(await detachTaskLink.getAttribute('href'),base);
  assert.equal(detachTaskURL.origin,new URL(base).origin);
  assert.equal(detachTaskURL.hash,`#/operations/${directCurrent.operation_id}`);
  phase = 'direct-public-detach-dispatch';
  await detachTaskLink.click(); await page.getByRole('heading',{name:'任务详情',exact:true}).waitFor(); await dispatchNodeTask(directCurrent.operation_id);
  await directInstancePanel(); directCurrent = (await read(`/public-ips/resources/${direct.id}`)).resource;
  assert.equal(directCurrent.binding_state,'unbound'); assert.equal(directCurrent.releasable,true);
  phase = 'direct-public-reclaim';
  await vmCard(direct.id).getByRole('button',{name:'回收',exact:true}).click(); await page.getByRole('dialog').locator('.resource-confirmation input').fill(direct.address);
  await page.getByRole('dialog').getByRole('button',{name:'回收公网地址',exact:true}).click(); await dialogClosed();
  assert.equal((await read(`/public-ips/resources/${direct.id}`)).resource.state,'released');
  assert.equal((await read(`/instances/${createdIntent.instance_id}`)).instance.state,'shutoff');
  check('direct address is reclaimed only after visible shutdown, exact node3 detachment dispatch and confirmed server state, never a hot IP replacement');
  assert.equal(writeAttempts(),16);
  assert.equal(report.public_ingress_write_attempts.length,3);
  for(const op of policyProofs) assert.deepEqual((await read(`/public-ingress-operations/${op.id}`)).operation,op);
  report.public_ingress_configured_default_deny_moved_revoked=true;report.public_ingress_immutable_operations=true;
  report.floating_bound_moved_unbound = true; report.floating_reclaimed_reallocated = true;
  report.direct_created_dispatched_detached_reclaimed = true; report.first_seven_epochs_retained = true;
  await resourcesView(); await noticesExpireNaturally('new resource history notice expires naturally before final screenshots');
  await page.setViewportSize({width:390,height:844}); await noOverflow('390px floating history and reallocated address has no overflow'); await screenshot('mobile-floating-ip-history');
  await page.setViewportSize({width:320,height:844}); await noOverflow('320px floating history has no overflow');
  await page.setViewportSize({width:1440,height:1000}); await screenshot('desktop-floating-ip-history');
  await page.getByRole('button',{name:'语言与外观',exact:true}).click(); await pick('界面语言','English'); await pick('Appearance','Dark'); await page.getByRole('button',{name:'Done',exact:true}).click(); await dialogClosed();
  await page.setViewportSize({width:390,height:844}); await noOverflow('390px English dark floating history has no overflow'); await screenshot('mobile-floating-ip-english-dark');
  await page.setViewportSize({width:1440,height:1000}); await noOverflow('desktop English dark floating history has no overflow'); await screenshot('desktop-floating-ip-english-dark');
  await page.goto(new URL(`#/instances/${floatTargets[0].instance_id}?tab=public`,base).href,{waitUntil:'networkidle'});
  await page.locator('.public-ingress-panel .ingress-policy-state').waitFor();
  await page.setViewportSize({width:390,height:844});await noOverflow('390px English dark public ingress rules have no overflow');await screenshot('mobile-public-ingress-english-dark');
  await page.setViewportSize({width:320,height:844});await noOverflow('320px English dark public ingress rules have no overflow');await page.setViewportSize({width:1440,height:1000});await screenshot('desktop-public-ingress-english-dark');
  assert.equal(await page.locator('select').count(),0);
  await page.goto(new URL(`#/instances/${createdIntent.instance_id}`,base).href,{waitUntil:'networkidle'});
  await page.getByRole('tab',{name:'Public addresses',exact:true}).click(); await vmCard(direct.id).waitFor();
  await page.setViewportSize({width:390,height:844}); await noOverflow('390px English dark instance tabs and direct resource have no document overflow');
  await page.setViewportSize({width:320,height:844}); await noOverflow('320px English dark instance tabs keep horizontal scrolling within their own strip');
  await page.setViewportSize({width:1440,height:1000}); await noOverflow('desktop English dark direct resource has no overflow');
  check('direct and floating management retain custom controls across mobile/desktop and Chinese/light/English/dark');

  phase = 'real-mysql-members-pagination';
  await membersBrowserAcceptance({ page, output, report, base, credentials });

  assert.deepEqual(report.console_errors, []);
  check('no browser JavaScript errors');
  report.public_egress_enabled = true;
  report.public_egress_disabled = true;
  report.pure_internet_reenabled = true;
  report.status = 'passed';
  report.passed = true;
  console.log('PASS real MySQL network management browser acceptance');
} catch (error) {
  report.status = 'failed';
  report.failure = { phase, kind: error instanceof Error ? error.name : 'Error', message: safeMessage(error) };
  // No raw error object/stack or HTML. A screenshot is safe only on a signed-in business page.
  if (signedIn && page && !page.isClosed()) {
    try { await screenshot('failure', false); } catch { /* Do not mask the original failure. */ }
  }
  console.error(`FAIL ${phase}: ${safeMessage(error)}`);
  process.exitCode = 1;
} finally {
  if (context) { try { await context.close(); } catch { /* Browser may have already stopped. */ } }
  fs.writeFileSync(path.join(output, 'report.json'), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
}
