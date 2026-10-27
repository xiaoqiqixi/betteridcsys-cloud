// W07-A reads the real console Handler and disposable MySQL through the browser.
// No response fulfillment, application state injection, member write or API mock.
// Only transport abort/delay is injected; all successful bodies come from HTTPS.
import assert from 'node:assert/strict';
import path from 'node:path';

export const MEMBERS_SCREENSHOTS = Object.freeze([
  'members-desktop-first.png', 'members-desktop-last.png',
  'members-mobile-first.png', 'members-mobile-last.png',
  'members-desktop-english-dark.png', 'members-mobile-english-dark.png',
]);
export const MEMBERS_CHECKS = Object.freeze([
  'actual_mysql_inventory_205', 'desktop_complete_pagination', 'previous_page',
  'refresh_returns_first', 'same_identity_refresh_keeps_page',
  'failed_next_keeps_rows', 'retry_requested_page', 'loading_keeps_rows',
  'mobile_complete_pagination', 'mobile_320_layout', 'custom_controls',
  'english_dark_layout', 'keyboard_pagination_focus', 'logout_cancels_pending_read',
  'anonymous_read_denied', 'viewer_read_denied', 'no_business_writes',
  'six_actual_screenshots',
]);

export function validateMembersFixture(value) {
  assert(value && Object.getPrototypeOf(value) === Object.prototype, 'Invalid members fixture');
  assert(value.count === 205 && Array.isArray(value.ids) && value.ids.length === 205, 'Invalid members inventory');
  assert(value.ids.every(id => typeof id === 'string' && /^[a-f0-9]{32}$/.test(id)) && new Set(value.ids).size === 205, 'Invalid members identities');
  assert(typeof value.viewer_email === 'string' && /^[^\s@]+@(?:[a-z0-9-]+\.)*example\.invalid$/.test(value.viewer_email), 'Invalid synthetic viewer');
  assert(typeof value.viewer_password === 'string' && value.viewer_password.length >= 16, 'Invalid private viewer credential');
  return value;
}
export function validateMembersResponse(value) {
  assert(value && Object.getPrototypeOf(value) === Object.prototype, 'Invalid members response');
  assert(value.limit === 100 && Array.isArray(value.items) && value.items.length <= 100, 'Invalid members page size');
  assert(value.items.every(item => item && typeof item.id === 'string' && /^[a-f0-9]{32}$/.test(item.id) && typeof item.email === 'string' && /^[^\s@]+@(?:[a-z0-9-]+\.)*example\.invalid$/.test(item.email)), 'Invalid synthetic members page');
  assert(new Set(value.items.map(item => item.id)).size === value.items.length, 'Duplicate member in page');
  assert(value.next_cursor === null ? value.truncated_possible === false : typeof value.next_cursor === 'string' && value.next_cursor.length <= 512 && /^u1\.[A-Za-z0-9_-]+$/.test(value.next_cursor) && value.items.length === 100 && value.truncated_possible === true, 'Invalid members continuation');
  return value;
}

// Self-contained browser-realm callback: native Fetch Response.status is a
// numeric property; only the outer Playwright Response uses status().
export async function readMembersInBrowser(cursor) {
  const response = await fetch('/console/v1/users' + (cursor ? '?cursor=' + encodeURIComponent(cursor) : ''), { credentials: 'same-origin', method: 'GET' });
  return { status: response.status, data: response.status === 200 ? await response.json() : null };
}

export async function membersBrowserAcceptance({ page, output, report, base, credentials }) {
  const fixture = validateMembersFixture(credentials.members_page);
  const origin = new URL(base).origin;
  const usersURL = url => url.origin === origin && url.pathname === '/console/v1/users';
  const memberResponse = response => usersURL(new URL(response.url())) && response.request().method() === 'GET';
  let businessWrites = 0, foreignRequests = 0, english = false;
  let releasePending, pendingHandler;
  report.members_checks = [];
  report.members_screenshots = [];
  function passed(name) {
    assert(MEMBERS_CHECKS.includes(name) && !report.members_checks.some(check => check.name === name), 'Unknown or duplicate members check');
    report.members_checks.push({ name, passed: true });
    console.log(`PASS members ${name}`);
  }
  // A fail-closed guard covers this module, including unexpected automatic writes.
  const businessWrite = request => !['GET', 'HEAD'].includes(request.method()) && !(request.method() === 'POST' && ['/console/v1/auth/login', '/console/v1/auth/logout'].includes(new URL(request.url()).pathname));
  const observeRequest = request => {
    if (new URL(request.url()).origin !== origin) foreignRequests++;
    if (businessWrite(request)) businessWrites++;
  };
  page.on('request', observeRequest);
  const readOnly = async route => {
    const request = route.request();
    if (new URL(request.url()).origin !== origin || businessWrite(request)) { await route.abort(); return; }
    await route.continue();
  };
  await page.route('**/*', readOnly);
  const label = (zh, en) => english ? en : zh;
  const next = () => page.locator('.members-pagination').getByRole('button', { name: label('下一页', 'Next'), exact: true });
  const previous = () => page.locator('.members-pagination').getByRole('button', { name: label('上一页', 'Previous'), exact: true });
  async function body(response) {
    assert(response.status() === 200, 'Real member read did not return 200');
    return validateMembersResponse(await response.json());
  }
  async function observe(action) {
    const response = page.waitForResponse(memberResponse);
    await action();
    return body(await response);
  }
  async function read(cursor = null) {
    const result = await page.evaluate(readMembersInBrowser, cursor);
    assert(result.status === 200, 'Real inventory read denied');
    return validateMembersResponse(result.data);
  }
  async function shown(number, data) {
    await page.waitForFunction(({ number, count }) => {
      const note = document.querySelector('.members-pagination p')?.textContent || '';
      return (note.includes(`第 ${number} 页`) || note.includes(`Page ${number} ·`)) && document.querySelectorAll('.member-row').length === count && !document.querySelector('.members-progress');
    }, { number, count: data.items.length });
    const emails = await page.locator('.member-row .member-name p').allTextContents();
    assert(emails.length === data.items.length && emails.every((email, i) => email.trim() === data.items[i].email), 'Visible member rows differ from the real response');
  }
  async function move(direction, number) {
    const data = await observe(async () => {
      await (direction === 'next' ? next() : previous()).focus();
      await page.keyboard.press('Enter');
    });
    await shown(number, data);
    await page.waitForFunction(() => document.activeElement === document.querySelector('.page-heading h1'));
    // Includes the long synthetic name/email whichever tied-timestamp page owns it.
    await geometry();
    return data;
  }
  async function refresh() {
    const data = await observe(() => page.getByRole('button', { name: label('刷新', 'Refresh'), exact: true }).click());
    await shown(1, data);
    return data;
  }
  async function image(name, fullPage = false) {
    assert(MEMBERS_SCREENSHOTS.includes(name) && !report.members_screenshots.includes(name), 'Invalid members screenshot');
    assert(await page.locator('.member-row').count() > 0 && await page.locator('input[type="password"]').count() === 0, 'No screenshots of sign-in or empty authorization states');
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
    await page.screenshot({ path: path.join(output, name), fullPage, animations: 'disabled' });
    report.members_screenshots.push(name);
  }
  async function geometry() {
    await page.locator('.members-pagination').scrollIntoViewIfNeeded();
    const result = await page.locator('.members-pagination').evaluate(nav => ({
      width: innerWidth, scroll: document.documentElement.scrollWidth,
      buttons: [...nav.querySelectorAll('button')].map(button => {
        const r = button.getBoundingClientRect();
        return r.width >= 44 && r.height >= 44 && r.left >= -1 && r.right <= innerWidth + 1;
      }),
    }));
    assert(result.scroll <= result.width && result.buttons.length === 2 && result.buttons.every(Boolean), 'Members navigation must fit with real 44px targets');
  }
  async function preferences(toEnglish, dark) {
    await page.getByRole('button', { name: english ? 'Language & appearance' : '语言与外观', exact: true }).click();
    await page.getByRole('combobox', { name: english ? 'Language' : '界面语言', exact: true }).click();
    await page.getByRole('option', { name: toEnglish ? 'English' : '简体中文', exact: true }).click();
    english = toEnglish;
    await page.getByRole('combobox', { name: english ? 'Appearance' : '外观', exact: true }).click();
    await page.getByRole('option', { name: english ? (dark ? 'Dark' : 'Light') : (dark ? '深色' : '浅色'), exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: english ? 'Done' : '完成', exact: true }).click();
    await page.getByRole('dialog').waitFor({ state: 'hidden' });
    await page.waitForFunction(() => !history.state?.asterOverlay);
  }
  async function holdNext() {
    let entered;
    const arrived = new Promise(resolve => { entered = resolve; });
    const released = new Promise(resolve => { releasePending = resolve; });
    pendingHandler = async route => {
      if (route.request().method() !== 'GET') { await route.fallback(); return; }
      entered();
      await released;
      // Logout may abort the owned browser request before continuation.
      try { await route.fallback(); } catch { /* Caller verifies logout and no rows. */ }
    };
    await page.route(usersURL, pendingHandler);
    await next().click();
    let timer;
    try { await Promise.race([arrived, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Member read was not intercepted')), 15000); })]); }
    finally { clearTimeout(timer); }
  }
  async function release() {
    releasePending?.(); releasePending = undefined;
    if (pendingHandler) await page.unroute(usersURL, pendingHandler);
    pendingHandler = undefined;
  }
  try {
    // The preceding network matrix ends in English/dark. Use visible controls.
    english = true;
    await preferences(false, false);
    const inventory = [], pages = [];
    let cursor = null;
    do {
      assert(pages.length < 3, 'Inventory must terminate at exactly 205 members');
      const data = await read(cursor); pages.push(data); inventory.push(...data.items.map(item => item.id)); cursor = data.next_cursor;
    } while (cursor);
    assert(inventory.length === 205 && inventory.every((id, i) => id === fixture.ids[i]), 'Real MySQL inventory must match private fixture order');
    passed('actual_mysql_inventory_205');
    await page.setViewportSize({ width: 1440, height: 1000 });
    let data = await observe(() => page.goto(new URL('#/users', base).href, { waitUntil: 'networkidle' }));
    await shown(1, data); await geometry(); await image('members-desktop-first.png');
    const desktop = [...data.items.map(item => item.id)];
    data = await move('next', 2); desktop.push(...data.items.map(item => item.id));
    data = await move('next', 3); desktop.push(...data.items.map(item => item.id));
    assert(desktop.length === 205 && desktop.every((id, i) => id === fixture.ids[i]) && await next().isDisabled(), 'Desktop must reach every real member once');
    await image('members-desktop-last.png', true); passed('desktop_complete_pagination'); passed('keyboard_pagination_focus');
    data = await move('previous', 2);
    assert(data.items.every((item, i) => item.id === fixture.ids[100 + i]), 'Previous must restore the real second page'); passed('previous_page');
    const me = page.waitForResponse(response => new URL(response.url()).pathname === '/console/v1/auth/me' && response.request().method() === 'GET');
    // Trigger the browser's real production focus-refresh listener, not a store assignment.
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    const refreshed = await me;
    assert(refreshed.status() === 200, 'Same-identity refresh must reach the real session handler');
    await refreshed.finished();
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await shown(2, data); passed('same_identity_refresh_keeps_page');
    await refresh(); assert(await previous().isDisabled(), 'Refresh must clear previous-page history'); passed('refresh_returns_first');
    data = await move('next', 2);
    const failOnce = async route => {
      if (route.request().method() === 'GET') await route.abort('failed');
      else await route.fallback();
    };
    await page.route(usersURL, failOnce, { times: 1 });
    await next().click(); await page.locator('.members-retry').waitFor(); await shown(2, data);
    assert(await next().isDisabled(), 'Unknown next page cannot be advanced'); passed('failed_next_keeps_rows');
    data = await observe(() => page.locator('.members-retry').getByRole('button').click()); await shown(3, data);
    assert(data.items.length === 5, 'Retry must use the failed third-page position'); passed('retry_requested_page');
    await refresh();
    await holdNext(); await page.locator('.members-progress').waitFor();
    assert(await page.locator('.member-row').count() === 100 && await next().isDisabled() && await previous().isDisabled(), 'Loading retains committed rows and disables navigation');
    const delayed = page.waitForResponse(memberResponse); await release(); data = await body(await delayed); await shown(2, data); passed('loading_keeps_rows');
    await page.setViewportSize({ width: 390, height: 844 });
    data = await refresh(); await geometry(); await image('members-mobile-first.png');
    const mobile = [...data.items.map(item => item.id)];
    data = await move('next', 2); mobile.push(...data.items.map(item => item.id));
    data = await move('next', 3); mobile.push(...data.items.map(item => item.id));
    assert(mobile.length === 205 && mobile.every((id, i) => id === fixture.ids[i]), 'Mobile must reach every real member once');
    await geometry(); await image('members-mobile-last.png', true); passed('mobile_complete_pagination');
    await page.setViewportSize({ width: 320, height: 844 }); await geometry(); passed('mobile_320_layout');
    assert(await page.locator('select').count() === 0, 'No native select in members UI'); passed('custom_controls');
    await page.setViewportSize({ width: 1440, height: 1000 }); await preferences(true, true); await shown(3, data); await geometry(); await image('members-desktop-english-dark.png', true);
    await page.setViewportSize({ width: 390, height: 844 }); await geometry(); await image('members-mobile-english-dark.png', true); passed('english_dark_layout');
    await page.setViewportSize({ width: 1440, height: 1000 }); await refresh(); await holdNext();
    const loggedOut = page.waitForResponse(response => new URL(response.url()).pathname === '/console/v1/auth/logout' && response.request().method() === 'POST');
    await page.locator('.aw-logout-trigger').click(); assert((await loggedOut).status() === 204, 'Actual logout must revoke the session');
    await page.locator('input[type="password"]').waitFor(); await release();
    assert(await page.locator('.member-row').count() === 0 && await page.locator('.members-pagination').count() === 0, 'Logout must clear rows and cancel page navigation'); passed('logout_cancels_pending_read');
    const status = () => page.evaluate(async cursor => (await fetch('/console/v1/users?cursor=' + encodeURIComponent(cursor), { method: 'GET', credentials: 'same-origin' })).status, pages[0].next_cursor);
    assert(await status() === 401, 'An anonymous cursor read must be denied by the real backend'); passed('anonymous_read_denied');
    await page.getByLabel('Email', { exact: true }).fill(fixture.viewer_email); await page.getByLabel('Password', { exact: true }).fill(fixture.viewer_password);
    await page.getByRole('button', { name: 'Sign in', exact: true }).click(); await page.locator('.aw-command-rail').waitFor();
    assert(await status() === 403, 'A real viewer session cannot read any members page');
    assert(await page.locator('.member-row').count() === 0 && await page.locator('.members-pagination').count() === 0 && await page.locator('.aw-rail-nav a[href="#/users"]').count() === 0, 'Viewer must not inherit administrator rows or navigation'); passed('viewer_read_denied');
    assert(businessWrites === 0 && foreignRequests === 0, 'Read-only members acceptance must never perform business writes or external requests'); passed('no_business_writes');
    assert(report.members_screenshots.length === MEMBERS_SCREENSHOTS.length, 'Every actual members screenshot is required'); passed('six_actual_screenshots');
    assert(report.members_checks.length === MEMBERS_CHECKS.length, 'Every members check must actually execute');
    report.members_acceptance = { schema: 1, passed: true, real_mysql: true, read_only: true, total: 205, pages: 3, anonymous_status: 401, viewer_status: 403, business_writes: 0, foreign_requests: 0 };
  } finally {
    await release();
    await page.unroute('**/*', readOnly);
    page.off('request', observeRequest);
  }
}
