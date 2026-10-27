// Read-only command-rail acceptance. Export/report/screenshot sidebar names are
// legacy compatibility identifiers, not evidence that a sidebar still exists.
// Read-only shell acceptance. No application state, DOM, API response or CSS is
// replaced here: only real viewport, scroll, focus and visible navigation input.
import assert from 'node:assert/strict';
import path from 'node:path';

export const SIDEBAR_SCREENSHOTS = Object.freeze([
  'sidebar-320-top.png', 'sidebar-320-drawer.png',
  'sidebar-390-bottom.png', 'sidebar-390-drawer.png',
  'sidebar-768-drawer.png', 'sidebar-1024-drawer.png',
  'sidebar-1025-middle.png', 'sidebar-1440-bottom.png',
  'sidebar-1440-short-nav-bottom.png', 'sidebar-1025-short-nav-bottom.png',
  'sidebar-zoom-720-drawer.png', 'sidebar-zoom-512-drawer.png',
]);

const tolerance = 2;
const settle = page => page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
async function scrollPage(page, position) {
  await page.evaluate(position => {
    const max = document.documentElement.scrollHeight - innerHeight;
    window.scrollTo({ top: position === 'middle' ? max / 2 : position === 'bottom' ? max : 0, behavior: 'instant' });
  }, position);
  await settle(page);
}

// Exported for a before-only probe against the unmodified bundle. This function
// does not mark a run passed; the mandatory assertions below remain fail-fast.
export async function sidebarLayout(page) {
  return page.evaluate(() => {
    const rect = el => {
      if (!el) return null;
      const b = el.getBoundingClientRect(), s = getComputedStyle(el);
      return { left: b.left, right: b.right, top: b.top, bottom: b.bottom,
        width: b.width, height: b.height, display: s.display, position: s.position,
        client_height: el.clientHeight, scroll_height: el.scrollHeight,
        client_width: el.clientWidth, scroll_width: el.scrollWidth,
        scroll_top: el.scrollTop, scroll_left: el.scrollLeft,
        overflow_y: s.overflowY, overflow_x: s.overflowX };
    };
    const visible = el => !!el && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
    return { shell_contract: 'command-rail-v1', width: innerWidth, height: innerHeight, scroll_y: scrollY,
      document_height: document.documentElement.scrollHeight, document_width: document.documentElement.scrollWidth,
      legacy_sidebar_present: !!document.querySelector('.sidebar'),
      navigation_visible: visible(document.querySelector('.aw-rail-nav')),
      menu_visible: visible(document.querySelector('.aw-menu-trigger')),
      shell: rect(document.querySelector('.console-shell')), rail: rect(document.querySelector('.aw-command-rail')),
      navigation: rect(document.querySelector('.aw-rail-nav')),
      brand: rect(document.querySelector('.aw-brand')), account: rect(document.querySelector('.aw-account-pill')),
      utilities: rect(document.querySelector('.aw-rail-right')),
      workspace: rect(document.querySelector('.console-workspace')), main: rect(document.querySelector('#main-content')),
      footer: rect(document.querySelector('.workspace-footer')) };
  });
}

async function hitAndFocus(page, locator, bounds, onFailure) {
  await locator.focus();
  await settle(page);
  const result = await locator.evaluate((el, bounds) => {
    const r = el.getBoundingClientRect(), clip = bounds ? document.querySelector(bounds)?.getBoundingClientRect() : null;
    const x = r.left + r.width / 2, y = r.top + r.height / 2;
    const top = document.elementFromPoint(x, y);
    const checks = { focused: document.activeElement === el, visible: r.width > 0 && r.height > 0,
      target_size: r.width >= 44 && r.height >= 44,
      in_viewport: r.left >= -1 && r.right <= innerWidth + 1 && r.top >= -1 && r.bottom <= innerHeight + 1,
      in_clip: !clip || r.top >= clip.top - 1 && r.bottom <= clip.bottom + 1 && r.left >= clip.left - 1 && r.right <= clip.right + 1,
      hit: !!top && (top === el || el.contains(top)) };
    const box = rect => rect ? Object.fromEntries(['left','top','right','bottom'].map(key => [key,Math.round(rect[key] * 100) / 100])) : null;
    const region = bounds ? document.querySelector(bounds) : null;
    return { checks, width: innerWidth, height: innerHeight, tag: el.tagName,
      link_index: [...document.querySelectorAll('.aw-rail-nav a')].indexOf(el),
      logout: el === document.querySelector('.aw-logout-trigger'), bounds: bounds || '',
      target_rect: box(r), clip_rect: box(clip), clip_scroll_top: region?.scrollTop ?? null, clip_scroll_left: region?.scrollLeft ?? null };
  }, bounds);
  if (!Object.values(result.checks).every(Boolean)) {
    onFailure?.(result);
    assert.fail(`Shell control is clipped, obscured or unreachable: ${JSON.stringify(result)}`);
  }
  return result;
}

export async function sidebarBrowserAcceptance({ page, output, report, capture = true, english = false }) {
  const originalURL = page.url(), originalViewport = page.viewportSize();
  const writeCount = () => report.requests.filter(r => r.method === 'POST').length;
  const writes = writeCount(), ingressWrites = report.public_ingress_write_attempts.length,
    publicWrites = report.public_ip_write_attempts.length;
  let completed = false;
  report.sidebar_checks ??= [];
  report.sidebar_screenshots ??= [];
  function passed(name, evidence = {}) {
    report.sidebar_checks.push({ name, shell_contract: 'command-rail-v1', mode: english ? 'english-dark' : 'chinese-light', ...evidence });
    console.log(`PASS command-rail ${name}`);
  }
  async function image(name) {
    if (!capture) return;
    assert(SIDEBAR_SCREENSHOTS.includes(name));
    assert(!report.sidebar_screenshots.includes(name), 'Sidebar evidence names must be unique');
    assert.equal(await page.locator('input[type="password"]').count(), 0);
    await page.screenshot({ path: path.join(output, name), fullPage: false, animations: 'disabled' });
    report.sidebar_screenshots.push(name);
  }
  async function size(width, height) {
    await page.setViewportSize({ width, height });
    await settle(page);
  }
  async function closed({ menuFocus = true } = {}) {
    await page.getByRole('dialog').waitFor({ state: 'hidden' });
    await page.waitForFunction(() => !history.state?.asterOverlay && !document.querySelector('#app')?.inert && document.body.style.overflow !== 'hidden');
    if (menuFocus) assert.equal(await page.locator('.aw-menu-trigger').evaluate(el => document.activeElement === el), true, 'Closing navigation restores its visible menu trigger');
  }
  async function geometry(width, position) {
    await scrollPage(page, position);
    const m = await sidebarLayout(page);
    assert.equal(m.width, width);
    assert(m.document_height - m.height >= 250, 'Use the real long business page, not a DOM spacer or a viewport-only page');
    if (position !== 'top') assert(m.scroll_y > 0, 'The long-page scroll must actually happen');
    assert(m.document_width <= m.width, 'Shell must not create document horizontal scrolling');
    assert(m.main && m.workspace && m.rail && m.footer && m.brand && m.utilities);
    assert.equal(m.legacy_sidebar_present, false, 'There must be no old sidebar beside the new rail');
    assert(Math.abs(m.workspace.left) <= tolerance && Math.abs(m.main.left) <= tolerance, 'Main workspace keeps the full viewport width');
    assert(m.main.right <= m.workspace.right + tolerance && m.workspace.right <= m.width + tolerance);
    assert.equal(m.rail.position, 'sticky');
    assert(Math.abs(m.rail.top) <= tolerance, 'The actual rail remains reachable at the middle/end of a long page');
    assert(Math.abs(m.rail.height - 52) <= tolerance, 'There is one real 52px command rail, not a duplicate topbar');
    assert(m.rail.left >= -tolerance && m.rail.right <= m.width + tolerance);
    if (position === 'top') assert(m.main.top >= m.rail.bottom - tolerance, 'At the document top the rail participates in normal flow');
    assert(m.brand.height > 0 && m.brand.width > 0 && m.brand.left >= m.rail.left - tolerance);
    assert(m.utilities.right <= m.rail.right + tolerance);
    if (width <= 1024) {
      assert.equal(m.navigation_visible, false);
      assert.equal(m.menu_visible, true);
      assert(m.brand.right <= m.utilities.left + tolerance, 'Compact brand/context and utilities cannot overlap');
    } else {
      assert.equal(m.navigation_visible, true);
      assert.equal(m.menu_visible, false);
      assert(m.navigation && m.account && m.account.height > 0 && m.account.width > 0);
      assert(m.navigation.left >= m.brand.right - tolerance && m.navigation.right <= m.utilities.left + tolerance, 'Navigation owns its horizontal region and never overlays account controls');
      assert(m.navigation.top >= m.rail.top - tolerance && m.navigation.bottom <= m.rail.bottom + tolerance);
      assert(['auto','scroll'].includes(m.navigation.overflow_x), 'Long navigation must scroll within its own region');
    }
    if (position === 'bottom') assert(Math.abs(m.footer.bottom - m.height) <= tolerance, 'The actual document footer must be visible at page bottom');
    passed(`${english ? 'English dark ' : ''}${width}px ${position} shell geometry`, m);
    return m;
  }
  async function drawer(name, closeBy = 'escape') {
    const menu = page.locator('.aw-menu-trigger');
    await menu.click();
    const dialog = page.getByRole('dialog');
    await dialog.waitFor();
    await settle(page);
    const evidence = await dialog.evaluate(el => {
      const r = el.getBoundingClientRect(), header = el.querySelector('.overlay-header')?.getBoundingClientRect(), footer = el.querySelector('.overlay-footer')?.getBoundingClientRect();
      return { width: innerWidth, height: innerHeight, scroll_y: scrollY,
        in_viewport: r.left >= 0 && r.right <= innerWidth && r.top >= 0 && r.bottom <= innerHeight,
        header_footer_visible: !!header && !!footer && header.top >= r.top && footer.bottom <= r.bottom + 1,
        no_horizontal_scroll: el.scrollWidth <= el.clientWidth + 1,
        focus_inside: el.contains(document.activeElement), background_inert: document.querySelector('#app')?.inert === true,
        background_locked: document.body.style.overflow === 'hidden' };
    });
    for (const key of ['in_viewport','header_footer_visible','no_horizontal_scroll','focus_inside','background_inert','background_locked']) assert.equal(evidence[key], true, `${name}: ${key}`);
    await dialog.locator('.overlay-header button').focus();
    await page.keyboard.press('Shift+Tab');
    assert.equal(await dialog.evaluate(el => el.contains(document.activeElement) && document.activeElement?.closest('.overlay-footer') !== null), true, 'Reverse tab wraps to the real navigation footer, not the background');
    await page.keyboard.press('Tab');
    assert.equal(await dialog.locator('.overlay-header button').evaluate(el => document.activeElement === el), true);
    if (evidence.height <= 450) {
      const body = dialog.locator('.overlay-body');
      const before = await body.evaluate(el => ({ height: el.clientHeight, scroll_height: el.scrollHeight, scroll_top: el.scrollTop }));
      assert(before.scroll_height > before.height + 1, 'The real six-link compact drawer must independently overflow at a short/zoom-equivalent viewport');
      await body.hover();
      await page.mouse.wheel(0, 10000);
      await page.waitForFunction(() => { const el = document.querySelector('[role="dialog"] .overlay-body'); return !!el && el.scrollTop >= el.scrollHeight - el.clientHeight - 2; });
      assert(Math.abs(await page.evaluate(() => scrollY) - evidence.scroll_y) <= 1, 'Scrolling the short drawer navigation may not move business content');
      evidence.short_navigation_scroll = { before, after: await body.evaluate(el => ({ scroll_top: el.scrollTop, client_height: el.clientHeight, scroll_height: el.scrollHeight })) };
    }
    await page.mouse.move(2, Math.round(evidence.height / 2));
    await page.mouse.wheel(0, 320);
    await settle(page);
    assert(Math.abs(await page.evaluate(() => scrollY) - evidence.scroll_y) <= 1, 'Drawer must lock background scrolling');
    await image(name);
    if (closeBy === 'back') await page.goBack();
    else if (closeBy === 'backdrop') await page.mouse.click(2, Math.round(evidence.height / 2));
    else await page.keyboard.press('Escape');
    await closed();
    passed(`${name} focus trap, background lock and ${closeBy} close`, evidence);
  }
  async function shortDesktop(width, name) {
    await size(width, 360);
    await geometry(width, 'middle');
    const before = await sidebarLayout(page);
    assert(before.rail.height <= 56 && before.navigation.client_height >= 44, 'Short desktop retains the real 44px navigation targets in one compact rail');
    const nav = page.locator('.aw-rail-nav'), box = await nav.boundingBox();
    assert(box && box.height >= 44);
    const max = Math.max(0, before.navigation.scroll_width - before.navigation.client_width);
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.wheel(10000, 0);
    await settle(page);
    if (max > tolerance) await page.waitForFunction(() => { const el = document.querySelector('.aw-rail-nav'); return !!el && el.scrollLeft >= el.scrollWidth - el.clientWidth - 2; });
    const after = await sidebarLayout(page);
    assert(Math.abs(after.scroll_y - before.scroll_y) <= 1, 'Horizontal rail scrolling must not move the business document');
    assert(Math.abs(after.brand.left - before.brand.left) <= 1 && Math.abs(after.utilities.right - before.utilities.right) <= 1, 'Brand/account stay outside the independently scrolling nav');
    await hitAndFocus(page, page.locator('.aw-logout-trigger'), '.aw-command-rail', evidence => { report.sidebar_control_failure = evidence; });
    await image(name);
    const keyboardDocumentY = await page.evaluate(() => scrollY), keyboardTargets = [];
    await page.locator('.aw-brand').focus();
    await settle(page);
    assert(Math.abs(await page.evaluate(() => scrollY) - keyboardDocumentY) <= 1, 'Focusing the rail brand must not move the business document');
    const links = page.locator('.aw-rail-nav a');
    const count = await links.count();
    assert.equal(count, 6, 'Use all six signed-in administrator destinations, never a reduced test menu');
    for (let i = 0; i < count; i++) {
      await page.keyboard.press('Tab');
      const link = links.nth(i);
      const focused = await link.evaluate(el => document.activeElement === el);
      if (!focused) {
        const identity = await page.evaluate(() => {
          const active = document.activeElement;
          return { tag: active?.tagName || '', navigation: active === document.querySelector('.aw-rail-nav'),
            rail: active === document.querySelector('.aw-command-rail'), body: active === document.body,
            main: active === document.querySelector('#main-content'), skip: active === document.querySelector('.skip-link'),
            brand: active === document.querySelector('.aw-brand'), logout: active === document.querySelector('.aw-logout-trigger'),
            link_index: [...document.querySelectorAll('.aw-rail-nav a')].indexOf(active) };
        });
        report.sidebar_focus_failure = { width, expected_link_index: i, ...identity };
        assert.fail(`Tab must follow every real rail link: expected=${i}, actual=${JSON.stringify(identity)}`);
      }
      const target = await hitAndFocus(page, link, '.aw-rail-nav', evidence => { report.sidebar_control_failure = evidence; });
      const documentY = await page.evaluate(() => scrollY);
      assert(Math.abs(documentY - keyboardDocumentY) <= 1, 'Tabbing each rail link must not move the business document');
      keyboardTargets.push({ ...target, document_scroll_y: documentY });
    }
    // The new single rail puts appearance before logout. Traverse it for real;
    // keep the six-link + logout legacy seven-target receipt independently.
    await page.keyboard.press('Tab');
    assert.equal(await page.locator('.aw-pref-trigger').evaluate(el => document.activeElement === el), true);
    const preferencesTarget = await hitAndFocus(page, page.locator('.aw-pref-trigger'), '.aw-command-rail', evidence => { report.sidebar_control_failure = evidence; });
    await page.keyboard.press('Tab');
    assert.equal(await page.locator('.aw-logout-trigger').evaluate(el => document.activeElement === el), true, 'Tab reaches sign-out without activating it');
    const accountTarget = await hitAndFocus(page, page.locator('.aw-logout-trigger'), '.aw-command-rail', evidence => { report.sidebar_control_failure = evidence; });
    const accountDocumentY = await page.evaluate(() => scrollY);
    assert(Math.abs(accountDocumentY - keyboardDocumentY) <= 1, 'Tabbing utilities must not move the business document');
    keyboardTargets.push({ ...accountTarget, document_scroll_y: accountDocumentY });
    // This name remains a report-schema compatibility identifier checked by the
    // unchanged outer gate. Evidence explicitly identifies command-rail-v1.
    passed(`${width}px 360px short-screen independent scroll and keyboard access`, { links: count, before, after,
      horizontal_scroll_required: max > tolerance, keyboard_document_scroll_y: keyboardDocumentY,
      keyboard_targets: keyboardTargets, preferences_keyboard_target: preferencesTarget });
  }

  try {
    await size(1440, 900);
    await scrollPage(page, 'top');
    assert.equal(await page.locator('.aw-command-rail').count(), 1);
    assert.equal(await page.locator('.topbar,.sidebar').count(), 0);
    assert.equal(await page.locator('.aw-rail-nav button').count(), 0);
    const destinations = await page.locator('.aw-rail-nav a').evaluateAll(links => links.map(el => el.getAttribute('href')));
    assert.deepEqual(destinations, ['#/instances','#/nodes','#/networks/overlays','#/operations','#/audit','#/users']);
    assert.equal(await page.locator('.aw-menu-trigger').getAttribute('aria-haspopup'), 'dialog');
    assert.equal(await page.locator('.aw-menu-trigger').getAttribute('aria-expanded'), 'false');
    passed('single command rail has six real semantic route anchors and controlled compact disclosure', { destinations });
    const matrix = english ? [[1024,768],[1025,768]] : [[320,740],[390,844],[768,900],[1024,768],[1025,768],[1440,1000]];
    for (const [width,height] of matrix) {
      await size(width,height);
      for (const position of ['top','middle','bottom']) {
        await geometry(width,position);
        if (!english && width === 320 && position === 'top') await image('sidebar-320-top.png');
        if (!english && width === 390 && position === 'bottom') await image('sidebar-390-bottom.png');
        if (!english && width === 1025 && position === 'middle') await image('sidebar-1025-middle.png');
        if (!english && width === 1440 && position === 'bottom') await image('sidebar-1440-bottom.png');
      }
      if (width <= 1024) await drawer(`sidebar-${width}-drawer.png`, width === 390 ? 'backdrop' : width === 768 ? 'back' : 'escape');
    }
    for (const width of [1440,1025]) await shortDesktop(width, `sidebar-${width}-short-nav-bottom.png`);
    if (!english) {
      // Equivalent CSS viewports for 1440x900 and 1024x768 at 200% zoom. DPR
      // changes screenshot resolution only and is not used as fake zoom proof.
      for (const [width,height] of [[720,450],[512,384]]) {
        await size(width,height);
        await geometry(width,'bottom');
        await drawer(`sidebar-zoom-${width}-drawer.png`);
        passed(`200 percent equivalent ${width}x${height} CSS viewport reflow`);
      }
    }
    await size(1025,768);
    await scrollPage(page,'middle');
    await page.locator('.aw-rail-nav a').last().focus();
    await size(1024,768);
    await page.waitForFunction(() => document.activeElement === document.querySelector('.aw-menu-trigger')).catch(() => {
      throw new Error('1025 to 1024 must transfer the focused sidebar link to the visible compact menu; CSS hiding must not strand focus on body');
    });
    assert.equal(await page.getByRole('dialog').count(),0);
    assert.equal(await page.evaluate(() => document.querySelector('#app')?.inert),false);
    passed('focused desktop sidebar becomes a reachable compact menu at 1024px');
    await page.locator('.aw-menu-trigger').click();
    await page.getByRole('dialog').waitFor();
    await size(1025,768);
    await closed({ menuFocus: false });
    assert.equal(await page.locator('#main-content').evaluate(el => document.activeElement === el),true, 'Crossing to desktop must not leave focus on the now-hidden menu or removed drawer');
    passed('1024 to 1025 closes drawer, clears inert/history and focuses main');
    await size(390,844);
    await page.locator('.aw-menu-trigger').click();
    await page.getByRole('dialog').locator('.nav-links a[href="#/instances"]').click();
    await page.waitForURL(/#\/instances(?:\?|$)/);
    await closed();
    await page.goto(originalURL,{ waitUntil:'networkidle' });
    await page.locator('.network-tabs').waitFor();
    passed('visible drawer navigation closes the overlay and reaches the actual route');
    const beforeSkipURL = page.url();
    await page.locator('.skip-link').focus();
    await page.locator('.skip-link').click();
    await settle(page);
    assert.equal(page.url(),beforeSkipURL,'Skip-to-content must not replace the hash-router URL with #main-content');
    assert.equal(await page.locator('#main-content').evaluate(el => document.activeElement === el),true,'The visible skip link must really focus the main landmark');
    passed('visible skip-link click focuses main without changing the hash route or making a write', { route_unchanged: true, main_focused: true });
    assert.equal(writeCount(),writes,'Shell acceptance must not add business POSTs');
    assert.equal(report.public_ingress_write_attempts.length,ingressWrites);
    assert.equal(report.public_ip_write_attempts.length,publicWrites);
    if (capture) assert.deepEqual([...report.sidebar_screenshots].sort(),[...SIDEBAR_SCREENSHOTS].sort());
    completed = true;
  } finally {
    // Do not erase a real short-screen failure before the caller captures its
    // signed-in failure.png. Only a complete passing phase restores the viewport.
    if (completed) {
      await size(originalViewport.width,originalViewport.height);
      if (page.url() === originalURL && await page.getByRole('dialog').count() === 0) await scrollPage(page,'top');
    }
  }
}
