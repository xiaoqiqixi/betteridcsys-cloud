// Pure parser/guard tests only: never a substitute for the real MySQL browser job.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';
import { MEMBERS_CHECKS, MEMBERS_SCREENSHOTS, validateMembersFixture, validateMembersResponse, readMembersInBrowser } from './members-browser.mjs';
const ids = Array.from({ length: 205 }, (_, index) => (index + 1).toString(16).padStart(32, '0'));
const fixture = { count: 205, ids, viewer_email: 'viewer@example.invalid', viewer_password: 'synthetic-private-fixture-only' };
const items = ids.slice(0, 100).map((id, index) => ({ id, email: `member-${index}@example.invalid` }));
const first = { items, limit: 100, next_cursor: 'u1.test', truncated_possible: true };
test('fixed evidence counts stay disjoint and bounded', () => {
  assert.equal(MEMBERS_CHECKS.length, 18); assert.equal(new Set(MEMBERS_CHECKS).size, 18);
  assert.equal(MEMBERS_SCREENSHOTS.length, 6); assert.equal(new Set(MEMBERS_SCREENSHOTS).size, 6);
  assert(MEMBERS_SCREENSHOTS.every(name => /^members-[a-z-]+\.png$/.test(name)));
});
test('205 unique private identities and reserved-domain viewer are required', () => {
  assert.equal(validateMembersFixture(fixture), fixture);
  for (const bad of [null, [], { ...fixture, count: 204 }, { ...fixture, ids: ids.slice(1) }, { ...fixture, ids: [...ids.slice(0, -1), ids[0]] }, { ...fixture, viewer_email: 'viewer@real.example.com' }, { ...fixture, viewer_password: 'short' }]) {
    assert.throws(() => validateMembersFixture(bad));
  }
});
test('real page guard requires exact limit, unique ids and consistent next', () => {
  assert.equal(validateMembersResponse(first), first);
  for (const bad of [null, [], { ...first, limit: '100' }, { ...first, items: [...items, items[0]] }, { ...first, items: Array(100).fill(items[0]) }, { ...first, next_cursor: null }, { ...first, next_cursor: 'https://foreign.invalid' }, { ...first, next_cursor: 'u1.' + 'a'.repeat(512) }, { ...first, truncated_possible: 1 }, { ...first, next_cursor: undefined }, { ...first, items: [{ id: ids[0], email: 'customer@real.example.com' }] }]) {
    assert.throws(() => validateMembersResponse(bad));
  }
});
test('final five real members need null continuation, not truncation', () => {
  const last = { items: items.slice(0, 5), limit: 100, next_cursor: null, truncated_possible: false };
  assert.equal(validateMembersResponse(last), last);
  assert.throws(() => validateMembersResponse({ ...last, next_cursor: 'u1.cursor', truncated_possible: true }));
  assert.throws(() => validateMembersResponse({ ...last, truncated_possible: 0 }));
});
test('long reserved-domain synthetic email survives guard; customer domains do not', () => {
  const email = 'l'.repeat(63) + '@' + 'd'.repeat(63) + '.example.invalid';
  assert.doesNotThrow(() => validateMembersResponse({ items: [{ id: ids[0], email }], limit: 100, next_cursor: null, truncated_possible: false }));
  for (const email of ['a@example.invalid.evil.test', 'a@@example.invalid', 'a b@example.invalid']) {
    assert.throws(() => validateMembersResponse({ items: [{ id: ids[0], email }], limit: 100, next_cursor: null, truncated_possible: false }));
  }
});

// Execute the exact serialized callback used by page.evaluate in another realm.
// These are real native Response objects, not Playwright-style status() objects.
async function nativeRead(response, cursor = null) {
  const requests = [];
  const result = await runInNewContext('(' + readMembersInBrowser.toString() + ')(cursor)', {
    cursor,
    fetch: async (url, options) => { requests.push({ url, options }); return response; },
  });
  assert.equal(requests.length, 1);
  assert.equal(requests[0].options.method, 'GET');
  assert.equal(requests[0].options.credentials, 'same-origin');
  assert.equal(requests[0].url, '/console/v1/users' + (cursor ? '?cursor=' + encodeURIComponent(cursor) : ''));
  return structuredClone(result);
}
test('browser-native Fetch status 200 parses JSON and returns only status/data', async () => {
  const data = { items: [], limit: 100, next_cursor: null, truncated_possible: false };
  const result = await nativeRead(new Response(JSON.stringify(data), { status: 200 }), 'u1.test');
  assert.deepEqual(result, { status: 200, data });
  assert.deepEqual(Object.keys(result).sort(), ['data', 'status']);
});
test('browser-native 401 keeps its numeric status and never parses rejected response bytes', async () => {
  assert.deepEqual(await nativeRead(new Response('not JSON; must not be returned', { status: 401 })), { status: 401, data: null });
});
test('browser-native 403 is not a successful data page; invalid 200 JSON still rejects', async () => {
  assert.deepEqual(await nativeRead(new Response('forbidden', { status: 403 })), { status: 403, data: null });
  await assert.rejects(nativeRead(new Response('invalid JSON', { status: 200 })));
});
