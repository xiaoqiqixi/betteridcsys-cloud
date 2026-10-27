// TLS gate only: no login, cookie export, browser security exceptions or host CA.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const { firefox } = await import(pathToFileURL(path.join(process.env.PLAYWRIGHT_MODULE_DIR, 'playwright/index.mjs')).href);
const origin = process.env.BASE_URL;
assert.equal(origin, 'https://localhost:5447');
const mode = process.argv[2];
assert.ok(['untrusted', 'trusted'].includes(mode));
const context = await firefox.launchPersistentContext(process.env.FIREFOX_PROFILE_DIR, {
  headless: true,
  ignoreHTTPSErrors: false,
  acceptDownloads: false,
  firefoxUserPrefs: { 'security.enterprise_roots.enabled': false },
});
try {
  const page = context.pages()[0] || await context.newPage();
  if (mode === 'untrusted') {
    let rejected = false;
    try {
      await page.goto(origin, { waitUntil: 'domcontentloaded', timeout: 30000 });
    } catch (error) {
      // Transport refusal, timeout and browser launch failure are NOT TLS proof.
      rejected = /SEC_ERROR_UNKNOWN_ISSUER|SEC_ERROR_UNTRUSTED_ISSUER/.test(String(error));
    }
    assert.ok(rejected, 'The untrusted localhost CA must be rejected by the actual browser');
    await fs.writeFile(path.join(process.env.BROWSER_ARTIFACT_DIR, 'tls.json'), JSON.stringify({
      untrusted_ca_rejected: true,
      private_profile_ca_trusted: false,
      ignore_https_errors: false,
      host_trust_modified: false,
    }), { mode: 0o600 });
  } else {
    const response = await page.goto(origin, { waitUntil: 'domcontentloaded', timeout: 30000 });
    assert.equal(response?.status(), 200);
    assert.equal(new URL(page.url()).origin, origin);
    const resultPath = path.join(process.env.BROWSER_ARTIFACT_DIR, 'tls.json');
    const previous = JSON.parse(await fs.readFile(resultPath, 'utf8'));
    assert.equal(previous.untrusted_ca_rejected, true);
    await fs.writeFile(resultPath, JSON.stringify({ ...previous, private_profile_ca_trusted: true }), { mode: 0o600 });
  }
} finally {
  await context.close();
}
