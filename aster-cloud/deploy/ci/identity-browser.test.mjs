import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import {IDENTITY_CHECKS,IDENTITY_SHOTS,validateIdentityBrowserReport} from './identity-browser-contract.mjs';
const report=()=>({schema:1,passed:true,real_mysql:true,strict_tls:true,checks:[...IDENTITY_CHECKS],screenshots:[...IDENTITY_SHOTS],write_attempts:5,foreign_requests:0});
const fixture=()=>({schema:1,passed:true,real_mysql:true,independent_identity_database:true,identity_browser_writes:5,identity_committed_operations:5,conflict_rejected:true,post_commit_response_lost:true,credential_hashes_unchanged:true,resource_and_financial_node_snapshots_unchanged:true,target_revision:5,actor_revision:2,no_kvm_or_host_actions:true,pre_revocation_target_sessions_revoked:true});
test('requires complete independent identity evidence',()=>assert(validateIdentityBrowserReport(report(),fixture())));
test('every real browser check and screenshot is mandatory, not a partial passed boolean',()=>{
 for(const key of ['checks','screenshots']){
  for(let i=0;i<report()[key].length;i++){const v=report();v[key].splice(i,1);assert.throws(()=>validateIdentityBrowserReport(v,fixture()));}
  for(const bad of [['unexpected'],[report()[key][0],report()[key][0]],[],null]){const v=report();v[key]=bad;assert.throws(()=>validateIdentityBrowserReport(v,fixture()));}
 }
});
test('rejects missing/false/coerced durable database and TLS proof',()=>{
 for(const key of Object.keys(fixture())){for(const bad of [null,false,'true',undefined]){const v=fixture();v[key]=bad;assert.throws(()=>validateIdentityBrowserReport(report(),v));}}
 for(const key of ['passed','real_mysql','strict_tls','foreign_requests','write_attempts']){const v=report();v[key]='wrong';assert.throws(()=>validateIdentityBrowserReport(v,fixture()));}
});
test('does not export arbitrary secret or raw-response fields',()=>{
 for(const key of ['password','cookie','csrf','credentials','storageState','raw_response']){const v=report();v[key]='private-placeholder';assert.throws(()=>validateIdentityBrowserReport(v,fixture()));}
});
test('gate keeps the read-only members baseline and runs a second owned database',()=>{
 const source=fs.readFileSync(new URL('./network-browser.sh',import.meta.url),'utf8');
 assert(source.includes("value.get('members_unchanged') is True"));assert(source.includes("value['members_total'] == 205"));
 assert(source.includes('owned_identity_browser_fixture_test.go'));assert(source.includes('TestOwnedIdentityBrowserFixture'));assert(source.includes('identity-browser-contract.mjs'));
 const browser=fs.readFileSync(new URL('./identity-browser.mjs',import.meta.url),'utf8');
 assert(browser.includes('ignoreHTTPSErrors:false'));assert(!browser.includes('route.fulfill'));assert(!browser.includes('storageState:'));assert(!browser.includes('method:\'POST\''));
});
test('dialog evidence waits for the real opaque transition and uses its actual viewport',()=>{
 const browser=fs.readFileSync(new URL('./identity-browser.mjs',import.meta.url),'utf8');
 assert(browser.includes("getComputedStyle(e).opacity==='1'"));
 assert(browser.includes("overlay-enter-active"));assert(browser.includes("fullPage:false"));
 assert(!browser.includes('fullPage:true'));assert(IDENTITY_CHECKS.includes('settled_dialog_screenshots'));
});
