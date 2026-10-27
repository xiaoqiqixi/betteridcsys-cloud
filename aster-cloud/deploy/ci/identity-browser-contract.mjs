import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
export const IDENTITY_SHOTS = Object.freeze([
 'identity-desktop-editor.png','identity-mobile-editor-top.png','identity-mobile-editor-reason.png',
 'identity-desktop-conflict.png','identity-mobile-uncertain.png','identity-desktop-revocation.png',
 'identity-mobile-self-revocation.png','identity-desktop-english-dark.png','identity-mobile-english-dark.png','identity-mobile-create-preview.png',
]);
export const IDENTITY_CHECKS = Object.freeze([
 'real_mysql_member_detail','fresh_revision','required_reason_blocks','ordinary_change_committed',
 'input_focus_preserved','stale_revision_rejected','conflict_draft_preserved','conflict_no_second_post',
 'explicit_reload_discards_draft','unknown_intent_persisted','refresh_keeps_unknown','unknown_no_repost',
 'original_receipt_matches','reconciliation_get_only','all_target_sessions_revoked','fresh_signin_allowed',
 'nested_focus_and_inert','nested_browser_back','self_revocation_exits','self_cookie_revoked',
 'readonly_member_denied','mobile_320_and_390_geometry','english_dark_geometry','custom_controls','ten_actual_screenshots',
 'reload_clears_orphan_overlay_marker','critical_feedback_revealed','teleported_confirmation_tokens',
 'settled_dialog_screenshots',
]);
export function validateIdentityBrowserReport(report, fixture, output) {
 assert.deepEqual(Object.keys(report).sort(),['schema','passed','real_mysql','strict_tls','checks','screenshots','write_attempts','foreign_requests'].sort());
 assert.equal(report?.schema,1);assert.equal(report?.passed,true);assert.equal(report?.real_mysql,true);assert.equal(report?.strict_tls,true);
 assert.equal(report.foreign_requests,0);assert.equal(report.write_attempts,5);
 assert.deepEqual(new Set(report.checks),new Set(IDENTITY_CHECKS));assert.equal(report.checks.length,IDENTITY_CHECKS.length);
 assert.deepEqual(new Set(report.screenshots),new Set(IDENTITY_SHOTS));assert.equal(report.screenshots.length,IDENTITY_SHOTS.length);
 assert.equal(fixture?.schema,1);assert.equal(fixture.passed,true);
 for(const key of ['real_mysql','independent_identity_database','conflict_rejected','post_commit_response_lost','credential_hashes_unchanged','resource_and_financial_node_snapshots_unchanged','no_kvm_or_host_actions','pre_revocation_target_sessions_revoked'])assert.equal(fixture[key],true);
 assert.equal(fixture.identity_browser_writes,5);assert.equal(fixture.identity_committed_operations,5);assert.equal(fixture.target_revision,5);assert.equal(fixture.actor_revision,2);
 if(output){
  const expected=new Set([...IDENTITY_SHOTS,'report.json','fixture.json']);
  assert.deepEqual(new Set(fs.readdirSync(output)),expected);
  for(const name of IDENTITY_SHOTS){const file=path.join(output,name);assert(fs.lstatSync(file).isFile()&&!fs.lstatSync(file).isSymbolicLink());assert(fs.readFileSync(file).subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));}
 }
 return true;
}
if(process.argv[1]===new URL(import.meta.url).pathname){
 const output=process.argv[2];assert(output&&path.isAbsolute(output));
 validateIdentityBrowserReport(JSON.parse(fs.readFileSync(path.join(output,'report.json'))),JSON.parse(fs.readFileSync(path.join(output,'fixture.json'))),output);
 console.log('PASS: identity browser, exact actual PNG inventory, finite MySQL writes and unchanged resource history.');
}
