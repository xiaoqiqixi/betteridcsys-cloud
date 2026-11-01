import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
export const CHECKS=Object.freeze(['server_confirmed_mode','members_remain_readable','member_editors_disabled','saved_instance_readable','instance_actions_disabled','no_live_node_queries','historical_nodes_readable','desktop_mobile_geometry','english_dark_readonly','logout_revokes_session']);
export const SHOTS=Object.freeze(['verification-desktop-members.png','verification-mobile-members.png','verification-desktop-instance.png','verification-mobile-instance.png','verification-mobile-nodes.png','verification-desktop-english-dark.png','verification-mobile-english-dark.png']);
export function validateVerificationBrowser(report,fixture,output){
 assert.deepEqual(Object.keys(report).sort(),['schema','passed','strict_tls','checks','screenshots','business_write_attempts','forbidden_node_reads','foreign_requests','page_errors'].sort());
 assert.equal(report.schema,1);assert.equal(report.passed,true);assert.equal(report.strict_tls,true);
 for(const key of ['business_write_attempts','forbidden_node_reads','foreign_requests','page_errors'])assert.equal(report[key],0);
 for(const [key,expected] of [['checks',CHECKS],['screenshots',SHOTS]]){assert(Array.isArray(report[key]));assert.equal(report[key].length,expected.length);assert.deepEqual(new Set(report[key]),new Set(expected));}
 const positive=['passed','real_mysql','minimum_sql_identity','business_and_identity_records_unchanged','historical_audit_prefix_unchanged'];
 const negative=['process_activation','source_host_migration','kvm_ready'];
 assert.deepEqual(Object.keys(fixture).sort(),['schema',...positive,...negative,'business_write_attempts','forbidden_node_reads','login_count','logout_count'].sort());
 assert.equal(fixture.schema,1);
 for(const key of positive)assert.equal(fixture[key],true);
 for(const key of negative)assert.equal(fixture[key],false);
 for(const key of ['business_write_attempts','forbidden_node_reads'])assert.equal(fixture[key],0);
 for(const key of ['login_count','logout_count'])assert.equal(fixture[key],1);
 if(output){
  assert.deepEqual(new Set(fs.readdirSync(output)),new Set([...SHOTS,'report.json','fixture.json']));
  for(const name of SHOTS){const file=path.join(output,name);assert(fs.lstatSync(file).isFile()&&!fs.lstatSync(file).isSymbolicLink());assert(fs.readFileSync(file).subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])));}
 }
 return true;
}
if(process.argv[1]===new URL(import.meta.url).pathname){
 const output=process.argv[2];assert(output&&path.isAbsolute(output));
 validateVerificationBrowser(JSON.parse(fs.readFileSync(path.join(output,'report.json'))),JSON.parse(fs.readFileSync(path.join(output,'fixture.json'))),output);
 console.log('PASS: readonly management UI, minimum real SQL identity and unchanged business history; not managed migration activation.');
}
