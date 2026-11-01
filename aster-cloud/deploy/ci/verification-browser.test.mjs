import assert from 'node:assert/strict';
import test from 'node:test';
import {CHECKS,SHOTS,validateVerificationBrowser} from './verification-browser-contract.mjs';
const report=()=>({schema:1,passed:true,strict_tls:true,checks:[...CHECKS],screenshots:[...SHOTS],business_write_attempts:0,forbidden_node_reads:0,foreign_requests:0,page_errors:0});
const fixture=()=>({schema:1,passed:true,real_mysql:true,minimum_sql_identity:true,business_and_identity_records_unchanged:true,historical_audit_prefix_unchanged:true,business_write_attempts:0,forbidden_node_reads:0,login_count:1,logout_count:1,process_activation:false,source_host_migration:false,kvm_ready:false});
test('requires complete readonly browser and durable SQL proof',()=>assert(validateVerificationBrowser(report(),fixture())));
test('missing, coerced, partial or extra proof is rejected',()=>{
 for(const kind of ['report','fixture'])for(const key of Object.keys(kind==='report'?report():fixture()))for(const bad of [undefined,null,'true','false']){
  const r=report(), f=fixture();(kind==='report'?r:f)[key]=bad;assert.throws(()=>validateVerificationBrowser(r,f));
 }
 for(const key of ['checks','screenshots'])for(let i=0;i<report()[key].length;i++){
  const r=report();r[key].splice(i,1);assert.throws(()=>validateVerificationBrowser(r,fixture()));
 }
 const extra=report();extra.cookie='private';assert.throws(()=>validateVerificationBrowser(extra,fixture()));
 const f=fixture();f.password='private';assert.throws(()=>validateVerificationBrowser(report(),f));
});
test('any write, live node query, missing login or overclaimed activation is rejected',()=>{
 for(const key of ['business_write_attempts','forbidden_node_reads','foreign_requests','page_errors']){const r=report();r[key]=1;assert.throws(()=>validateVerificationBrowser(r,fixture()));}
 for(const key of ['process_activation','source_host_migration','kvm_ready']){const f=fixture();f[key]=true;assert.throws(()=>validateVerificationBrowser(report(),f));}
 for(const key of ['login_count','logout_count']){const f=fixture();f[key]=0;assert.throws(()=>validateVerificationBrowser(report(),f));}
});
