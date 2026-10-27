// Actual HTTPS/production handlers and a second disposable MySQL database.
// All business mutations use visible controls. Programmatic evidence reads are
// GET only. No fulfilled responses, demo success, credential changes or KVM.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {IDENTITY_SHOTS,IDENTITY_CHECKS} from './identity-browser-contract.mjs';
const base=new URL(process.env.BASE_URL);assert.equal(base.href,'https://localhost:5447/');
const output=process.env.BROWSER_ARTIFACT_DIR;assert(path.isAbsolute(output));
const credentials=JSON.parse(fs.readFileSync(process.env.BROWSER_CREDENTIALS_FILE,'utf8'));
for(const key of ['actor_id','target_id','second_id'])assert(/^[a-f0-9]{32}$/.test(credentials[key]));
for(const key of ['email','target_email'])assert(credentials[key].endsWith('@example.invalid'));
assert(typeof credentials.password==='string'&&credentials.password.length>=16);
const {firefox}=await import(pathToFileURL(path.join(process.env.PLAYWRIGHT_MODULE_DIR,'playwright/index.mjs')).href);
const report={schema:1,passed:false,real_mysql:true,strict_tls:true,checks:[],screenshots:[],write_attempts:0,foreign_requests:0};
let context,page,phase='launch',step='start',english=false;
const label=(zh,en)=>english?en:zh;
function check(name){assert(IDENTITY_CHECKS.includes(name)&&!report.checks.includes(name));report.checks.push(name);console.log(`PASS identity ${name}`);}
const dialog=()=>page.getByRole('dialog',{includeHidden:true}).filter({has:page.getByRole('heading',{name:label('编辑成员','Edit member'),exact:true,includeHidden:true})});
async function read(p,currentPage=page){return currentPage.evaluate(async p=>{const r=await fetch('/console/v1'+p,{method:'GET',credentials:'same-origin',cache:'no-store'});return{status:r.status,data:r.status===200?await r.json():null};},p);}
async function screenshot(name){
 assert(IDENTITY_SHOTS.includes(name)&&!report.screenshots.includes(name));
 // Visible layout is not enough: a Teleport can already hold focus while its
 // enter-from shade is still transparent. Capture the settled actual viewport,
 // not a full-document image extending past a fixed mobile shade.
 await page.waitForFunction(()=>{
  const shades=[...document.querySelectorAll('.overlay-shade')];
  return shades.length>0&&shades.every(e=>!['overlay-enter-active','overlay-enter-from','overlay-enter-to','overlay-leave-active'].some(c=>e.classList.contains(c))&&getComputedStyle(e).opacity==='1');
 });
 assert.equal(await page.locator('input[type=password]').evaluateAll(inputs=>inputs.some(input=>input.value!=='')),false,'Screenshots may never include entered credentials');
 assert.equal(await page.locator('.login-form').count(),0,'No login screenshots');
 await page.screenshot({path:path.join(output,name),fullPage:false,animations:'disabled'});report.screenshots.push(name);
}
async function geometry(){
 const proof=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,regions:[...document.querySelectorAll('[role=dialog],.overlay-body,.aw-op-notice')].map(e=>({width:e.clientWidth,scroll:e.scrollWidth}))}));
 assert(proof.scroll<=proof.width);assert(proof.regions.every(r=>r.scroll<=r.width+1));
 assert.equal(await page.locator('select').count(),0);
}
async function criticalFeedback(){
 await page.waitForFunction(()=>{
  const feedback=document.activeElement;
  if(!feedback?.classList.contains('identity-editor-feedback')||feedback.closest('[inert]'))return false;
  const region=feedback.closest('.overlay-body'),heading=feedback.querySelector('.aw-notice-title'),action=feedback.querySelector('button');
  if(!region||!heading||!action)return false;
  const bounds=region.getBoundingClientRect();
  return [heading,action].every(e=>{const r=e.getBoundingClientRect();return r.top>=bounds.top&&r.bottom<=bounds.bottom&&r.left>=bounds.left&&r.right<=bounds.right;});
 });
}
async function confirmationTokens(confirmation){
 const proof=await confirmation.evaluate(e=>{
  const body=e.querySelector('.aw-revoke-dialog-body'),input=e.querySelector('.aw-reason-input'),warn=e.querySelector('.aw-impact-warn');
  if(!body||!input||!warn)return false;
  const tokens=getComputedStyle(body),field=getComputedStyle(input),strip=getComputedStyle(warn);
  return !!tokens.getPropertyValue('--aw-ledger-border-strong').trim()&&!!tokens.getPropertyValue('--aw-warn-icon').trim()&&parseFloat(field.borderTopWidth)>=1&&field.borderTopStyle==='solid'&&field.backgroundColor!=='rgba(0, 0, 0, 0)'&&strip.backgroundColor!=='rgba(0, 0, 0, 0)'&&strip.borderLeftColor===strip.color;
 });
 assert.equal(proof,true,'Teleported confirmation must retain visible input boundaries and semantic warning colors');
}
async function login(email=credentials.email,currentPage=page){
 await currentPage.locator('.login-form input[type=email]').fill(email);await currentPage.locator('.login-form input[type=password]').fill(credentials.password);
 await currentPage.locator('.login-form button[type=submit]').click();await currentPage.locator('.login-form').waitFor({state:'detached'});
}
async function editTarget(){await page.locator('.member-row').filter({hasText:credentials.target_email}).getByRole('button',{name:label('编辑','Edit'),exact:true}).click();await dialog().getByLabel(label('姓名','Name'),{exact:true}).waitFor();}
async function closeEditor(){step='close-editor-click';await dialog().getByRole('button',{name:label('取消','Cancel'),exact:true}).click();step='close-editor-detach';await dialog().waitFor({state:'detached'});step='close-editor-history';await page.waitForFunction(()=>!history.state?.asterOverlay);step='start';}
async function save(){const response=page.waitForResponse(r=>new URL(r.url()).pathname===`/console/v1/users/${credentials.target_id}`&&r.request().method()==='PATCH');await dialog().getByRole('button',{name:label('保存更改','Save changes'),exact:true}).click();return response;}
async function setPreferences(locale,appearance){
 // Preferences are test-only presentation state, not API/session injection.
 await page.evaluate(({locale,appearance})=>localStorage.setItem('aster.cloud.ui.v1',JSON.stringify({locale,appearance})),{locale,appearance});
 english=locale==='en';await page.reload();await page.getByRole('heading',{name:label('成员与权限','Members & access'),exact:true}).waitFor();
}
try{
 context=await firefox.launchPersistentContext(process.env.FIREFOX_PROFILE_DIR,{headless:true,ignoreHTTPSErrors:false,acceptDownloads:false,viewport:{width:1440,height:1000},firefoxUserPrefs:{'security.enterprise_roots.enabled':false}});
 context.on('request',request=>{const url=new URL(request.url());if(url.origin!==base.origin)report.foreign_requests++;if(!['GET','HEAD'].includes(request.method())&&!url.pathname.startsWith('/console/v1/auth/'))report.write_attempts++;});
 page=await context.newPage();for(const old of context.pages())if(old!==page)await old.close();await page.goto(base.href+'#/users');
 // Remove only presentation preferences from the earlier, independent fixture.
 await page.evaluate(()=>localStorage.setItem('aster.cloud.ui.v1',JSON.stringify({locale:'zh-CN',appearance:'light'})));await page.reload();
 phase='signin';await login();await page.locator('.member-row').filter({hasText:credentials.target_email}).waitFor();
 const initial=await read('/users/'+credentials.target_id);assert.equal(initial.status,200);assert.equal(initial.data.user.revision,1);check('real_mysql_member_detail');
 phase='editor';await editTarget();const name=dialog().getByLabel('姓名',{exact:true});const focused=await name.elementHandle();await name.focus();await name.press('End');await page.keyboard.type('待');
 assert(await focused.evaluate(e=>e.isConnected&&document.activeElement===e),'Typing must not replace focused input');check('input_focus_preserved');
 await name.fill('资料已更新');assert.equal(await dialog().getByRole('button',{name:'保存更改',exact:true}).isEnabled(),false);check('required_reason_blocks');
 await screenshot('identity-desktop-editor.png');await page.setViewportSize({width:320,height:760});await geometry();await screenshot('identity-mobile-editor-top.png');
 await page.setViewportSize({width:390,height:844});await dialog().getByLabel('说明本次变更的原因',{exact:true}).fill('正常成员资料更新');await dialog().getByLabel('说明本次变更的原因',{exact:true}).scrollIntoViewIfNeeded();await geometry();await screenshot('identity-mobile-editor-reason.png');check('mobile_320_and_390_geometry');
 assert.equal(initial.data.user.revision,1);check('fresh_revision');assert.equal((await save()).status(),200);await dialog().waitFor({state:'detached'});const updated=await read('/users/'+credentials.target_id);assert.equal(updated.data.user.revision,2);assert.equal(updated.data.user.name,'资料已更新');check('ordinary_change_committed');
 phase='conflict';await page.setViewportSize({width:1440,height:1000});await editTarget();await dialog().getByLabel('姓名',{exact:true}).fill('保留的修改草稿');await dialog().getByLabel('说明本次变更的原因',{exact:true}).fill('核对并发修改');assert.equal((await save()).status(),409);await dialog().getByText('资料已有更新',{exact:true}).waitFor();await criticalFeedback();check('stale_revision_rejected');
 assert.equal(await dialog().getByLabel('姓名',{exact:true}).inputValue(),'保留的修改草稿');assert.equal(await dialog().getByRole('button',{name:'保存更改',exact:true}).isEnabled(),false);check('conflict_draft_preserved');assert.equal(report.write_attempts,2);check('conflict_no_second_post');await screenshot('identity-desktop-conflict.png');
 await dialog().getByRole('button',{name:'放弃草稿并重新读取',exact:true}).click();await page.waitForFunction(()=>document.querySelector('input[type=text]')?.value==='另一位管理员已更新');check('explicit_reload_discards_draft');
 phase='lost-response';await dialog().getByLabel('姓名',{exact:true}).fill('响应丢失但已保存');await dialog().getByLabel('说明本次变更的原因',{exact:true}).fill('核对丢失响应');assert.equal((await save()).status(),503);await dialog().getByText('更改结果待核对',{exact:true}).waitFor();await criticalFeedback();check('critical_feedback_revealed');
 const pending=await page.evaluate(()=>JSON.parse(sessionStorage.getItem('aster.cloud.identity.pending.v1')||'[]'));assert.equal(pending.length,1);assert.equal(pending[0].owner,credentials.actor_id);assert.equal(pending[0].target,credentials.target_id);assert.equal(pending[0].intent.revision,3);assert.equal(pending[0].intent.name,'响应丢失但已保存');assert(!JSON.stringify(pending).includes(credentials.password));check('unknown_intent_persisted');
 await page.setViewportSize({width:390,height:844});await geometry();await screenshot('identity-mobile-uncertain.png');await page.reload();await page.locator('.identity-pending-tray').waitFor();check('refresh_keeps_unknown');assert.equal(await page.evaluate(()=>history.state?.asterOverlay),undefined);check('reload_clears_orphan_overlay_marker');assert.equal(report.write_attempts,3);check('unknown_no_repost');
 const receipt=await read('/identity-operations/'+pending[0].key);assert.equal(receipt.status,200);const op=receipt.data.operation;assert.equal(op.actor_id,credentials.actor_id);assert.equal(op.target_id,credentials.target_id);assert.equal(op.base_revision,3);assert.deepEqual(op.intent,pending[0].intent);check('original_receipt_matches');
 await page.locator('.identity-pending-tray').getByRole('button',{name:'核对原操作',exact:true}).click();await page.locator('.identity-pending-tray').waitFor({state:'detached'});assert.equal(report.write_attempts,3);check('reconciliation_get_only');
 phase='revocation';await page.setViewportSize({width:1440,height:1000});await editTarget();await dialog().getByRole('button',{name:'撤销全部会话',exact:true}).click();const confirmation=page.getByRole('dialog',{name:'撤销全部会话',exact:true});await confirmation.waitFor();
 assert(await confirmation.evaluate(e=>e.contains(document.activeElement)));assert(await dialog().evaluate(e=>e.closest('.overlay-shade').inert));check('nested_focus_and_inert');await confirmationTokens(confirmation);check('teleported_confirmation_tokens');await screenshot('identity-desktop-revocation.png');
 await page.goBack();await confirmation.waitFor({state:'detached'});await dialog().waitFor();assert(await dialog().evaluate(e=>e.contains(document.activeElement)));assert(await dialog().evaluate(e=>!e.closest('.overlay-shade').inert));check('nested_browser_back');
 await dialog().getByRole('button',{name:'撤销全部会话',exact:true}).click();await confirmation.getByLabel('撤销原因',{exact:true}).fill('隔离测试要求重新登录');const revResponse=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith('/'+credentials.target_id+'/revoke-sessions'));await confirmation.getByRole('button',{name:'确认撤销会话',exact:true}).click();assert.equal((await revResponse).status(),200);await confirmation.waitFor({state:'detached'});await dialog().waitFor({state:'detached'});assert.equal((await read('/users/'+credentials.target_id)).data.user.revision,5);check('all_target_sessions_revoked');
 phase='readonly';await page.getByRole('button',{name:'退出登录',exact:true}).click();await page.locator('.login-form').waitFor();await login(credentials.target_email);assert.equal((await read('/users')).status,403);assert.equal(await page.locator('.member-row').count(),0);check('readonly_member_denied');
 await page.getByRole('button',{name:'退出登录',exact:true}).click();await page.locator('.login-form').waitFor();await login();check('fresh_signin_allowed');
 phase='theme';await setPreferences('en','dark');await editTarget();await geometry();await screenshot('identity-desktop-english-dark.png');await page.setViewportSize({width:390,height:844});await geometry();await screenshot('identity-mobile-english-dark.png');check('english_dark_geometry');check('custom_controls');await closeEditor();
 await setPreferences('zh-CN','light');await page.getByRole('button',{name:'新增成员',exact:true}).click();await page.getByRole('dialog',{name:'新增成员',exact:true}).waitFor();await screenshot('identity-mobile-create-preview.png');await page.getByRole('dialog',{name:'新增成员',exact:true}).getByRole('button',{name:'取消',exact:true}).click();await page.waitForFunction(()=>!history.state?.asterOverlay);
 phase='self-revocation';await page.locator('.member-row').filter({hasText:credentials.email}).getByRole('button',{name:'编辑',exact:true}).click();await dialog().getByRole('button',{name:'撤销全部会话',exact:true}).click();await confirmation.waitFor();await screenshot('identity-mobile-self-revocation.png');await confirmation.getByLabel('撤销原因',{exact:true}).fill('结束本轮隔离验收的所有管理会话');const selfResponse=page.waitForResponse(r=>new URL(r.url()).pathname.endsWith('/'+credentials.actor_id+'/revoke-sessions'));await confirmation.getByRole('button',{name:'撤销并退出登录',exact:true}).click();assert.equal((await selfResponse).status(),200);await page.locator('.login-form').waitFor();check('self_revocation_exits');assert.equal((await read('/auth/me')).status,401);check('self_cookie_revoked');
 assert.equal(report.screenshots.length,10);check('ten_actual_screenshots');check('settled_dialog_screenshots');
 // Real backend separately verifies target sessions were removed, unchanged
 // credential hashes, five receipts and every resource/financial/node row.
 report.passed=true;
}catch{
 report.failure_phase=phase;report.failure_step=step;process.exitCode=1;
 // Fixed booleans/counts only: no DOM text, credentials, raw response or
 // exception string may leak from private browser diagnostics into artifacts.
 if(page)try{report.failure_ui=await page.evaluate(()=>({dialog_count:document.querySelectorAll('[role=dialog]').length,overlay_marker_present:typeof history.state?.asterOverlay==='string',pending_visible:!!document.querySelector('.identity-pending-tray'),discard_visible:!!document.querySelector('.discard-box')}));}catch{}
}
finally{if(context)await context.close();fs.writeFileSync(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});}
