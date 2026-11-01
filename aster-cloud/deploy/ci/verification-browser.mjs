// Actual browser + production read-only API + minimum real MySQL account.
// No response substitution, business writes, node calls or authentication injection.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {CHECKS,SHOTS} from './verification-browser-contract.mjs';
const base=new URL(process.env.BASE_URL);assert.equal(base.href,'https://localhost:5447/');
const output=process.env.BROWSER_ARTIFACT_DIR;assert(path.isAbsolute(output));
const credentials=JSON.parse(fs.readFileSync(process.env.BROWSER_CREDENTIALS_FILE,'utf8'));
for(const key of ['actor_id','instance_id','operation_id'])assert(/^[a-f0-9]{32}$/.test(credentials[key]));
assert(credentials.email.endsWith('@example.invalid'));assert(typeof credentials.password==='string'&&credentials.password.length>=16);
const {firefox}=await import(pathToFileURL(path.join(process.env.PLAYWRIGHT_MODULE_DIR,'playwright/index.mjs')).href);
const report={schema:1,passed:false,strict_tls:true,checks:[],screenshots:[],business_write_attempts:0,forbidden_node_reads:0,foreign_requests:0,page_errors:0};
let context,page,phase='launch';
function check(name){assert(CHECKS.includes(name)&&!report.checks.includes(name));report.checks.push(name);console.log('PASS verification '+name);}
async function read(p){return page.evaluate(async p=>{const r=await fetch('/console/v1'+p,{method:'GET',credentials:'same-origin',cache:'no-store'});return{status:r.status,data:r.status===200?await r.json():null};},p);}
async function geometry(){
 const proof=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,main:document.querySelector('main')?.getBoundingClientRect().toJSON(),banner:[...document.querySelectorAll('[role="status"]')].find(e=>e.textContent.includes('迁移验证中')||e.textContent.includes('Migration verification'))?.getBoundingClientRect().toJSON()}));
 assert(proof.scroll<=proof.width);assert(proof.main&&proof.main.left>=-1&&proof.main.right<=proof.width+1);
 assert(proof.banner&&proof.banner.width>0&&proof.banner.left>=-1&&proof.banner.right<=proof.width+1);
}
async function shot(name){assert(SHOTS.includes(name)&&!report.screenshots.includes(name));await geometry();await page.screenshot({path:path.join(output,name),fullPage:false});report.screenshots.push(name);}
async function disabled(labels){for(const label of labels){const button=page.getByRole('button',{name:label,exact:true});assert.equal(await button.count(),1);assert.equal(await button.isEnabled(),false);}}
try{
 context=await firefox.launchPersistentContext(process.env.FIREFOX_PROFILE_DIR,{headless:true,ignoreHTTPSErrors:false,acceptDownloads:false,viewport:{width:1440,height:1000},firefoxUserPrefs:{'security.enterprise_roots.enabled':false}});
 context.on('request',request=>{
  const u=new URL(request.url());if(u.origin!==base.origin)report.foreign_requests++;
  if(!['GET','HEAD'].includes(request.method())&&!u.pathname.startsWith('/console/v1/auth/'))report.business_write_attempts++;
  if(/^\/console\/v1\/instances\/[^/]+\/(metrics|observation|migration-targets)$/.test(u.pathname))report.forbidden_node_reads++;
 });
 page=await context.newPage();for(const old of context.pages())if(old!==page)await old.close();
 page.on('pageerror',()=>report.page_errors++);
 await page.goto(base.href+'#/users');
 // Presentation preferences only; never place a user, cookie or API mode in storage.
 await page.evaluate(()=>localStorage.setItem('aster.cloud.ui.v1',JSON.stringify({locale:'zh-CN',appearance:'light'})));await page.reload();
 phase='signin';await page.locator('.login-form').waitFor();await page.getByLabel('邮箱',{exact:true}).fill(credentials.email);await page.getByLabel('密码',{exact:true}).fill(credentials.password);await page.getByRole('button',{name:'登录',exact:true}).click();
 await page.getByRole('heading',{name:'成员与权限',exact:true}).waitFor();await page.getByText(credentials.email,{exact:true}).first().waitFor();
 const session=await read('/auth/me');assert.equal(session.status,200);assert.equal(session.data.verification_mode,true);assert(session.data.user.permissions.includes('users.manage'));
 const status=await read('/migration-verification');assert.equal(status.status,200);assert.equal(status.data.operation_id,credentials.operation_id);assert.equal(status.data.business_writes,false);assert.equal(status.data.node_contacts,false);check('server_confirmed_mode');
 const users=await read('/users');assert.equal(users.status,200);assert(users.data.items.some(u=>u.id===credentials.actor_id));check('members_remain_readable');
 await disabled(['新增成员','编辑']);check('member_editors_disabled');await shot('verification-desktop-members.png');
 phase='mobile-members';await page.setViewportSize({width:390,height:844});await shot('verification-mobile-members.png');await page.setViewportSize({width:320,height:760});await geometry();
 phase='instance';await page.setViewportSize({width:1440,height:1000});await page.goto(base.href+'#/instances/'+credentials.instance_id);
 const detail=await read('/instances/'+credentials.instance_id);assert.equal(detail.status,200);assert.equal(detail.data.instance.id,credentials.instance_id);
 await page.getByRole('heading',{name:detail.data.instance.hostname||credentials.instance_id,exact:true}).waitFor();assert.equal(detail.data.instance.state,'reserved');await page.getByText('已预留',{exact:true}).waitFor();check('saved_instance_readable');
 await disabled(['启动','关机','重启','迁移','强制关机','删除实例']);check('instance_actions_disabled');await shot('verification-desktop-instance.png');
 await page.setViewportSize({width:390,height:844});await shot('verification-mobile-instance.png');await page.setViewportSize({width:320,height:760});await geometry();
 phase='nodes';await page.goto(base.href+'#/nodes');await page.getByRole('heading',{name:'节点',exact:true}).waitFor();
 const nodes=await read('/nodes');assert.equal(nodes.status,200);assert(nodes.data.items.length>0);assert(nodes.data.items.every(n=>n.online===false&&n.heartbeat_at));check('historical_nodes_readable');
 await page.setViewportSize({width:390,height:844});await shot('verification-mobile-nodes.png');
 phase='english';await page.evaluate(()=>localStorage.setItem('aster.cloud.ui.v1',JSON.stringify({locale:'en',appearance:'dark'})));await page.goto(base.href+'#/instances/'+credentials.instance_id);await page.reload();
 await page.getByText('Migration verification',{exact:true}).waitFor();await page.getByText('Reserved',{exact:true}).waitFor();await disabled(['Start','Shut down','Restart','Migrate','Force off','Delete instance']);
 await page.setViewportSize({width:1440,height:1000});await shot('verification-desktop-english-dark.png');await page.setViewportSize({width:390,height:844});await shot('verification-mobile-english-dark.png');check('english_dark_readonly');check('desktop_mobile_geometry');
 assert.equal(report.forbidden_node_reads,0);check('no_live_node_queries');
 phase='logout';await page.setViewportSize({width:1440,height:1000});await page.getByRole('button',{name:'Sign out',exact:true}).click();await page.locator('.login-form').waitFor();assert.equal((await read('/auth/me')).status,401);check('logout_revokes_session');
 assert.equal(report.page_errors,0);assert.equal(report.business_write_attempts,0);assert.equal(report.foreign_requests,0);assert.equal(report.screenshots.length,SHOTS.length);assert.equal(report.checks.length,CHECKS.length);report.passed=true;
}catch{
 report.failure_phase=phase;process.exitCode=1;
 // No exception strings, DOM text, credentials, cookies or response bodies.
}finally{
 if(context)await context.close();fs.writeFileSync(path.join(output,'report.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
}
