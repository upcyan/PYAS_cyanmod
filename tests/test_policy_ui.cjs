/* R1 browser tests: review is explicit, cancellation never submits policy. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), http = require('node:http');
(async () => {
 const root = path.resolve(__dirname, '../Interface');
 const server = http.createServer((req,res) => {
  const file = path.resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
  if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404);res.end();return; }
  res.setHeader('Content-Type', {'.html':'text/html','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml'}[path.extname(file)] || 'application/octet-stream');
  res.end(fs.readFileSync(file));
 });
 await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
 let browser, checks=0;
 try {
  browser = await chromium.launch({headless:true, executablePath:process.env.EDGE_EXECUTABLE});
  const page = await browser.newPage({viewport:{width:1000,height:850}});
  const errors=[];page.on('pageerror',e=>errors.push(String(e)));
  await page.addInitScript(() => {
   window.p = {status:{state:'not_initialized',initialized:false,error:''}, calls:[], writes:[], statusCalls:0,
      mode:'cancel', legacy:true, statusMode:'normal'};
   window.pywebview={api:{
    get_config:async()=>({first_launch:true, language:'simplified_switch',theme:'white_switch',version:'fixture',
       process_switch:false,document_switch:false,system_switch:false,network_switch:false,
       policy_status:{state:'not_initialized',initialized:false}}),
    init_ui_ready:async()=>true,report_ui_error:async()=>true,get_pending_threat_count:async()=>0,
    update_config:async(key,value)=>{window.p.calls.push([key,value]);return value;},
    get_policy_status:async()=>{window.p.statusCalls++;if(window.p.statusMode==='hang')return new Promise(resolve=>window.p.statusHold=resolve);return {...window.p.status};},
    get_policy_defaults_preview:async()=>({available:true,values:{process_switch:false,white_list:[],ai_api_key_enc:'[redacted]'}}),
    get_policy_migration_preview:async()=>({available:window.p.legacy,digest:'d'.repeat(64),values:{process_switch:true,
        white_list:[{file:'<img src=x onerror="window.injected=true">'}],ai_api_key_enc:'[redacted]'}}),
    initialize_security_policy:async(legacy,digest)=>{
      window.p.writes.push({legacy,digest});
      if(window.p.mode==='hang'){window.p.status={state:'authorizing',initialized:false};return new Promise(resolve=>window.p.initHold=resolve);}
      if(window.p.mode==='accept'){window.p.status={state:'restart_required',initialized:true};return {ok:true,restart_required:true};}
      window.p.status={state:'not_initialized',initialized:false,error:'cancelled'};return {ok:false};
    },
    show_alert:async()=>true, get_context_menu_status:async()=>({mode:'disabled'}),
   }};
  });
  await page.goto('http://127.0.0.1:'+server.address().port+'/templates/index.html');
  await page.waitForFunction(()=>typeof window.onEngineReady==='function');
  const check=async(name,fn)=>{await fn();checks++;console.log('PASS '+name);};
  const processToggle=page.locator('input[data-config-key="process_switch"]');
  const review=async(legacy=false)=>{
   await page.locator(legacy?'#policy_migrate_btn':'#policy_initialize_btn').click();
   await page.locator('#policy_review_dialog').waitFor({state:'visible'});
  };
  await check('uninitialized policy is visible and protected toggles are disabled',async()=>{
   await page.locator('#policy_status_panel').waitFor({state:'visible'});
   assert.equal(await processToggle.isDisabled(),true);
   assert.match(await page.locator('#policy_status_text').textContent(),/策略|policy/i);
  });
  await check('first engine ready never auto-enables administrator policies',async()=>{
   await page.evaluate(()=>window.onEngineReady());
   assert.deepEqual(await page.evaluate(()=>window.p.calls.filter(x=>x[0]!=='first_launch')),[]);
   assert.equal(await page.evaluate(()=>window.p.writes.length),0);
  });
  await check('theme preference remains writable without authorization',async()=>{
   assert.equal(await page.locator('#theme_select').isEnabled(),true);
   // The native select is hidden behind the custom-select UI; dispatch its actual change contract.
   await page.locator('#theme_select').selectOption('black_switch', {force:true});
   assert.ok(await page.evaluate(()=>window.p.calls.some(x=>x[0]==='theme'&&x[1]==='black_switch')));
   assert.equal(await page.evaluate(()=>window.p.writes.length),0);
  });
  await check('review requires explicit confirmation and cancel sends no write',async()=>{
   await review();assert.equal(await page.locator('#policy_review_approve').isDisabled(),true);
   const approve = page.locator('#policy_review_approve');
   const disabledStyle = await approve.evaluate(el => ({opacity: getComputedStyle(el).opacity,
     cursor: getComputedStyle(el).cursor}));
   assert.ok(Number(disabledStyle.opacity) < 1, 'unchecked approval must look greyed out');
   assert.equal(disabledStyle.cursor, 'not-allowed');
   await approve.evaluate(el => el.click());
   assert.equal(await page.locator('#policy_review_dialog').isVisible(), true);
   assert.equal(await page.evaluate(()=>window.p.writes.length), 0);
   await page.locator('#policy_review_confirm').check();
   assert.equal(await approve.isEnabled(), true);
   assert.equal(await approve.evaluate(el => getComputedStyle(el).opacity), '1');
   await page.locator('#policy_review_confirm').uncheck();
   assert.equal(await approve.isDisabled(), true);
   assert.ok(Number(await approve.evaluate(el => getComputedStyle(el).opacity)) < 1);
   assert.match(await page.locator('#policy_review_values').textContent(),/redacted/);
   await page.locator('#policy_review_cancel').click();
   assert.equal(await page.evaluate(()=>window.p.writes.length),0);
  });
  await check('legacy review is text-only and cancellation does not activate it',async()=>{
   await review(true);
   assert.equal(await page.locator('#policy_review_values img').count(),0);
   assert.equal(await page.evaluate(()=>window.injected),undefined);
   await page.locator('#policy_review_confirm').check();
   await page.locator('#policy_review_approve').click();
   await page.waitForFunction(()=>window.p.writes.length===1);
   assert.deepEqual(await page.evaluate(()=>window.p.writes[0]),{legacy:true,digest:'d'.repeat(64)});
   assert.equal(await processToggle.isChecked(),false);
   assert.equal(await processToggle.isDisabled(),true);
  });
  await check('missing legacy data gives persistent feedback without elevation',async()=>{
   await page.evaluate(()=>{window.p.legacy=false;window.dispatchEvent(new Event('pyas-policy-refresh'));});
   await page.locator('#policy_migrate_btn').click();
   await page.waitForFunction(()=>document.getElementById('policy_status_text').textContent.includes('可导入'));
   assert.equal(await page.evaluate(()=>window.p.writes.length),1);
  });
  await check('pending UAC leaves user preferences usable and never auto-retries',async()=>{
   await page.evaluate(()=>{window.p.mode='hang';window.p.legacy=true;});
   await review();await page.locator('#policy_review_confirm').check();await page.locator('#policy_review_approve').click();
   await page.waitForFunction(()=>window.p.writes.length===2);
   assert.equal(await page.locator('#theme_select').isEnabled(),true);
   assert.equal(await processToggle.isDisabled(),true);
   await page.waitForTimeout(1200);assert.equal(await page.evaluate(()=>window.p.writes.length),2);
   await page.evaluate(()=>{window.p.status={state:'not_initialized',initialized:false,error:'cancelled'};window.p.initHold({ok:false});});
   await page.waitForFunction(()=>!document.getElementById('policy_initialize_btn').disabled);
   assert.equal(await processToggle.isChecked(),false);
  });
  await check('successful commit requests restart without claiming active protection',async()=>{
   await page.evaluate(()=>{window.p.mode='accept';});
   await review();await page.locator('#policy_review_confirm').check();await page.locator('#policy_review_approve').click();
   await page.waitForFunction(()=>document.getElementById('policy_status_text').textContent.includes('重新启动'));
   assert.equal(await processToggle.isChecked(),false);
   assert.equal(await processToggle.isDisabled(),true);
   assert.equal(await page.locator('#policy_initialize_btn').isVisible(),false);
   assert.equal(await page.evaluate(()=>window.p.writes.length),3);
  });
  await check('status polling is single-flight and stale page responses are discarded',async()=>{
   await page.evaluate(()=>{window.p.statusMode='hang';window.dispatchEvent(new Event('pyas-policy-refresh'));});
   await page.waitForFunction(()=>typeof window.p.statusHold==='function');
   const before=await page.evaluate(()=>window.p.statusCalls);
   await page.evaluate(()=>{for(let i=0;i<4;i++)window.dispatchEvent(new Event('pyas-policy-refresh'));});
   await page.waitForTimeout(1100);assert.equal(await page.evaluate(()=>window.p.statusCalls),before);
   await page.evaluate(()=>{
    window.dispatchEvent(new Event('pagehide'));
    window.p.statusHold({state:'not_initialized',initialized:false});window.p.statusMode='normal';
    window.dispatchEvent(new Event('pageshow'));
   });
   await page.waitForFunction(()=>document.getElementById('policy_status_text').textContent.includes('重新启动'));
   assert.deepEqual(errors,[]);
  });
  console.log('SUMMARY checks='+checks+' failures=0');
 }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);process.exitCode=1;});
