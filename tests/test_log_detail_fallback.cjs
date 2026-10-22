/* Every language must resolve log detail patterns; untranslated ones fall back to English. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs'), path = require('node:path'), http = require('node:http');
(async () => {
 const root = path.resolve(__dirname, '../Interface');
 const server = http.createServer((req,res) => {
  const file = path.resolve(root, '.' + new URL(req.url,'http://localhost').pathname);
  if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404);res.end();return; }
  res.setHeader('Content-Type', {'.html':'text/html','.css':'text/css','.js':'text/javascript'}[path.extname(file)] || 'application/octet-stream');
  res.end(fs.readFileSync(file));
 });
 await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
 let browser, checks = 0;
 try {
  browser = await chromium.launch({headless:true, executablePath:process.env.EDGE_EXECUTABLE});
  const page = await browser.newPage();
  const errors=[]; page.on('pageerror', e=>errors.push(String(e)));
  await page.addInitScript(() => { window.pywebview = { api: {
    get_config: async () => ({ language:'traditional_switch', first_launch:false, version:'fixture' }),
    init_ui_ready: async () => true, report_ui_error: async () => true, get_pending_threat_count: async () => 0,
    get_logs: async () => [], get_context_menu_status: async () => ({ mode:'disabled' }),
    update_config: async (k,v) => v, show_alert: async () => true,
  }};});
  await page.goto('http://127.0.0.1:'+server.address().port+'/templates/index.html');
  await page.waitForFunction(() => typeof window.translateLogDetail === 'function');
  const check=async(name,fn)=>{await fn();checks++;console.log('PASS '+name);};
  const expectedLangTag = { traditional_switch:'zh-Hant', simplified_switch:'zh-Hans' };
  // translateText() runs synchronously in the select's change handler; wait for
  // its observable effect instead of racing the handler.
  const useLanguage = async (lang) => {
   await page.locator('#lang_select').selectOption(lang, { force: true });
   const tag = expectedLangTag[lang];
   await page.waitForFunction(([value, expected]) => expected
     ? document.documentElement.lang === expected
     : document.getElementById('lang_select').value === value, [lang, tag || null]);
  };

  await check('traditional renders the localized watch sentence', async () => {
   await useLanguage('traditional_switch');
   const text = await page.evaluate(() => window.translateLogDetail('Real-time file protection is on (watching the user profile for file changes)'));
   assert.equal(text, '檔案即時防護已開啟');
  });
  await check('simplified renders its own wording', async () => {
   await useLanguage('simplified_switch');
   const text = await page.evaluate(() => window.translateLogDetail('Real-time file protection is on (watching the user profile for file changes)'));
   assert.equal(text, '文件实时防护已开启');
  });
  // 整句式详情没有占位符,靠词条本身翻译(不是 log_detail_patterns)
  await check('static sentences resolve through the plain dictionary', async () => {
   await useLanguage('simplified_switch');
   const cases = await page.evaluate(() => ({
     engine: window.translateLogDetail('Engine Initialization Complete'),
     autostart: window.translateLogDetail('Elevated autostart changes require administrator; keeping existing task state'),
     registered: window.translateLogDetail('Context menu registered'),
     unregistered: window.translateLogDetail('Context menu unregistered'),
     missing: window.translateLogDetail('Registration files are missing'),
   }));
   assert.equal(cases.engine, '引擎初始化完成');
   assert.equal(cases.autostart, '开机自启动需要管理员权限才能设置；当前以普通权限运行，已保留现有自启动状态');
   assert.equal(cases.registered, '已注册');
   assert.equal(cases.unregistered, '已取消注册');
   assert.equal(cases.missing, '注册文件缺失');
  });
  await check('ai suggestion details localize their verdict', async () => {
   await useLanguage('simplified_switch');
   const cases = await page.evaluate(() => ({
     block: window.translateLogDetail('model=mimo-flash verdict=block from_cache=False elapsed=14.46s reason=混淆代码'),
     allow: window.translateLogDetail('model=mimo-flash verdict=allow from_cache=True elapsed=3.4s reason=looks benign'),
     appliedBlock: window.translateLogDetail('Trojan.JS/Loader.1 / block'),
     failed: window.translateLogDetail('model=mimo-flash state=failed from_cache=False elapsed=1.2s'),
     skipped: window.translateLogDetail('model=mimo-flash skipped: decided within 30s delay window'),
   }));
   assert.equal(cases.block, '模型 mimo-flash 建议拦截（用时 14.46 秒）：混淆代码');
   assert.equal(cases.allow, '模型 mimo-flash 建议放行（用时 3.4 秒）：looks benign');
   assert.equal(cases.appliedBlock, '已按 AI 建议拦截：Trojan.JS/Loader.1');
   assert.equal(cases.failed, '模型 mimo-flash 分析失败（用时 1.2 秒）');
   assert.equal(cases.skipped, '模型 mimo-flash 跳过分析：用户已在 30 秒延迟窗口内做出决定');
  });
  await check('a language without the sentence keeps the English original', async () => {
   await useLanguage('japanese_switch');
   const text = await page.evaluate(() => window.translateLogDetail('Engine Initialization Complete'));
   assert.equal(text, 'エンジン初期化完了');
   const unknown = await page.evaluate(() => window.translateLogDetail('Context menu registered'));
   assert.equal(unknown, 'Context menu registered');
  });

  await check('untranslated language falls back explicitly to the original English sentence', async () => {
   await useLanguage('japanese_switch');
   const text = await page.evaluate(() => window.translateLogDetail('No file activity for 120s; rescanning to make sure nothing was missed'));
   assert.equal(text, 'No file activity for 120s; rescanning to make sure nothing was missed');
  });
  await check('all eleven languages resolve every backend template', async () => {
   const result = await page.evaluate(() => {
    const langs = Object.keys(window.AppI18n.dict).filter(k => k.endsWith('_switch'));
    const samples = [
     'Real-time file protection is on (watching the user profile for file changes)',
     'Real-time file protection cannot watch C:\\X; will retry',
     'No file activity for 90s; rescanning to make sure nothing was missed',
     'Too many files changing at once; running a full rescan',
     'File events were dropped during heavy activity; running a full rescan',
     'File monitoring hit an error; running a full rescan',
     'File monitoring stopped responding; running a full rescan',
     'model=mimo-flash skipped: decided within 30s delay window',
     'model=mimo-flash cancelled after 12.5s (user decided)',
     'model=mimo-flash state=failed from_cache=False elapsed=1.2s',
     'model=mimo-flash verdict=allow from_cache=True elapsed=3.4s reason=looks benign',
     'model=mimo-flash verdict=block from_cache=False elapsed=14.46s reason=混淆代码',
     'Trojan.JS/Loader.1 / block',
     'Trojan.JS/Loader.1 / allow',
    ];
    const failures = [];
    for (const lang of langs) {
      // Every section must declare a pattern table, not rely on silent fallback.
      const patterns = window.AppI18n.dict[lang]?.log_detail_patterns;
      if (!Array.isArray(patterns) || patterns.length !== 15) { failures.push(lang + ':patterns'); continue; }
      for (const sample of samples) {
        const after = window.translateLogDetail(sample);
        if (typeof after !== 'string' || !after) failures.push(lang + ':' + sample);
      }
    }
    return { langs: langs.length, failures };
   });
   assert.equal(result.langs, 11, '11 language sections expected');
   assert.deepEqual(result.failures, []);
  });
  await check('unmatched detail text is returned unchanged', async () => {
   const text = await page.evaluate(() => window.translateLogDetail('Unrelated backend detail'));
   assert.equal(text, 'Unrelated backend detail');
  });
  assert.deepEqual(errors, []);
  console.log('SUMMARY checks=' + checks + ' failures=0');
 } finally { if (browser) await browser.close(); await new Promise(r => server.close(r)); }
})().catch(e => { console.error(e); process.exitCode = 1; });
