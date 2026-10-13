/* Browser acceptance for the evidence-first dialog. No real engines or decisions are invoked.
 * NODE_PATH=<playwright node_modules> PLAYWRIGHT_BROWSERS_PATH=<cache> node tests/test_threat_ai_ui.cjs [screenshots]
 * EDGE_EXECUTABLE can select an installed Windows Edge or Chromium executable.
 */
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

(async () => {
    const root = path.resolve(__dirname, '../Interface');
    const output = process.argv[2] && path.resolve(process.argv[2]);
    if (output) fs.mkdirSync(output, { recursive: true });
    const server = http.createServer((req, res) => {
        const file = path.resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
        if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
            res.writeHead(404); res.end(); return;
        }
        const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' };
        res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    let browser;
    let checks = 0;
    const check = async (name, test) => { await test(); checks += 1; console.log('PASS ' + name); };
    try {
        browser = await chromium.launch({
            executablePath: process.env.EDGE_EXECUTABLE || (process.platform === 'win32'
                ? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe' : undefined),
            headless: true,
        });
        const page = await browser.newPage({ viewport: { width: 900, height: 760 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript(() => {
            window.fixture = {
                blank: false, fail: false, decisions: [], focus: [], hold: false,
                data: {
                    id: 'r1', title: '文件防护', summary: '检测到可疑文件，等待您决定是否拦截。',
                    message: '示例告警（测试数据）\n来源: C:/Downloads/sample.exe', count: 1,
                    events: [{ id: 'file', title: '文件防护', count: 1, active: true }],
                    can_remember: true, identity_summary: 'C:/Downloads/sample.exe',
                    process_label: '进程',
                    process: { name: 'installer.exe', path: 'C:/Downloads/installer.exe' },
                    file: { name: 'sample.exe', path: 'C:/Downloads/sample.exe', sha256: 'a'.repeat(64) },
                    evidence: { engine: 'ml', status: 'detected', score: 92, score_kind: 'model_probability',
                        category: 'Malware', platform: 'WinPE', family: 'General', generic: true,
                        raw_label: 'Malware:WinPE/General.92!ml', rules: [], description: '' },
                    theme: 'white_switch', language: 'simplified_switch', remaining: null,
                    waiting: '等待您选择', allow: '本次允许', block: '拦截', countdown: '', resolving: false,
                    ai: { state: 'analyzing', verdict: '', label: 'AI 分析中…', hint: '正在结合检测证据生成建议。' },
                },
            };
            window.pywebview = { api: {
                ready: async () => true,
                snapshot: async () => {
                    if (window.fixture.fail) throw new Error('fixture disconnected');
                    const data = window.fixture.blank ? null : JSON.parse(JSON.stringify(window.fixture.data));
                    if (window.fixture.hold) {
                        window.fixture.hold = false;
                        return new Promise((resolve, reject) => {
                            window.releaseSnapshot = () => resolve(data);
                            window.rejectSnapshot = () => reject(new Error("late snapshot failure"));
                        });
                    }
                    return data;
                },
                decide: async (id, choice) => { window.fixture.decisions.push({ id, choice }); return true; },
                set_focus: async state => { window.fixture.focus.push(state); return true; },
                minimize: async () => true,
            } };
        });
        await page.goto('http://127.0.0.1:' + server.address().port + '/templates/threat.html');
        await page.waitForFunction(() => document.getElementById('threat_score').textContent === '92');
        const glow = page.locator('#ai_window_glow');
        const patch = async data => page.evaluate(data => Object.assign(window.fixture.data, data), data);
        const waitStopped = () => page.waitForFunction(() => !document.getElementById('ai_window_glow').classList.contains('is-analyzing'));

        await check('AI action button removed; model facts are visible', async () => {
            assert.equal(await page.locator('#threat_ai').count(), 0);
            assert.equal(await page.locator('#threat_engine').textContent(), '本地 PE 机器学习');
            assert.equal(await page.locator('#threat_category').textContent(), '恶意软件（通用）');
            assert.equal(await page.locator('#threat_family').textContent(), '通用检测 · 未确定家族');
            assert.equal(await page.locator('#threat_raw_label').textContent(), 'Malware:WinPE/General.92!ml');
            assert.match(await page.locator('#threat_score_note').textContent(), /不是实测准确率/);
        });
        await check('four window edges fade inward and never capture input', async () => {
            await page.waitForFunction(() => document.getElementById('ai_window_glow').classList.contains('is-analyzing'));
            const facts = await glow.evaluate(el => {
                const s = getComputedStyle(el), before = getComputedStyle(el, '::before'), r = el.getBoundingClientRect();
                return { x: r.x, y: r.y, w: r.width, h: r.height, pointer: s.pointerEvents, mask: s.maskImage,
                    animation: before.animationName, state: before.animationPlayState,
                    top: document.elementFromPoint(innerWidth / 2, 1) === el,
                    bottom: document.elementFromPoint(innerWidth / 2, innerHeight - 1) === el };
            });
            assert.deepEqual([facts.x, facts.y, facts.w, facts.h], [0, 0, 900, 760]);
            assert.equal(facts.pointer, 'none'); assert.equal(facts.top || facts.bottom, false);
            assert.equal((facts.mask.match(/linear-gradient/g) || []).length, 4);
            assert.match(facts.mask, /0.55/); assert.match(facts.mask, /0.14/);
            assert.equal(facts.animation, 'ai-window-spectrum'); assert.equal(facts.state, 'running');
        });
        await check('rainbow is actually animated', async () => {
            const before = await glow.evaluate(el => getComputedStyle(el, '::before').transform);
            await page.waitForFunction(value => getComputedStyle(document.getElementById('ai_window_glow'), '::before').transform !== value, before);
        });
        if (output) await page.screenshot({ path: path.join(output, 'threat-evidence-light.png') });
        await check('reduced motion preserves static state without animation', async () => {
            await page.emulateMedia({ reducedMotion: 'reduce' });
            assert.equal(await glow.evaluate(el => getComputedStyle(el, '::before').animationName), 'none');
            await page.emulateMedia({ reducedMotion: 'no-preference' });
        });
        await check('delay has text but no active-analysis glow', async () => {
            await patch({ ai: { state: 'delay', label: '2 秒后启动 AI 决策', hint: '' } }); await waitStopped();
            assert.equal(await page.locator('#ai_result_verdict').textContent(), '2 秒后启动 AI 决策');
        });
        await check('ready advice stops animation but does not execute decisions', async () => {
            await patch({ ai: { state: 'ready', verdict: 'allow', label: 'AI 建议放行', hint: '证据仍需人工复核。' } });
            await page.waitForFunction(() => document.getElementById('ai_result_verdict').classList.contains('verdict-allow'));
            await waitStopped();
            assert.equal(await glow.evaluate(el => getComputedStyle(el, '::before').animationPlayState), 'paused');
            assert.equal(await page.evaluate(() => window.fixture.decisions.length), 0);
            assert.match(await page.locator('#ai_result_note').textContent(), /可能出错/);
        });
        await check('YARA fixed 100 never appears as probability', async () => {
            await patch({ evidence: { engine: 'yr', score: 100, score_kind: 'rule_match', category: 'TrojanDownloader',
                platform: 'JS', family: 'WSHLoader', generic: false, raw_label: 'TrojanDownloader:JS/WSHLoader.1!yr',
                rules: ['TrojanDownloader_JS_WSHLoader'], description: 'HTTP 客户端、落盘及执行组合命中。' } });
            await page.waitForFunction(() => document.getElementById('threat_score').textContent === '规则命中');
            assert.equal(await page.locator('#threat_score_track').isVisible(), false);
            assert.equal(await page.locator('#threat_score_track').getAttribute('aria-valuenow'), null);
            assert.equal(await page.locator('#threat_category').textContent(), '木马下载器');
            assert.equal(await page.locator('#threat_engine').textContent(), 'YARA 文件规则');
            assert.equal(await page.locator('#threat_rules').textContent(), 'TrojanDownloader_JS_WSHLoader');
        });
        await check('unknown evidence clears old score and rule names', async () => {
            await patch({ id: 'r2', evidence: {}, file: {}, process: {}, summary: '' });
            await page.waitForFunction(() => document.getElementById('threat_score').textContent === '未评分');
            assert.equal(await page.locator('#threat_engine').textContent(), '未提供');
            assert.equal(await page.locator('#threat_rules').textContent(), '');
            assert.equal(await page.locator('#threat_file').isVisible(), false);
        });
        await check('file, detector and AI strings are text, not HTML or instructions', async () => {
            const payload = '<img src=x onerror="window.pwned=1">';
            await patch({ id: 'r3', file: { name: payload, path: 'C:/' + 'long/'.repeat(65) + payload },
                evidence: { raw_label: payload, description: payload, rules: [payload] },
                ai: { state: 'ready', verdict: 'block', label: 'AI 建议拦截', hint: payload } });
            await page.waitForFunction(value => document.getElementById('threat_raw_label').textContent === value, payload);
            assert.equal(await page.locator('#threat_evidence img, #ai_result img, #threat_file img').count(), 0);
            assert.equal(await page.evaluate(() => window.pwned), undefined);
        });
        await check('responsive narrow layout never overflows horizontally', async () => {
            await page.setViewportSize({ width: 390, height: 700 });
            const widths = await page.evaluate(() => [document.documentElement.scrollWidth, innerWidth,
                document.querySelector('.threat-detail').scrollWidth, document.querySelector('.threat-detail').clientWidth]);
            assert.ok(widths[0] <= widths[1] + 1, JSON.stringify(widths));
            assert.ok(widths[2] <= widths[3] + 1, JSON.stringify(widths));
            const rect = await page.locator('#threat_block').boundingBox();
            assert.ok(rect.y + rect.height <= 700);
            if (output) await page.screenshot({ path: path.join(output, 'threat-evidence-narrow.png') });
            await page.setViewportSize({ width: 900, height: 760 });
        });
        await check('all supported locales have readable field labels with fallback', async () => {
            const langs = await page.evaluate(() => Object.entries(window.AppI18n.langMap));
            for (const [language, code] of langs) {
                await patch({ language });
                await page.waitForFunction(code => document.documentElement.lang === code, code);
                const text = await page.locator('#evidence_heading').textContent();
                assert.ok(text && !text.startsWith('evidence_'), language);
            }
            await patch({ language: 'simplified_switch' });
        });
        await check('dark theme and whole-window glow remain active', async () => {
            await patch({ theme: 'black_switch', file: { name: 'sample.exe', path: 'C:/Downloads/sample.exe' },
                evidence: { engine: 'ml', score: 92, score_kind: 'model_probability', category: 'Malware', platform: 'WinPE',
                    family: 'General', generic: true, raw_label: 'Malware:WinPE/General.92!ml' },
                ai: { state: 'analyzing', label: 'AI 分析中…', hint: '正在结合检测证据生成建议。' } });
            await page.waitForFunction(() => document.body.dataset.appliedTheme === 'black_switch'
                && getComputedStyle(document.querySelector('.navigate-window')).backgroundColor === 'rgb(28, 28, 30)'
                && Number(getComputedStyle(document.getElementById('ai_window_glow')).opacity) >= .65
                && document.getElementById('ai_window_glow').classList.contains('is-analyzing'));
            if (output) await page.screenshot({ path: path.join(output, 'threat-evidence-dark.png') });
        });
        await check('resolving request cannot keep analysis glow alive', async () => {
            await patch({ resolving: true }); await waitStopped();
            assert.equal(await page.locator('#threat_allow').isDisabled(), true);
            await patch({ resolving: false });
        });
        await check('failure and unavailable AI clear analysis state', async () => {
            for (const state of ['failed', 'unavailable']) {
                await patch({ ai: { state, label: 'AI 建议不可用', hint: '证据不足，等待人工决定。' } });
                await page.waitForFunction(() => document.getElementById('ai_result_verdict').textContent === 'AI 建议不可用');
                await waitStopped();
            }
            await patch({ ai: null });
            await page.waitForFunction(() => document.getElementById('ai_result').classList.contains('hidden'));
        });
        await check('manual block still decides the current request exactly once', async () => {
            await page.locator('#threat_block').click();
            await page.waitForFunction(() => window.fixture.decisions.length === 1);
            assert.deepEqual(await page.evaluate(() => window.fixture.decisions), [{ id: 'r3', choice: 'block' }]);
        });
        await check('empty queue clears facts, confirmation and pending actions', async () => {
            await page.locator('#threat_permanent').click();
            await page.evaluate(() => { window.fixture.blank = true; });
            await page.waitForFunction(() => document.getElementById('queue_count').textContent === '0');
            await waitStopped();
            assert.equal(await page.locator('#threat_confirmation').isVisible(), false);
            assert.equal(await page.locator('#threat_block').isDisabled(), true);
            assert.equal(await page.locator('#threat_raw_label').textContent(), '未提供');
            assert.equal(await page.locator('#threat_file_path').textContent(), '');
        });
        await check('failed snapshot pauses actions and recovers without stale decisions', async () => {
            await page.evaluate(() => { window.fixture.blank = false; window.fixture.fail = true; });
            await page.waitForFunction(() => document.getElementById('threat_status').textContent.includes('数据暂不可用'));
            assert.equal(await page.locator('#threat_allow').isDisabled(), true);
            await page.evaluate(() => { window.fixture.fail = false; });
            await page.waitForFunction(() => !document.getElementById('threat_block').disabled);
        });
        await check('pagehide invalidates in-flight snapshots and pageshow resumes', async () => {
            await patch({ ai: { state: 'analyzing', label: 'AI 分析中…' } });
            await page.evaluate(() => { window.fixture.hold = true; });
            await page.waitForFunction(() => typeof window.releaseSnapshot === 'function');
            await page.evaluate(() => { window.dispatchEvent(new Event('pagehide')); window.releaseSnapshot(); });
            await waitStopped();
            assert.equal(await page.locator('#threat_block').isDisabled(), true);
            await page.evaluate(() => { window.fixture.data.ai = null; window.dispatchEvent(new Event('pageshow')); });
            await page.waitForFunction(() => !document.getElementById('threat_block').disabled);
            await waitStopped();
        });
        await check('lost API bridge clears current facts and pauses actions', async () => {
            await page.evaluate(() => { window.savedBridge = window.pywebview; window.pywebview = null; });
            await page.waitForFunction(() => document.getElementById('threat_status').textContent.includes('数据暂不可用'));
            await waitStopped();
            assert.equal(await page.locator('#threat_block').isDisabled(), true);
            await page.evaluate(() => { window.pywebview = window.savedBridge; });
            await page.waitForFunction(() => !document.getElementById('threat_block').disabled);
        });
        await check('late rejected snapshot cannot clear a newer request', async () => {
            await page.evaluate(() => { window.releaseSnapshot = null; window.fixture.hold = true; });
            await page.waitForFunction(() => typeof window.releaseSnapshot === 'function');
            await page.evaluate(() => {
                window.dispatchEvent(new Event('pagehide'));
                window.fixture.data.id = 'new-after-resume';
                window.fixture.data.title = '新告警';
                window.dispatchEvent(new Event('pageshow'));
            });
            await page.waitForFunction(() => document.getElementById('threat_title').textContent === '新告警');
            await page.evaluate(async () => { window.rejectSnapshot(); await new Promise(resolve => setTimeout(resolve, 30)); });
            assert.equal(await page.locator('#threat_title').textContent(), '新告警');
            assert.equal(await page.locator('#threat_block').isDisabled(), false);
        });
        await check('focus reporting and JavaScript runtime remain healthy', async () => {
            await page.evaluate(() => { window.dispatchEvent(new Event('blur')); window.dispatchEvent(new Event('focus')); });
            assert.deepEqual(await page.evaluate(() => window.fixture.focus.slice(-2)), [false, true]);
            assert.deepEqual(errors, []);
        });
        console.log('SUMMARY checks=' + checks + ' failures=0');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
