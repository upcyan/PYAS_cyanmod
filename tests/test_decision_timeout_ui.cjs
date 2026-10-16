/* Live Chromium regression: pending bridge calls cannot permanently strand decisions.
   Optional THREAT_JS_OVERRIDE serves the unmodified baseline script for failure reproduction. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
    const root = path.resolve(__dirname, '../Interface');
    const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://localhost').pathname;
        const requested = path.resolve(root, '.' + url);
        const file = url === '/static/js/threat.js' && process.env.THREAT_JS_OVERRIDE
            ? path.resolve(process.env.THREAT_JS_OVERRIDE) : requested;
        if (!requested.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
            res.writeHead(404); res.end(); return;
        }
        res.setHeader('Content-Type', { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' }[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    let browser;
    let checks = 0;
    try {
        browser = await chromium.launch({ headless: true, executablePath: process.env.EDGE_EXECUTABLE ||
            (process.platform === 'win32' ? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe' : undefined) });
        const page = await browser.newPage({ viewport: { width: 720, height: 720 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript(() => {
            window.f = { mode: 'hang', calls: [], reports: [], snapshots: 0, held: [], snapshotHeld: null,
                holdSnapshot: false, failSnapshot: false,
                data: { id: 'first', title: 'first', summary: 'fixture', message: 'fixture',
                    events: [{ id: 'file', title: '文件防护', count: 3, active: true }], count: 3,
                    can_remember: true, identity_summary: 'fixture identity', remaining: null,
                    waiting: '等待您选择', allow: '本次允许', block: '拦截', countdown: '',
                    language: 'simplified_switch', theme: 'white_switch', resolving: false,
                    ai: { state: 'unavailable', label: 'AI 建议不可用', hint: '' }, evidence: {}, file: {}, process: {},
                    fp: { button: '误报处理', scope_this: '仅此检测', scope_file: '此文件', reason: '原因',
                        reasons: [['other', '其他']], note: '备注', submit: '提交', cancel: '取消' } } };
            const hold = list => new Promise((resolve, reject) => list.push({ resolve, reject }));
            window.pywebview = { api: {
                ready: async () => true, set_focus: async () => true, minimize: async () => true,
                snapshot: async () => {
                    window.f.snapshots += 1;
                    const captured = JSON.parse(JSON.stringify(window.f.data));
                    if (window.f.holdSnapshot) return new Promise((resolve, reject) => {
                        window.f.snapshotHeld = { resolve: () => resolve(captured), reject };
                    });
                    return captured;
                },
                decide: async (id, choice) => {
                    window.f.calls.push({ id, choice });
                    if (window.f.mode === 'advance') window.f.data.id = window.f.data.title = 'next';
                    if (window.f.mode === 'normal-advance') {
                        window.f.data.id = window.f.data.title = 'normal-next';
                        return true;
                    }
                    if (window.f.mode === 'persist') window.f.data.resolving = true;
                    if (window.f.mode === 'normal') return true;
                    return hold(window.f.held);
                },
                report_false_positive: async (...args) => { window.f.reports.push(args); return hold(window.f.held); },
            } };
        });
        await page.goto('http://127.0.0.1:' + server.address().port + '/templates/threat.html');
        await page.waitForFunction(() => !document.getElementById('threat_block').disabled);
        const check = async (name, fn) => { await fn(); checks += 1; console.log('PASS ' + name); };
        const enabled = () => page.waitForFunction(() => !document.getElementById('threat_block').disabled, null, { timeout: 7500 });
        await check('hung decision times out without automatic resubmission', async () => {
            await page.locator('#threat_allow').click();
            assert.equal(await page.locator('#threat_block').isDisabled(), true);
            await enabled();
            assert.match(await page.locator('#threat_status').textContent(), /响应超时/);
            assert.deepEqual(await page.evaluate(() => window.f.calls), [{ id: 'first', choice: 'allow' }]);
            await page.evaluate(() => { window.f.mode = 'normal'; });
            await page.locator('#threat_block').click();
            await enabled();
            assert.equal(await page.evaluate(() => window.f.calls.length), 2);
        });
        await check('committed action with delayed acknowledgement recovers next event', async () => {
            await page.evaluate(() => { window.f.mode = 'advance'; });
            await page.locator('#threat_block').click();
            await page.waitForFunction(() => document.getElementById('threat_title').textContent === 'next', null, { timeout: 7500 });
            await enabled();
            assert.doesNotMatch(await page.locator('#threat_status').textContent(), /响应超时/);
            assert.equal(await page.evaluate(() => window.f.calls.length), 3);
            // A late success from an older action must not unlock a new in-flight action.
            await page.evaluate(() => { window.f.mode = 'hang'; });
            await page.locator('#threat_block').click();
            await page.evaluate(async () => { window.f.held[0].resolve(true); await new Promise(r => setTimeout(r, 50)); });
            assert.equal(await page.locator('#threat_block').isDisabled(), true);
            await page.evaluate(() => { window.f.held.at(-1).resolve(true); });
            await enabled();
        });
        await check('false-positive submit recovers but never auto-allows', async () => {
            await page.locator('#threat_fp').click();
            await page.locator('#threat_fp_submit').click();
            await enabled();
            assert.match(await page.locator('#threat_status').textContent(), /响应超时/);
            assert.equal(await page.evaluate(() => window.f.reports.length), 1);
            assert.equal(await page.evaluate(() => window.f.calls.filter(x => x.choice === 'allow').length), 1);
        });
        await check('expired snapshot is single-flight and discarded on recovery', async () => {
            await page.evaluate(() => { window.f.holdSnapshot = true; });
            await page.waitForFunction(() => window.f.snapshotHeld !== null);
            const calls = await page.evaluate(() => window.f.snapshots);
            await page.waitForFunction(() => document.getElementById('threat_status').textContent.includes('数据暂不可用'), null, { timeout: 7500 });
            assert.equal(await page.locator('#threat_block').isDisabled(), true);
            await page.waitForTimeout(850); // several polling opportunities; none may add a native call
            assert.equal(await page.evaluate(() => window.f.snapshots), calls);
            await page.evaluate(() => {
                window.f.data.id = window.f.data.title = 'fresh-after-stall';
                window.f.holdSnapshot = false; window.f.snapshotHeld.resolve();
            });
            await page.waitForFunction(() => document.getElementById('threat_title').textContent === 'fresh-after-stall');
            await enabled();
        });
        await check('page teardown cancels waits; late failures cannot clear restored view', async () => {
            await page.locator('#threat_allow').click();
            await page.evaluate(() => {
                window.dispatchEvent(new Event('pagehide'));
                window.f.data.id = window.f.data.title = 'restored';
                window.dispatchEvent(new Event('pageshow'));
            });
            await page.waitForFunction(() => document.getElementById('threat_title').textContent === 'restored');
            await enabled();
            await page.evaluate(async () => {
                window.f.held.at(-1).reject(new Error('late old request'));
                await new Promise(r => setTimeout(r, 50));
            });
            assert.equal(await page.locator('#threat_title').textContent(), 'restored');
            assert.equal(await page.locator('#threat_block').isDisabled(), false);
        });
        await check('server-side persistence remains guarded after client timeout', async () => {
            const before = await page.evaluate(() => window.f.calls.length);
            await page.evaluate(() => { window.f.mode = 'persist'; });
            await page.locator('#threat_block').click();
            await page.waitForFunction(() => document.getElementById('threat_status').textContent.includes('正在处理'), null, { timeout: 7500 });
            assert.equal(await page.locator('#threat_block').isDisabled(), true);
            assert.equal(await page.locator('#threat_allow').isDisabled(), true);
            assert.equal(await page.evaluate(() => window.f.calls.length), before + 1);
            await page.evaluate(() => { window.f.data.resolving = false; window.f.held.at(-1).resolve(true); });
            await enabled();
        });
        await check('new action cannot reuse a pre-decision snapshot', async () => {
            await page.evaluate(() => {
                window.f.mode = 'normal-advance'; window.f.snapshotHeld = null; window.f.holdSnapshot = true;
                window.titleHistory = [];
                new MutationObserver(() => window.titleHistory.push(document.getElementById('threat_title').textContent))
                    .observe(document.getElementById('threat_title'), { childList: true, subtree: true, characterData: true });
            });
            await page.waitForFunction(() => window.f.snapshotHeld !== null);
            await page.locator('#threat_block').click();
            await page.waitForFunction(() => window.f.data.id === 'normal-next');
            await page.evaluate(() => { window.f.holdSnapshot = false; window.f.snapshotHeld.resolve(); });
            await page.waitForFunction(() => document.getElementById('threat_title').textContent === 'normal-next');
            await enabled();
            assert.equal(await page.evaluate(() => window.titleHistory.includes('restored')), false);
            assert.deepEqual(errors, []);
        });
        console.log('SUMMARY checks=' + checks + ' failures=0');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
