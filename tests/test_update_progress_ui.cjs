/* Real Chromium update protocol/animation tests. No native installer is executed. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
(async () => {
    const root = path.resolve(__dirname, '../Interface');
    const server = http.createServer((req, res) => {
        const file = path.resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
        if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); res.end(); return; }
        res.setHeader('Content-Type', { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' }[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    let browser, checks = 0;
    try {
        browser = await chromium.launch({ headless: true, executablePath: process.env.EDGE_EXECUTABLE ||
            (process.platform === 'win32' ? 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe' : undefined) });
        const page = await browser.newPage({ viewport: { width: 900, height: 760 }, reducedMotion: 'no-preference' });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript(() => {
            const asset = (version, letter) => ({ name: 'PYAS_Setup_v' + version + '.exe', version: 'v' + version,
                url: 'https://github.com/upcyan/PYAS_cyanmod/releases/download/v' + version + '/PYAS_Setup_v' + version + '.exe',
                size: 100, digest: 'sha256:' + '0'.repeat(64), asset_id: letter.repeat(64) });
            const make = (selected, id, revision, phase, extra = {}) => ({ asset_id: selected.asset_id, asset_url: selected.url,
                file_name: selected.name, version: selected.version, download_id: id, revision, phase,
                downloading: ['downloading', 'verifying'].includes(phase), installing: ['installing', 'install_unknown'].includes(phase),
                received: 0, total: 100, percent: 0, result: null, ...extra });
            const old = asset('1', 'a');
            const selected = asset('2', 'b');
            window.f = { selected, asset, make, checks: 0, downloads: [], installs: [], alerts: [],
                checkMode: 'normal', downloadMode: 'normal', installMode: 'hang',
                state: make(old, 'a'.repeat(32), 4, 'ready', { percent: 100,
                    result: { success: true, path: 'C:/Downloads/PYAS_Setup_v1.exe', size: 100 } }) };
            window.f.send = changes => {
                window.f.state = { ...window.f.state, revision: window.f.state.revision + 1, ...changes };
                window.updateDownloadState(JSON.parse(JSON.stringify(window.f.state)));
            };
            window.pywebview = { api: {
                get_config: async () => ({ first_launch: false, language: 'simplified_switch', theme: 'white_switch', version: '3.7.1-9', interactive_timeout: 30 }),
                init_ui_ready: async () => true, report_ui_error: async () => true, get_pending_threat_count: async () => 0,
                check_update: async () => {
                    window.f.checks++;
                    if (window.f.checkMode === 'reject') throw new Error('fixture rejected check');
                    if (window.f.checkMode === 'hang') return new Promise((resolve, reject) => { window.f.checkHold = { resolve, reject }; });
                    return { has_update: true, current: '3.7.1-9', latest: window.f.selected.version,
                        asset: window.f.selected, url: 'https://github.com/upcyan/PYAS_cyanmod/releases', body: 'fixture notes' };
                },
                get_update_download_state: async () => JSON.parse(JSON.stringify(window.f.state)),
                download_update: async (url, name, id) => {
                    window.f.downloads.push({ url, name, id });
                    window.f.state = make(window.f.selected, id, 0, 'downloading');
                    const response = { success: true, started: true, state: JSON.parse(JSON.stringify(window.f.state)) };
                    if (window.f.downloadMode === 'delayed-start-failure') {
                        window.f.send({ phase: 'failed', downloading: false, result: { success: false, error: 'old worker failed' } });
                        const failed = { success: false, error: 'old worker failed', state: JSON.parse(JSON.stringify(window.f.state)) };
                        return new Promise(resolve => { window.f.startFailureAck = () => resolve(failed); });
                    }
                    if (window.f.downloadMode === 'reject-after-start') throw new Error('acknowledgement lost');
                    if (window.f.downloadMode === 'hang') return new Promise(resolve => { window.f.downloadHold = () => resolve(response); });
                    return response;
                },
                run_update_installer: async (file, id) => {
                    window.f.installs.push({ file, id });
                    window.f.send({ phase: 'installing', downloading: false, installing: true });
                    if (window.f.installMode === 'hang') return new Promise(resolve => { window.f.installHold = resolve; });
                    return true;
                },
                show_alert: async (...args) => { window.f.alerts.push(args); return true; },
            } };
        });
        await page.goto('http://127.0.0.1:' + server.address().port + '/templates/index.html');
        await page.waitForFunction(() => typeof window.updateDownloadState === 'function');
        const check = async (name, fn) => { await fn(); checks++; console.log('PASS ' + name); };
        const track = page.locator('#update_progress_track');
        const remaining = page.locator('#update_progress_remaining');
        const animation = () => remaining.evaluate(el => getComputedStyle(el, '::after').animationName);
        const open = async () => {
            await page.locator('#quick_update_btn').click();
            await page.waitForFunction(() => !document.getElementById('update_modal').classList.contains('hidden')
                && !document.getElementById('quick_update_btn').hasAttribute('aria-busy'));
        };
        const start = async () => {
            const before = await page.evaluate(() => window.f.downloads.length);
            await page.locator('#update_download_btn').click();
            await page.waitForFunction(n => window.f.downloads.length > n, before);
        };
        await open();
        await check('new version never restores a previous asset installer', async () => {
            assert.match(await page.locator('#update_modal_version').textContent(), /v2/);
            assert.equal(await page.locator('#update_install_btn').isVisible(), false);
            assert.equal(await page.evaluate(() => window.f.installs.length), 0);
        });
        await start();
        await check('40 percent sweep is confined to the remaining 40-to-100 track', async () => {
            await page.evaluate(() => window.f.send({ percent: 40, received: 40, total: 100 }));
            await page.waitForFunction(() => {
                const track = document.getElementById('update_progress_track').getBoundingClientRect();
                const rest = document.getElementById('update_progress_remaining').getBoundingClientRect();
                return Math.abs((rest.left - track.left) / track.width - .4) < .005;
            });
            const shape = await remaining.evaluate(el => {
                const rest = el.getBoundingClientRect(), parent = el.parentElement.getBoundingClientRect();
                return [(rest.left - parent.left) / parent.width, (rest.right - parent.left) / parent.width];
            });
            assert.ok(Math.abs(shape[0] - .4) < .005 && Math.abs(shape[1] - 1) < .005);
            assert.equal(await track.getAttribute('aria-valuenow'), '40');
            const before = await remaining.evaluate(el => getComputedStyle(el, '::after').transform);
            await page.waitForFunction(before => getComputedStyle(document.getElementById('update_progress_remaining'), '::after').transform !== before, before);
        });
        await check('100 percent stops motion without a success callback', async () => {
            await page.evaluate(() => window.f.send({ percent: 100, received: 100 }));
            assert.equal(await animation(), 'none');
            assert.equal(await track.getAttribute('aria-valuenow'), '100');
            assert.equal(await page.locator('#update_progress_text').textContent(), '100%');
        });
        await check('older revisions and other job IDs cannot revive stale UI', async () => {
            await page.evaluate(() => {
                window.updateDownloadState({ ...window.f.state, revision: 0, percent: 5 });
                window.updateDownloadState({ ...window.f.state, download_id: 'f'.repeat(32), revision: 500, phase: 'ready',
                    result: { success: true, path: 'C:/Downloads/old.exe' } });
            });
            assert.equal(await page.locator('#update_progress_text').textContent(), '100%');
            assert.equal(await page.locator('#update_install_btn').isVisible(), false);
        });
        await check('failure clears motion, permits retry and ignores old completion', async () => {
            await page.evaluate(() => { window.f.oldJob = { ...window.f.state }; window.f.send({ phase: 'failed', downloading: false,
                result: { success: false, error: 'fixture failure' } }); });
            assert.equal(await animation(), 'none');
            assert.equal(await page.locator('#update_download_btn').isEnabled(), true);
            await start();
            await page.evaluate(() => window.updateDownloadState({ ...window.f.oldJob, revision: 800, phase: 'ready',
                result: { success: true, path: 'C:/Downloads/old.exe' } }));
            assert.equal(await page.locator('#update_install_btn').isVisible(), false);
            assert.equal(await page.locator('#update_modal_progress').isVisible(), true);
        });
        await check('late start failure acknowledgement cannot overwrite a retry', async () => {
            await page.evaluate(() => {
                window.f.send({ phase: 'failed', downloading: false, result: { success: false, error: 'fixture retry' } });
                window.f.downloadMode = 'delayed-start-failure';
            });
            await start();
            await page.waitForFunction(() => !document.getElementById('update_download_btn').disabled);
            await page.evaluate(() => { window.f.downloadMode = 'normal'; });
            await start();
            const before = await page.evaluate(() => window.f.alerts.length);
            await page.evaluate(() => window.f.startFailureAck());
            await page.waitForTimeout(80);
            assert.equal(await page.locator('#update_download_btn').isDisabled(), true);
            assert.equal(await page.evaluate(() => window.f.alerts.length), before);
            assert.notEqual(await animation(), 'none');
        });
        await check('unknown total is indeterminate rather than fabricated 35 percent', async () => {
            await page.evaluate(() => window.f.send({ percent: -1, total: 0, received: 1234 }));
            assert.equal(await track.getAttribute('aria-valuenow'), null);
            assert.match(await track.getAttribute('aria-valuetext'), /总大小未知/);
            assert.equal(await page.locator('#update_progress_fill').evaluate(el => el.style.width), '0%');
            assert.notEqual(await animation(), 'none');
        });
        await check('reduced motion, close and same-job reopen have correct animation state', async () => {
            await page.emulateMedia({ reducedMotion: 'reduce' }); assert.equal(await animation(), 'none');
            await page.emulateMedia({ reducedMotion: 'no-preference' });
            await page.locator('#update_close_btn').click(); assert.equal(await animation(), 'none');
            await open(); assert.notEqual(await animation(), 'none');
            assert.equal(await track.getAttribute('aria-valuenow'), null);
        });
        await check('asset change hides the previous verified installer', async () => {
            await page.evaluate(() => window.f.send({ phase: 'ready', downloading: false, percent: 100,
                result: { success: true, path: 'C:/Downloads/PYAS_Setup_v2.exe', size: 100 } }));
            assert.equal(await page.locator('#update_install_btn').isEnabled(), true);
            await page.locator('#update_close_btn').click();
            await page.evaluate(() => { window.f.selected = window.f.asset('3', 'c'); });
            await open();
            assert.equal(await page.locator('#update_install_btn').isVisible(), false);
            assert.match(await page.locator('#update_modal_version').textContent(), /v3/);
        });
        await check('check rejection is visible and duplicate checks are suppressed', async () => {
            await page.locator('#update_close_btn').click();
            const before = await page.evaluate(() => window.f.alerts.length);
            await page.evaluate(() => { window.f.checkMode = 'reject'; });
            await page.locator('#quick_update_btn').click();
            await page.waitForFunction(n => window.f.alerts.length > n, before);
            assert.deepEqual(errors, []);
            await page.waitForFunction(() => !document.getElementById('quick_update_btn').hasAttribute('aria-busy'));
            const calls = await page.evaluate(() => window.f.checks);
            await page.evaluate(() => { window.f.checkMode = 'hang'; });
            await page.locator('#quick_update_btn').click();
            await page.evaluate(() => document.getElementById('quick_update_btn').click());
            assert.equal(await page.evaluate(() => window.f.checks), calls + 1);
            await page.evaluate(() => { window.f.checkHold.reject(new Error('fixture check failed')); window.f.checkMode = 'normal'; });
            await page.waitForFunction(() => !document.getElementById('quick_update_btn').hasAttribute('aria-busy'));
        });
        await open();
        await check('lost start acknowledgement restores server job without repeating download', async () => {
            await page.evaluate(() => { window.f.downloadMode = 'reject-after-start'; });
            const before = await page.evaluate(() => window.f.downloads.length);
            await start();
            await page.waitForFunction(() => document.getElementById('update_progress_track').classList.contains('is-downloading'));
            assert.equal(await page.evaluate(() => window.f.downloads.length), before + 1);
            assert.equal(await page.locator('#update_download_btn').isDisabled(), true);
        });
        await check('install timeout keeps pending state and never launches twice', async () => {
            await page.evaluate(() => window.f.send({ phase: 'ready', downloading: false, percent: 100,
                result: { success: true, path: 'C:/Downloads/PYAS_Setup_v3.exe', size: 100 } }));
            await page.locator('#update_install_btn').click();
            await page.waitForFunction(() => document.getElementById('update_modal_status').textContent.includes('无法确认'), null, { timeout: 7500 });
            assert.equal(await page.evaluate(() => window.f.installs.length), 1);
            assert.equal(await page.locator('#update_install_btn').isDisabled(), true);
            await page.evaluate(() => { window.f.send({ phase: 'installer_finished', installing: false }); window.f.installHold(true); });
            await page.waitForTimeout(50);
            assert.equal(await page.locator('#update_modal').isVisible(), true, 'late response cannot close a newer view');
            assert.equal(await page.locator('#update_install_btn').isVisible(), false);
            assert.deepEqual(errors, []);
        });
        console.log('SUMMARY checks=' + checks + ' failures=0');
    } finally { if (browser) await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => { console.error(error); process.exitCode = 1; });
