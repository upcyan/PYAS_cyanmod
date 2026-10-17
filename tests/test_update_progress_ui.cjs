/* Live Chromium check: shimmer runs during download and stops at 100%. */
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
        const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' };
        res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    let browser;
    try {
        browser = await chromium.launch({ headless: true, executablePath: process.env.EDGE_EXECUTABLE });
        const page = await browser.newPage({ viewport: { width: 720, height: 620 } });
        const errors = [];
        page.on('pageerror', e => errors.push(String(e)));
        await page.addInitScript(() => {
            window.progressCalls = [];
            window.progressPayload = { percent: 40 };
            window.pywebview = { api: {
                get_config: async () => ({ first_launch: false, language: 'simplified_switch', theme: 'white_switch', interactive_timeout: 30 }),
                init_ui_ready: async () => true, report_ui_error: async () => true,
                get_update_download_state: async () => ({ downloading: true, progress: window.progressPayload, result: null }),
            } };
            Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
        });
        await page.goto('http://127.0.0.1:' + server.address().port + '/templates/index.html');
        const fill = page.locator('#update_progress_fill');
        const check = async (name, fn) => { await fn(); console.log('PASS ' + name); };
        const state = () => fill.evaluate(el => {
            const s = getComputedStyle(el, '::after');
            return { anim: s.animationName, content: s.content, width: el.style.width, text: document.getElementById('update_progress_text').textContent, cls: el.className };
        });
        await check('shimmer animates while progress below 100%', async () => {
            await page.evaluate(() => window.updateDownloadProgress(window.progressPayload));
            const s = await state();
            assert.equal(s.anim, 'progress-shimmer'); assert.equal(s.width, '40%'); assert.equal(s.text, '40%');
            const before = await fill.evaluate(() => getComputedStyle(document.getElementById('update_progress_fill'), '::before').transform);
            await page.waitForFunction(prev => {
                const s = getComputedStyle(document.getElementById('update_progress_fill'), '::after');
                return s.animationName === 'progress-shimmer' && s.animationPlayState === 'running';
            }, before);
        });
        await check('animation stops once progress reaches 100%', async () => {
            await page.evaluate(() => window.updateDownloadProgress({ percent: 100 }));
            await page.evaluate(() => window.updateDownloadFinished({ success: true, path: 'C:/fixture/setup.exe' }));
            const s = await state();
            assert.equal(s.cls.includes('is-complete'), true);
            assert.equal(s.content, 'none');
            assert.equal(s.width, '100%'); assert.equal(s.text, '100%');
        });
        await check('failed download also clears the animation', async () => {
            await page.evaluate(() => { window.updateDownloadProgress({ percent: 60 }); });
            await page.evaluate(() => window.updateDownloadFinished({ success: false, error: 'fixture network error' }));
            const s = await state();
            assert.ok(s.content === 'none' || s.content === '""', 'content: ' + s.content);
        });
        await check('resume download restarts the animation', async () => {
            await page.evaluate(() => { window.updateDownloadProgress({ percent: 30 }); });
            const s = await state();
            assert.equal(s.anim, 'progress-shimmer'); assert.equal(s.width, '30%');
            assert.deepEqual(errors, []);
        });
        console.log('SUMMARY checks=4 failures=0');
    } finally { if (browser) await browser.close(); await new Promise(r => server.close(r)); }
})().catch(e => { console.error(e); process.exitCode = 1; });
