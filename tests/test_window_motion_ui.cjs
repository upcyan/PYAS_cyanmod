/* 窗口动画回归(2026-10-19):
   本机系统动画是关的(ClientAreaAnimation=False),无边框窗口的最大化/最小化
   原本是「啪」地硬切。现在改成:CSS 给标题栏 + 内容区一段落定动画,
   最小化还要等这段动画走完再真正收窗,否则内容直接消失、动画等于没做。

   断言的是三件容易回退的事:
     1. 点最小化 → 先挂 win-anim-shrink,延迟后才调 native minimize;
     2. 点最大化 → 图标先同步,再挂 win-anim-grow;
     3. 两段动画都挂在两个顶层容器上(不是整个 .app-container:
        它有 opacity:1 !important,动画压不过)
*/
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

(async () => {
    const root = path.resolve(__dirname, '../Interface');
    const server = http.createServer((req, res) => {
        const file = path.resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
        if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
            res.writeHead(404); res.end(); return;
        }
        res.setHeader('Content-Type', { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' }[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${server.address().port}/templates/index.html`;
    let browser;
    const errors = [];

    try {
        browser = await chromium.launch({
            executablePath: process.env.EDGE_EXECUTABLE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
            headless: true,
        });
        const page = await browser.newPage({ viewport: { width: 1100, height: 760 } });
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript(() => {
            window.__calls = [];
            window.__bridge = [];
            window.pywebview = {
                // 拖动合并器的落点:main.js 会在 DOMContentLoaded 时把它包一层,
                // 这里先放一个记录器,替身要跑在 main.js 之前才拦得到
                _jsApiCallback: (name, params) => { window.__bridge.push([name, params]); },
                api: {
                get_config: async () => ({
                    first_launch: false, language: 'simplified_switch', theme: 'white_switch',
                    version: 'test', interactive_timeout: 30, ai_provider_mode: 'local',
                    ai_model: '', ai_base_url: '', ai_assist_switch: false, ai_delay_switch: true,
                    ai_delay_seconds: 3, ai_auto_execute: false,
                    process_switch: true, document_switch: true, system_switch: true,
                    network_switch: true, driver_switch: true,
                    driver_alert_exempt: true, driver_home_hidden: false,
                }),
                init_ui_ready: async () => true,
                report_ui_error: async () => true,
                get_pending_threat_count: async () => 0,
                get_pending_threat_queue: async () => ({ count: 0, events: [] }),
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [],
                get_policy_status: async () => ({ state: 'ready', initialized: true }),
                show_confirm: async () => true,
                show_alert: async () => true,
                update_config: async (key, value) => value,
                minimize: () => { window.__calls.push({ kind: 'minimize', at: performance.now() }); },
                toggle_maximize: async () => { window.__calls.push({ kind: 'maximize', at: performance.now() }); return true; },
            } };
        });
        await page.goto(url);
        await page.waitForFunction(() => document.querySelector('.app-container')?.classList.contains('fade-in'));

        // ---- 最小化:先动画,后收窗 ----
        const clickAt = await page.evaluate(() => {
            const start = performance.now();
            document.getElementById('minimize_button').click();
            return start;
        });
        assert.equal(await page.evaluate(() => document.querySelector('.app-container').classList.contains('win-anim-shrink')), true,
            '最小化必须立刻挂上 win-anim-shrink');
        assert.equal(await page.evaluate(() => window.__calls.length), 0,
            '动画期间不能已经收窗,否则用户看不到过渡');
        await page.waitForTimeout(400);
        const calls = await page.evaluate(() => window.__calls);
        assert.equal(calls.length, 1, '最小化应只调用一次 native minimize');
        assert.equal(calls[0].kind, 'minimize', '先动画后收窗,调用的应是 minimize');
        assert.ok(calls[0].at - clickAt >= 120, `收窗要等动画走完,实际只等了 ${Math.round(calls[0].at - clickAt)}ms`);
        assert.equal(await page.evaluate(() => document.querySelector('.app-container').classList.contains('win-anim-shrink')), false,
            '动画结束后类要摘掉,否则下次点不重播');

        // ---- 最大化:图标同步 + 落定动画 ----
        await page.click('#maximize_button');
        await page.waitForFunction(() => document.querySelector('.app-container').classList.contains('win-anim-grow'));
        assert.equal(await page.evaluate(() => document.getElementById('icon_restore').classList.contains('hidden')), false,
            '最大化后应切到还原图标');
        const anims = await page.evaluate(() => {
            const header = getComputedStyle(document.querySelector('.navigate-window')).animationName;
            const main = getComputedStyle(document.querySelector('.main-layout')).animationName;
            return { header, main };
        });
        assert.equal(anims.header, 'win-surface-grow', '标题栏要参与落定动画');
        assert.equal(anims.main, 'win-surface-grow', '内容区要参与落定动画');

        // ---- 拖动:保留 pywebview 的拖动区(原生 WM_NCLBUTTONDOWN 在 WebView2 上拖不动,已回退),
        //      但把每个 mousemove 一次的过桥压成每帧最多一次 ----
        assert.equal(await page.locator('.pywebview-drag-region').count(), 2,
            '标题栏与侧栏必须仍是拖动区,否则窗口拖不动');
        const burst = await page.evaluate(async () => {
            window.__bridge.length = 0;
            for (let i = 0; i < 5; i += 1) {
                window.pywebview._jsApiCallback('pywebviewMoveWindow', [i, i], 'move');
            }
            const beforeFrame = window.__bridge.length;
            window.pywebview._jsApiCallback('pywebviewStateUpdate', { key: 'x' }, 'state');
            const afterOther = window.__bridge.length;
            await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
            return { beforeFrame, afterOther, after: window.__bridge.slice() };
        });
        assert.equal(burst.beforeFrame, 0, '同一帧内的连发不能在帧前就过桥');
        assert.equal(burst.afterOther, 1, '非拖动回调要立刻过桥,不能一起排队');
        const moves = burst.after.filter(([name]) => name === 'pywebviewMoveWindow');
        assert.equal(moves.length, 1, '一帧只应发一次拖动 IPC');
        assert.deepEqual(moves[0][1], [4, 4], '要发最后一帧的位置,不是最早那个');

        assert.deepEqual(errors, []);
        console.log('Window motion UI: PASS (最小化先动画后收窗 / 最大化落定动画 + 图标同步 / 拖动每帧一次过桥)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
