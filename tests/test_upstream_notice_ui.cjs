/* 上游跟进提示 UI 测试(Playwright + 本机 Edge)
   覆盖:开发者模式(后端带回 upstream)时弹窗出现上游提示、标题改为「上游有新版本」、
        没自身更新时不给下载按钮只给上游发布页;普通模式(后端不带 upstream)完全不出现,
        且没有自身更新时仍走「已是最新版本」提示。
   用法: NODE_PATH=<node_modules> node tests/test_upstream_notice_ui.cjs [screenshot_dir] */
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

(async () => {
    const root = path.resolve(__dirname, '../Interface');
    const server = http.createServer((req, res) => {
        const file = path.resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
        if (!file.startsWith(root + path.sep) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
        const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' };
        res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const shotDir = process.argv[2] || '';

    let browser;
    try {
        browser = await chromium.launch({
            executablePath: process.env.EDGE_EXECUTABLE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
            headless: true,
        });
        const page = await browser.newPage({ viewport: { width: 1024, height: 720 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error).slice(0, 200)));
        await page.addInitScript(() => {
            const cfg = {
                first_launch: false, language: 'simplified_switch', theme: 'white_switch',
                version: '3.7.0-24', interactive_timeout: 30, ai_provider_mode: 'local',
                ai_model: '', ai_base_url: '', ai_assist_switch: false,
                ai_delay_switch: true, ai_delay_seconds: 3, ai_auto_execute: false,
                dev_channel: true,
            };
            window.__updatePayload = null;
            window.__alerts = [];
            window.__openedUrls = [];
            window.pywebview = { api: {
                get_config: async () => cfg, init_ui_ready: async () => true,
                report_ui_error: async () => true, get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [], show_confirm: async () => true,
                show_alert: async (title, text) => { window.__alerts.push(`${title}|${text}`); return true; },
                check_update: async () => window.__updatePayload,
                get_update_download_state: async () => null,
                open_url: async (url) => { window.__openedUrls.push(url); return true; },
                update_config: async (key, value) => value,
            } };
        });

        await page.goto(`${base}/templates/index.html`, { timeout: 20000 });
        await page.waitForFunction(() => document.querySelector('.app-container')?.classList.contains('fade-in'), null, { timeout: 15000 });

        // 开发者模式:主界面版本号后挂「开发者模式」标识
        assert.equal(await page.evaluate(() => document.getElementById('title_dev_badge')?.classList.contains('hidden')),
            false, '开发者模式下版本号后应出现开发者模式标识');
        assert.equal((await page.textContent('#title_dev_badge')).trim(), '开发者模式', '标识文案应来自 i18n');

        // 用 checkVisibility:它连带祖先的 display/visibility 一起算,
        // 只看自身样式会把「藏在已关闭弹窗里的元素」判成可见
        const visible = async (sel) => page.evaluate((s) => {
            const el = document.querySelector(s);
            if (!el || el.classList.contains('hidden')) return false;
            return el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true });
        }, sel);

        const triggerCheck = async (payload) => {
            await page.evaluate((p) => { window.__updatePayload = p; window.__alerts = []; }, payload);
            await page.click('#quick_update_btn');
            await page.waitForTimeout(320);
        };

        const upstreamPayload = {
            has_update: false, current: '3.7.0-24', latest: '3.7.0-24',
            // 真实后端在「自身已是最新」时也会带回最新版安装包,下载按钮必须据此隐藏
            body: 'cyanmod notes', published_at: '2026-10-05',
            asset: { name: 'PYAS_Setup_v3.7.0-24.exe', url: 'https://github.com/upcyan/PYAS_cyanmod/releases/download/v3.7.0-24/PYAS_Setup_v3.7.0-24.exe', size: 1024 },
            upstream: {
                supported: true, has_update: true, repository: '87owo/PYAS',
                tracked: '3.7.0', latest: 'v3.7.1',
                url: 'https://github.com/87owo/PYAS/releases', body: 'upstream notes', published_at: '2026-10-01',
            },
        };

        // 1. 开发者模式 + 只有上游更新:弹窗只提示跟进上游
        await triggerCheck(upstreamPayload);
        assert.equal(await visible('#update_modal'), true, '有上游更新时必须弹出提示');
        assert.equal(await visible('#update_modal_upstream'), true, '上游提示块必须出现');
        const text = await page.textContent('#update_modal_upstream');
        assert.ok(text.includes('v3.7.1'), `上游版本应出现在提示里,实际: ${text}`);
        assert.ok(text.includes('3.7.0'), `当前跟进版本应出现在提示里,实际: ${text}`);
        assert.equal(await page.textContent('#update_modal_title'), '上游有新版本', '标题应切换为上游提示');
        assert.equal(await visible('#update_download_btn'), false, '没有自身更新时不应出现下载按钮');
        assert.equal(await visible('#update_modal_asset'), false, '没有自身更新时不应展示本仓库安装包信息');
        assert.equal(await visible('#update_install_btn'), false, '没有自身更新时不应出现安装按钮');
        assert.equal(await visible('#update_page_btn'), false, '自身没有发布页可去时该按钮应隐藏');
        assert.equal(await visible('#update_upstream_btn'), true, '必须给出上游发布页入口');
        assert.equal(await page.getAttribute('#update_upstream_btn', 'data-url'), upstreamPayload.upstream.url,
            '上游按钮要指向上游发布页');
        const upstreamChangelog = await page.textContent('#update_modal_changelog');
        assert.ok(upstreamChangelog.includes('upstream notes'), `更新日志应展示上游内容,实际: ${upstreamChangelog}`);
        assert.ok(!upstreamChangelog.includes('cyanmod notes'), `不应残留本仓库的旧日志,实际: ${upstreamChangelog}`);
        assert.deepEqual(await page.evaluate(() => window.__alerts), [], '有上游更新时不应只弹「已是最新」');
        if (shotDir) {
            fs.mkdirSync(shotDir, { recursive: true });
            await page.screenshot({ path: path.join(shotDir, 'upstream-notice-dev.png') });
        }

        // 上游按钮点击后打开上游发布页
        await page.click('#update_upstream_btn');
        await page.waitForTimeout(120);
        assert.deepEqual(await page.evaluate(() => window.__openedUrls), [upstreamPayload.upstream.url],
            '点击上游按钮应打开上游发布页');

        // 2. 自身也有更新 + 上游也有:同一弹窗里给两件事
        await page.click('#update_close_btn');
        await triggerCheck({
            has_update: true, current: '3.7.0-24', latest: 'v9.0.0-1', url: 'https://github.com/upcyan/PYAS_cyanmod/releases',
            asset: { name: 'PYAS_Setup_v9.0.0-1.exe', url: 'https://github.com/upcyan/PYAS_cyanmod/releases/download/v9.0.0-1/PYAS_Setup_v9.0.0-1.exe', size: 1024 },
            body: 'cyanmod notes', published_at: '2026-10-12',
            upstream: upstreamPayload.upstream,
        });
        assert.equal(await visible('#update_modal_upstream'), true, '自身更新与上游提示应同时出现');
        assert.equal(await page.textContent('#update_modal_title'), '发现新版本', '自身有更新时标题保持「发现新版本」');
        assert.equal(await visible('#update_download_btn'), true, '自身有更新时保留下载按钮');
        assert.equal(await visible('#update_page_btn'), true, '自身有更新时应给出本仓库发布页');
        assert.equal(await visible('#update_upstream_btn'), true, '上游按钮同时可见');
        const bothChangelog = await page.textContent('#update_modal_changelog');
        assert.ok(bothChangelog.includes('cyanmod notes'), `自身有更新时日志应展示本仓库内容,实际: ${bothChangelog}`);
        assert.ok(!bothChangelog.includes('upstream notes'), `此时不该把上游日志顶到前面,实际: ${bothChangelog}`);

        // 3. 普通模式:后端不带 upstream 字段 —— 上游提示整块不出现
        await page.click('#update_close_btn');
        await triggerCheck({ has_update: false, current: '3.7.0-24', latest: '3.7.0-24' });
        assert.equal(await visible('#update_modal'), false, '普通模式没有更新时不应弹窗');
        assert.equal(await visible('#update_modal_upstream'), false, '普通模式不应出现上游提示块');
        const alerts = await page.evaluate(() => window.__alerts);
        assert.equal(alerts.length, 1, `普通模式应回落到「已是最新」提示,实际: ${JSON.stringify(alerts)}`);
        assert.ok(alerts[0].includes('3.7.0-24'), `提示应带当前版本,实际: ${alerts[0]}`);

        assert.deepEqual(errors, [], `页面不应有 JS 错误: ${errors.join(' | ')}`);
        console.log('上游跟进提示 UI: PASS (开发者模式提示上游/自身+上游并存/普通模式不出现/上游入口可点)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch((error) => {
    console.error('上游跟进提示 UI: FAIL', error.message);
    process.exit(1);
});
