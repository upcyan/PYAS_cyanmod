/* Run with Playwright available: node tests/test_pending_threats_ui.cjs [screenshot-dir]
   回归:待处理告警筛选必须展示当前弹窗队列,而非空白(曾因缺 data-filter 导致 homeLogFilter=undefined)。 */
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

(async () => {
    const root = path.resolve(__dirname, '../Interface');
    const server = http.createServer((req, res) => {
        const file = path.resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
        if (!file.startsWith(root + path.sep) || !fs.existsSync(file)) {
            res.writeHead(404); res.end(); return;
        }
        const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' };
        res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    let browser;
    try {
        browser = await chromium.launch({
            executablePath: process.env.EDGE_EXECUTABLE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
            headless: true,
        });
        const page = await browser.newPage({ viewport: { width: 1024, height: 768 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript(() => {
            // 队列桩:3 组(网络防护×2 处理中 / 文件防护×1 / 进程防护×1),可整体清空
            window.pendingTest = {
                count: 4,
                opened: 0,
                queue: () => ({
                    count: window.pendingTest.count,
                    events: window.pendingTest.count === 0 ? [] : [
                        { id: 'net', title: '网络防护', count: 2, active: true },
                        { id: 'file', title: '文件防护', count: 1, active: false },
                        { id: 'proc', title: '进程防护', count: 1, active: false },
                    ],
                }),
            };
            const cfg = { first_launch: false, language: 'simplified_switch', theme: 'white_switch', version: 'test', interactive_timeout: 30 };
            window.pywebview = { api: {
                get_config: async () => cfg,
                init_ui_ready: async () => true,
                report_ui_error: async () => true,
                get_pending_threat_count: async () => window.pendingTest.count,
                get_pending_threat_queue: async () => window.pendingTest.queue(),
                show_pending_threats: async () => { window.pendingTest.opened += 1; return true; },
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [
                    { id: 'l1', time_str: '2026-10-12 10:00:00', level: 'INFO', action: 'System', source: 'UI test', detail: '日志一' },
                    { id: 'l2', time_str: '2026-10-12 10:01:00', level: 'BLOCK', action: 'File Block', source: 'C:\\demo\\a.exe', detail: '日志二' },
                ],
                show_confirm: async () => true,
                show_alert: async () => true,
                update_config: async (key, value) => { cfg[key] = value; return value; },
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`);
        await page.waitForFunction(() => document.querySelector('.app-container').classList.contains('fade-in'));

        const chip = page.locator('#pending_threats_btn');
        // 1. 有待处理时 chip 可见且徽标为总数(4 = 2+1+1)
        await page.waitForFunction(() => !document.getElementById('pending_threats_btn').classList.contains('hidden'));
        assert.equal(await page.locator('#pending_threats_count').textContent(), '4');

        // 2. 点击 chip:日志区必须渲染队列,而不是空白
        await chip.click();
        await page.waitForFunction(() => document.querySelectorAll('#home_log_list .home-log-item.lv-PENDING').length === 3);
        assert.equal(await chip.getAttribute('data-filter'), 'pending', 'chip must be a real filter');
        assert.equal(await page.locator('#home_log_list .home-log-item.lv-PENDING.is-active').count(), 1, 'exactly one active row');
        const firstRow = page.locator('#home_log_list .home-log-item.lv-PENDING').first();
        assert.equal(await firstRow.locator('.hl-action').textContent(), '网络防护');
        assert.equal(await firstRow.locator('.hl-source').textContent(), '×2 · 处理中');
        assert.equal(await page.locator('#home_log_list .home-log-item.lv-PENDING').nth(1).locator('.hl-source').textContent(), '×1');
        assert.equal(await page.locator('#home_log_list .home-log-empty').count(), 0, 'no empty state while queue has items');
        const output = process.argv[2];
        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.screenshot({ path: path.join(output, 'pending-filter.png') });
        }

        // 3. 点击队列条目:打开告警窗(而非空白无响应)
        await firstRow.click();
        await page.waitForFunction(() => window.pendingTest.opened === 1);
        assert.equal(await page.evaluate(() => window.pendingTest.opened), 1);

        // 4. 其他筛选仍正常(回归:普通日志筛选不能被打断)
        await page.locator('.log-filter[data-filter="BLOCK"]').click();
        await page.waitForFunction(() => document.querySelectorAll('#home_log_list .home-log-item').length === 1);
        assert.equal(await page.locator('#home_log_list .home-log-item .hl-action').textContent(), '文件拦截');

        // 5. 回到 pending 筛选后队列被处理完:自动回退「全部」,chip 隐藏,日志恢复
        await chip.click();
        await page.waitForFunction(() => document.querySelectorAll('#home_log_list .home-log-item.lv-PENDING').length === 3);
        await page.evaluate(() => { window.pendingTest.count = 0; });
        await page.waitForFunction(() => document.getElementById('pending_threats_btn').classList.contains('hidden'), null, { timeout: 5000 });
        assert.equal(await page.locator('.log-filter.active').getAttribute('data-filter'), 'all', 'must fall back to all');
        assert.equal(await page.locator('#home_log_list .home-log-item').count(), 2);

        // 6. 非 pending 筛选下队列清空:停在当前筛选,不误回退(BLOCK 仍只显示拦截日志)
        await page.evaluate(() => { window.pendingTest.count = 2; });
        await page.waitForFunction(() => !document.getElementById('pending_threats_btn').classList.contains('hidden'));
        await page.locator('.log-filter[data-filter="BLOCK"]').click();
        await page.waitForFunction(() => document.querySelectorAll('#home_log_list .home-log-item').length === 1);
        await page.evaluate(() => { window.pendingTest.count = 0; });
        await page.waitForFunction(() => document.getElementById('pending_threats_btn').classList.contains('hidden'), null, { timeout: 5000 });
        assert.equal(await page.locator('.log-filter.active').getAttribute('data-filter'), 'BLOCK', 'non-pending filter must not be hijacked');
        assert.equal(await page.locator('#home_log_list .home-log-item').count(), 1);

        assert.deepEqual(errors, []);
        console.log('Pending alerts filter: PASS (chip visibility, queue rendering, active row, open window, row click, fallback to all, filter isolation)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
