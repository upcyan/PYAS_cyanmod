/* Run with Playwright available: node tests/test_release_records_ui.cjs [screenshot-dir] */
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const PERM_HASH = 'a'.repeat(64);
const SUP_HASH = 'b'.repeat(64);

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
    let browser;
    try {
        browser = await chromium.launch({
            executablePath: process.env.EDGE_EXECUTABLE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
            headless: true,
        });
        const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error).slice(0, 200)));
        await page.addInitScript(() => {
            const cfg = {
                first_launch: false, language: 'simplified_switch', theme: 'white_switch',
                version: '3.7.0', interactive_timeout: 30, ai_provider_mode: 'local', ai_model: '',
            };
            window.pywebview = { api: {
                get_config: async () => cfg, init_ui_ready: async () => true,
                report_ui_error: async () => true, get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [], show_confirm: async () => true, show_alert: async () => true,
                update_config: async (k, v) => v, save_ai_config: async () => ({ ok: true }),
                get_ai_token_usage: async () => ({ model: '', usage: {}, total: { tokens: 0, requests: 0 } }),
                reset_ai_token_usage: async () => ({ ok: true }),
                list_release_records: async () => ({
                    permanent: [{ key: 'K1', action: 'Process Block', source: 'C:/Windows/evil.exe', sha256: 'a'.repeat(64) }],
                    suppress: [{ id: 'S1', action: 'File Block', source: '', sha256: 'b'.repeat(64), reason: 'dev_tool', scope: 'file_rule', days_left: 87, hits: 5 }],
                }),
                delete_release_record: async () => true, clear_release_records: async () => true,
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`, { timeout: 20000 });
        await page.waitForFunction(() => document.querySelector('.app-container')?.classList.contains('fade-in'), null, { timeout: 15000 });

        await page.$eval('[data-target="release_window"]', el => el.click());
        await page.waitForSelector('#release_window .manage-list-item', { timeout: 10000 });

        const output = process.argv[2];
        if (output) await page.screenshot({ path: path.join(output, 'release-records.png') });

        // 列:类型/功能/路径/校验码/状态/命中 —— 类型与状态不再重复,校验码为新增列
        const headers = await page.$$eval('#release_window .col-header .header-text', els => els.map(el => el.textContent.trim()));
        assert.deepEqual(headers, ['类型', '功能', '路径', '校验码', '状态', '命中']);

        const rows = await page.$$eval('#release_window .manage-list-item', items => items.map(li => ({
            value: li.querySelector('input')?.value,
            cells: [...li.querySelectorAll('.row-col')].map(cell => ({ text: cell.textContent, title: cell.title })),
        })));
        assert.equal(rows.length, 2);

        const [permanent, suppress] = rows;
        assert.equal(permanent.value, 'p:K1');
        assert.deepEqual(permanent.cells.map(cell => cell.text),
            ['永久允许', '进程拦截', 'C:/Windows/evil.exe', PERM_HASH, '-', '-']);
        assert.equal(suppress.value, 's:S1');
        assert.deepEqual(suppress.cells.map(cell => cell.text),
            ['误报抑制', '文件拦截', '-', SUP_HASH, '剩余 87 天', '5']);
        assert.equal(suppress.cells[3].title, SUP_HASH, '校验码悬停显示完整值');

        // 按校验码搜索
        await page.fill('#release_window .search-box input', PERM_HASH.slice(0, 20));
        const matched = await page.$$eval('#release_window .manage-list-item .row-col:first-child', els => els.map(el => el.textContent));
        assert.deepEqual(matched, ['永久允许']);
        await page.fill('#release_window .search-box input', '');

        // 全部清除后的重新渲染走另一段构建逻辑,状态列不得回退成原始 i18n key
        await page.$eval('#release_select', el => { el.value = 'clear'; el.dispatchEvent(new Event('change', { bubbles: true })); });
        await page.waitForTimeout(300);
        const refreshed = await page.textContent('#release_window');
        assert.ok(!refreshed.includes('release_days_left'), '状态列不应显示原始 i18n key');
        assert.ok(!refreshed.includes('release_kind_'), '类型列不应显示原始 i18n key');

        assert.deepEqual(errors, []);
        console.log('Release records UI: PASS (columns, checksum, status, refresh, search)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
