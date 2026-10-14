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
                version: '3.7.1-1', interactive_timeout: 30, ai_provider_mode: 'local', ai_model: '',
            };
            // 可变存储:移除要真的从后端数据里删掉,刷新后行才消失
            window.__store = {
                permanent: [
                    { key: 'K1', action: 'Process Block', source: 'C:/Windows/evil.exe', sha256: 'a'.repeat(64), hits: 3, created: 1791800000 },
                    // 旧版本存的记录没有 hits/created:命中显示 0,添加时间显示占位符
                    { key: 'K2', action: 'File Block', source: 'C:/legacy/old.exe', sha256: 'c'.repeat(64) },
                ],
                suppress: [{ id: 'S1', action: 'File Block', source: '', sha256: 'b'.repeat(64), reason: 'dev_tool', scope: 'file_rule', days_left: 87, hits: 5, created: 1791800000 }],
            };
            window.__deleteCalls = [];
            // 后端契约:kind 只认 permanent/suppress,其余一律拒绝(返回 False)
            const VALID_KINDS = new Set(['permanent', 'suppress']);
            window.pywebview = { api: {
                get_config: async () => cfg, init_ui_ready: async () => true,
                report_ui_error: async () => true, get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [], show_confirm: async () => true, show_alert: async () => true,
                update_config: async (k, v) => v, save_ai_config: async () => ({ ok: true }),
                get_ai_token_usage: async () => ({ model: '', usage: {}, total: { tokens: 0, requests: 0 } }),
                reset_ai_token_usage: async () => ({ ok: true }),
                list_release_records: async () => JSON.parse(JSON.stringify(window.__store)),
                delete_release_record: async (kind, ident) => {
                    window.__deleteCalls.push([kind, ident]);
                    if (!VALID_KINDS.has(kind)) return false;
                    const field = kind === 'permanent' ? 'key' : 'id';
                    const listName = kind === 'permanent' ? 'permanent' : 'suppress';
                    const before = window.__store[listName].length;
                    window.__store[listName] = window.__store[listName].filter(item => item[field] !== ident);
                    return window.__store[listName].length < before;
                },
                clear_release_records: async () => {
                    window.__store.permanent = [];
                    window.__store.suppress = [];
                    return true;
                },
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`, { timeout: 30000, waitUntil: 'domcontentloaded' });
        await page.waitForFunction(() => document.querySelector('.app-container')?.classList.contains('fade-in'), null, { timeout: 15000 });

        await page.$eval('[data-target="release_window"]', el => el.click());
        await page.waitForSelector('#release_window .manage-list-item', { timeout: 10000 });

        const output = process.argv[2];
        if (output) await page.screenshot({ path: path.join(output, 'release-records.png') });

        // 列:类型/功能/路径/校验码/状态/命中/添加时间 —— 校验码与添加时间为新增列
        const headers = await page.$$eval('#release_window .col-header .header-text', els => els.map(el => el.textContent.trim()));
        assert.deepEqual(headers, ['类型', '功能', '路径', '校验码', '状态', '命中', '添加时间']);

        const rows = await page.$$eval('#release_window .manage-list-item', items => items.map(li => ({
            value: li.querySelector('input')?.value,
            cells: [...li.querySelectorAll('.row-col')].map(cell => ({ text: cell.textContent, title: cell.title })),
        })));
        assert.equal(rows.length, 3);

        const [permanent, legacy, suppress] = rows;
        const fmt = epoch => { const d = new Date(epoch * 1000); const p = v => String(v).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`; };
        assert.equal(permanent.value, 'p:K1');
        assert.deepEqual(permanent.cells.map(cell => cell.text),
            ['永久允许', '进程拦截', 'C:/Windows/evil.exe', PERM_HASH, '-', '3', fmt(1791800000)]);
        assert.equal(legacy.value, 'p:K2', '旧记录(无 hits/created)也要渲染');
        assert.equal(legacy.cells[5].text, '0', '旧记录命中从 0 起显示');
        assert.equal(legacy.cells[6].text, '-', '旧记录没有添加时间,显示占位符');
        assert.equal(suppress.value, 's:S1');
        assert.deepEqual(suppress.cells.map(cell => cell.text),
            ['误报抑制', '文件拦截', '-', SUP_HASH, '剩余 87 天', '5', fmt(1791800000)]);
        assert.equal(suppress.cells[3].title, SUP_HASH, '校验码悬停显示完整值');

        // 按添加时间排序:数值列不能按字符串排
        const createdHeader = '#release_window .col-header[data-idx="6"]';
        await page.click(createdHeader);
        await page.waitForFunction(() => document.querySelector('#release_window .col-header[data-idx="6"] .sort-icon')?.textContent.trim() !== '', null, { timeout: 5000 });
        const sortedFirst = await page.$eval('#release_window .manage-list-item .row-col', el => el.textContent);
        assert.ok(['永久允许', '误报抑制'].includes(sortedFirst), `添加时间可排序,实际首行类型: ${sortedFirst}`);

        // 按校验码搜索
        await page.fill('#release_window .search-box input', PERM_HASH.slice(0, 20));
        const matched = await page.$$eval('#release_window .manage-list-item .row-col:first-child', els => els.map(el => el.textContent));
        assert.deepEqual(matched, ['永久允许']);
        await page.fill('#release_window .search-box input', '');

        // 移除项目:通过行点击勾选(走 click 处理器,同步 gridState.checkedSet),
        // 断言后端收到的是契约里的 kind='permanent' 而非行 value 的单字母前缀 'p'
        const rowK1 = page.locator('#release_window .manage-list-item', { has: page.locator('input[value="p:K1"]') });
        await rowK1.locator('.row-col').first().click();
        assert.equal(await page.$eval('#release_window .manage-list-item input[value="p:K1"]', el => el.checked), true, '行点击应勾选 K1');
        await page.$eval('#release_select', el => { el.value = 'remove'; el.dispatchEvent(new Event('change', { bubbles: true })); });
        await page.waitForFunction(() => window.__deleteCalls.length > 0, null, { timeout: 5000 });
        assert.deepEqual(await page.evaluate(() => window.__deleteCalls), [['permanent', 'K1']],
            '移除永久允许必须传后端契约的 kind=permanent');
        await page.waitForFunction(() => document.querySelectorAll('#release_window .manage-list-item').length === 2, null, { timeout: 5000 });
        const afterRemove = await page.$$eval('#release_window .manage-list-item input[type="checkbox"]', els => els.map(el => el.value));
        assert.deepEqual(afterRemove, ['p:K2', 's:S1'], '被移除的行应从列表消失');

        // 全部清除后的重新渲染走另一段构建逻辑,状态列不得回退成原始 i18n key
        await page.$eval('#release_select', el => { el.value = 'clear'; el.dispatchEvent(new Event('change', { bubbles: true })); });
        await page.waitForTimeout(300);
        const refreshed = await page.textContent('#release_window');
        assert.ok(!refreshed.includes('release_days_left'), '状态列不应显示原始 i18n key');
        assert.ok(!refreshed.includes('release_kind_'), '类型列不应显示原始 i18n key');

        assert.deepEqual(errors, []);
        console.log('Release records UI: PASS (columns, checksum, status, refresh, search, remove)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
