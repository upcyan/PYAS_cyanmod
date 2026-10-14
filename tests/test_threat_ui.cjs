/* Run with Playwright available: node tests/test_threat_ui.cjs [screenshot-dir] */
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
        const page = await browser.newPage({ viewport: { width: 720, height: 520 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript(() => {
            const events = [
                { id: '1', title: '网络防护' },
                { id: '2', title: '文件防护' },
                { id: '3', title: '进程防护' },
            ];
            window.fixture = { theme: 'white_switch', events, minimized: 0, decisions: [] };
            window.pywebview = { api: {
                ready: async () => true,
                snapshot: async () => {
                    const item = events[0];
                    const groups = new Map();
                    for (const entry of events) {
                        if (!groups.has(entry.title)) groups.set(entry.title, { id: entry.title, title: entry.title, count: 0, active: false });
                        const group = groups.get(entry.title);
                        group.count++;
                        group.active ||= entry.id === item?.id;
                    }
                    return item ? {
                        ...item, events: [...groups.values()], count: events.length, can_remember: true,
                        identity_summary: 'C:\\fixture\\example.exe\nSHA-256: ' + '0'.repeat(64), theme: window.fixture.theme,
                        language: 'simplified_switch', remaining: null,
                        message: '检测到进程正连接已知恶意地址。拦截将终止该进程；本次允许将允许此次连接。\n\n来源：C:\\Users\\demo\\Downloads\\' + '长目录名称\\'.repeat(16) + 'example.exe\n目标：example.test:443\n进程：4321',
                        waiting: '等待您选择；关闭窗口仅收起，不执行操作。',
                        allow: '本次允许', block: '拦截', countdown: '',
                    } : null;
                },
                decide: async (id, choice) => {
                    if (events[0]?.id !== id) return false;
                    window.fixture.decisions.push({ id, choice });
                    events.shift(); return true;
                },
                minimize: async () => { window.fixture.minimized += 1; },
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/threat.html`);
        await page.getByRole('button', { name: '拦截', exact: true }).waitFor();
        await page.waitForFunction(() => !document.getElementById('threat_block').disabled);
        assert.equal(await page.locator('#queue_count').textContent(), '3');
        await page.keyboard.press('Escape');
        assert.equal(await page.evaluate(() => window.fixture.minimized), 1);
        assert.equal(await page.evaluate(() => window.fixture.decisions.length), 0);
        await page.locator('#threat_allow').focus();
        await page.evaluate(() => window.fixture.events.push({ id: '4', title: '网络防护' }));
        await page.waitForFunction(() => document.getElementById('queue_count').textContent === '4');
        assert.equal(await page.evaluate(() => document.activeElement.id), 'threat_allow');
        assert.equal(await page.locator('#threat_queue_list li').count(), 3, 'repeated protection grouped into one row');
        const output = process.argv[2];
        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.screenshot({ path: path.join(output, 'threat-light.png') });
        }
        await page.setViewportSize({ width: 560, height: 420 });
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        assert(await page.locator('#threat_block').isVisible());
        assert((await page.locator('#threat_allow').boundingBox()).height <= 60, 'Compact buttons must not wrap vertically');
        if (output) await page.screenshot({ path: path.join(output, 'threat-compact.png') });
        await page.setViewportSize({ width: 720, height: 520 });
        await page.evaluate(() => { window.fixture.theme = 'black_switch'; });
        await page.waitForFunction(() => getComputedStyle(document.documentElement).getPropertyValue('--bg-window').trim() === 'rgb(0, 0, 0)');
        await page.waitForFunction(() => getComputedStyle(document.querySelector('.navigate-window')).backgroundColor === 'rgb(28, 28, 30)' && getComputedStyle(document.getElementById('threat_allow')).color === 'rgb(216, 216, 220)');
        if (output) await page.screenshot({ path: path.join(output, 'threat-dark.png') });
        await page.locator('#threat_block').click();
        await page.waitForFunction(() => document.getElementById('threat_title').textContent === '文件防护');
        assert.deepEqual(await page.evaluate(() => window.fixture.decisions), [{ id: '1', choice: 'block' }]);
        const permanentBox = await page.locator('#threat_permanent').boundingBox();
        const allowBox = await page.locator('#threat_allow').boundingBox();
        assert(permanentBox.x + permanentBox.width + 20 < allowBox.x, 'permanent button separated on left');
        await page.locator('#threat_permanent').click();
        assert.equal(await page.locator('#threat_confirmation').isVisible(), true);
        assert.equal(await page.evaluate(() => window.fixture.decisions.length), 1, 'permanent requires confirmation');
        await page.locator('#threat_cancel').click();
        assert.equal(await page.locator('#threat_confirmation').isVisible(), false);
        await page.locator('#threat_permanent').click();
        await page.locator('#threat_confirm').click();
        await page.waitForFunction(() => window.fixture.decisions.length === 2);
        assert.deepEqual(await page.evaluate(() => window.fixture.decisions[1]), { id: '2', choice: 'permanent' });
        assert.equal(await page.locator('#threat_repeat').isChecked(), false);
        assert.deepEqual(errors, []);
        const main = await browser.newPage({ viewport: { width: 1024, height: 768 } });
        main.on('pageerror', error => errors.push(String(error)));
        await main.addInitScript(() => {
            window.copiedLogs = [];
            Object.defineProperty(navigator, 'clipboard', { value: { writeText: async text => window.copiedLogs.push(text) }, configurable: true });
            const cfg = { first_launch: false, language: 'simplified_switch', theme: 'white_switch', version: 'test', interactive_timeout: 30 };
            window.menuTest = { cfg, rejectNext: false, alerts: [], mode: 'disabled', notice: '' };
            window.pywebview = { api: {
                get_config: async () => cfg,
                init_ui_ready: async () => true,
                report_ui_error: async () => true,
                get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => {
                    const status = { mode: window.menuTest.mode, notice: window.menuTest.notice };
                    window.menuTest.notice = '';
                    return status;
                },
                get_logs: async () => [{ id: 'fixture', time_str: '2026-10-10 10:00:00', level: 'INFO', action: 'System', source: 'UI test', detail: '完整日志：<script> & "中文"\n' + '长信息'.repeat(100) }],
                show_confirm: async () => true,
                show_alert: async (...args) => { window.menuTest.alerts.push(args); },
                update_config: async (key, value) => {
                    if (key === 'context_switch' && window.menuTest.rejectNext) {
                        window.menuTest.rejectNext = false;
                        return !!cfg[key];
                    }
                    cfg[key] = value;
                    if (key === 'context_switch') window.menuTest.mode = value ? 'modern' : 'disabled';
                    return value;
                },
            } };
        });
        await main.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`);
        await main.waitForFunction(() => document.querySelector('.app-container').classList.contains('fade-in'));
        assert.equal(await main.locator('#context_menu_status').textContent(), '未添加右键菜单');
        await main.evaluate(async () => {
            window.menuTest.mode = 'legacy';
            window.menuTest.notice = 'Add-AppxPackage: 签名证书不受信任 0x800B0109';
            await window.refreshContextMenuStatus();
        });
        assert.equal(await main.locator('#context_menu_status').textContent(), '已添加传统菜单');
        assert((await main.evaluate(() => window.menuTest.alerts[0][1])).includes('Windows 不信任'));
        await main.evaluate(async () => { await window.refreshContextMenuStatus(); });
        assert.equal(await main.evaluate(() => window.menuTest.alerts.length), 1);
        await main.evaluate(() => { window.menuTest.alerts = []; });
        const log = main.locator('#home_log_list .home-log-item').first();
        await log.waitFor();
        await log.locator('.hl-source').click({ button: 'right' });
        assert.equal(await main.locator('#ctx_copy_row').isVisible(), true);
        assert.equal(await main.locator('#ctx_open_location').isVisible(), false);
        assert.equal(await main.locator('#ctx_copy_cell').isVisible(), true);
        // A live refresh while the menu is open must not change the copied record.
        await main.evaluate(() => window.updateLogs({ id: 'newer', time_str: '2026-10-10 10:01:00', level: 'WARN', action: 'System', detail: '新日志' }));
        await main.waitForFunction(() => document.querySelectorAll('#home_log_list .home-log-item').length === 2);
        await main.locator('#ctx_copy_row').click();
        assert.equal(await main.evaluate(() => window.copiedLogs[0]), '2026-10-10 10:00:00\t信息\t系统\tUI test\n完整日志：<script> & "中文"\n' + '长信息'.repeat(100));
        await main.locator('#home_log_list .home-log-item').first().click({ button: 'right' });
        await main.keyboard.press('Escape');
        assert.equal(await main.locator('.custom-context-menu').isVisible(), false);
        console.log('Realtime log copy: PASS (full row, Chinese, multiline, HTML characters, live refresh snapshot, Escape)');
        await main.evaluate(() => window.updateLogs({ id: 'scan-fixture', time_str: '2026-10-10 10:02:00', level: 'SCAN', action: 'Found Virus', detail: '扫描记录测试' }));
        await main.locator('.log-filter[data-filter="SCAN"]').click();
        assert.equal(await main.locator('.log-filter[data-filter="SCAN"]').textContent(), '扫描');
        assert.equal(await main.locator('#home_log_list .home-log-item').count(), 1);
        assert((await main.locator('#home_log_list').textContent()).includes('扫描记录测试'));
        await main.locator('.log-filter[data-filter="all"]').click();
        assert.equal(await main.locator('#home_log_list .home-log-item').count(), 3);
        console.log('Realtime log filter: PASS (scan level and return to all)');
        await main.locator('.nav-btn[data-target="setting_window"]').click();
        const automatic = main.locator('[data-config-key="interactive_auto_block"]');
        const timeout = main.locator('#interactive_timeout_input');
        const classic = main.locator('#classic_menu_options');
        const clearDecisions = main.locator('#clear_alert_rules');
        assert.equal(await classic.isVisible(), false);
        assert.equal(await main.locator('#setting_window .settings-group').count(), 2);
        assert.equal(await main.locator('#ai_window .settings-group').count(), 4, 'AI settings retain model, decision, suppression and draft groups');
        assert.equal(await main.evaluate(() => document.querySelector('[data-config-key="context_switch"]').closest('.settings-group') === document.querySelector('[data-config-key="interactive_switch"]').closest('.settings-group')), false, 'each parent must have a separate group');
        assert.equal(await automatic.isVisible(), false);
        assert.equal(await clearDecisions.isVisible(), false);
        await main.locator('label:has([data-config-key="context_switch"])').click();
        await main.waitForFunction(() => !document.querySelector('[data-config-key="context_switch"]').disabled);
        assert.equal(await classic.isVisible(), true);
        const parentBox = await main.locator('[data-config-key="context_switch"]').locator('xpath=../..').boundingBox();
        const childBox = await classic.boundingBox();
        assert(childBox.y >= parentBox.y + parentBox.height, 'classic menu must appear below its parent');
        assert.equal(childBox.x, parentBox.x, 'secondary setting must not be indented');
        assert.equal(childBox.width, parentBox.width, 'grouped rows must have equal width');
        assert(Math.abs(childBox.y - parentBox.y - parentBox.height) < 1, 'parent and child must connect without a gap');
        assert.equal(await classic.evaluate(el => getComputedStyle(el).borderRadius), '0px', 'only outer card has rounded corners');
        await main.locator('label:has([data-config-key="context_switch"])').click();
        await main.waitForFunction(() => !document.querySelector('[data-config-key="context_switch"]').disabled);
        assert.equal(await classic.isVisible(), false);
        await main.evaluate(() => { window.menuTest.rejectNext = true; });
        await main.locator('label:has([data-config-key="context_switch"])').click();
        await main.waitForFunction(() => window.menuTest.alerts.length === 1);
        assert.equal(await main.locator('[data-config-key="context_switch"]').isChecked(), false);
        assert.equal(await classic.isVisible(), false);
        assert((await main.evaluate(() => window.menuTest.alerts[0][1])).includes('Modern Context Menu'));
        assert.equal(await automatic.isChecked(), false);
        assert.equal(await automatic.isDisabled(), true);
        assert.equal(await timeout.isVisible(), false);
        await main.locator('label:has([data-config-key="interactive_switch"])').click();
        await main.waitForFunction(() => !document.querySelector('[data-config-key="interactive_auto_block"]').disabled);
        assert.equal(await clearDecisions.isVisible(), true);
        await main.locator('label:has([data-config-key="interactive_auto_block"])').click();
        await main.waitForFunction(() => !document.getElementById('interactive_timeout_input').disabled);
        assert.equal(await timeout.isVisible(), true);
        assert.equal(await main.evaluate(() => {
            const automaticRow = document.querySelector('[data-config-key="interactive_auto_block"]').closest('.list-item');
            const timeoutRow = document.getElementById('interactive_timeout_input').closest('.list-item');
            const clearRow = document.getElementById('clear_alert_rules').closest('.list-item');
            return automaticRow.nextElementSibling === timeoutRow && timeoutRow.nextElementSibling === clearRow;
        }), true, 'timeout sits directly below automatic blocking');
        await main.locator('label:has([data-config-key="interactive_auto_block"])').click();
        await main.waitForFunction(() => document.getElementById('interactive_timeout_input').closest('.list-item').classList.contains('hidden'));
        assert.equal(await timeout.isDisabled(), true);
        await main.locator('label:has([data-config-key="interactive_auto_block"])').click();
        await main.waitForFunction(() => !document.getElementById('interactive_timeout_input').disabled);
        await main.locator('label:has([data-config-key="interactive_switch"])').click();
        await main.waitForFunction(() => !document.querySelector('[data-config-key="interactive_switch"]').disabled);
        assert.equal(await automatic.isVisible(), false);
        assert.equal(await clearDecisions.isVisible(), false);
        assert.equal(await timeout.isVisible(), false);
        assert.equal(await main.evaluate(() => window.menuTest.cfg.interactive_auto_block), true, 'hiding children preserves preferences');
        await main.locator('label:has([data-config-key="interactive_switch"])').click();
        await main.waitForFunction(() => !document.getElementById('interactive_timeout_input').disabled);
        assert.equal(await clearDecisions.isVisible(), true);
        assert.equal(await timeout.isVisible(), true);
        if (output) {
            await main.locator('label:has([data-config-key="context_switch"])').click();
            await main.waitForFunction(() => !document.querySelector('[data-config-key="context_switch"]').disabled);
            await clearDecisions.scrollIntoViewIfNeeded();
            await main.screenshot({ path: path.join(output, 'settings-secondary-options.png') });
        }
        assert.deepEqual(errors, []);
        console.log('Threat UI: PASS (theme, compact layout, long paths, queue, focus, minimize, decisions)');
        console.log('Settings UI: PASS (default off, opt-in, timeout visibility, explicit config bindings)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
