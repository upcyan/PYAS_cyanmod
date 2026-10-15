/* 智能体加固 UI 测试(Playwright + 本机 Edge)
   覆盖:扫描按钮已移除、图标按「本机已安装」过滤渲染、无安装时的空态、进页自动扫进程。
   用法: NODE_PATH=<node_modules> node tests/test_agent_hardening_ui.cjs [screenshot_dir] */
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
        const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png' };
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
        const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error).slice(0, 200)));
        await page.addInitScript(() => {
            const cfg = { first_launch: false, language: 'simplified_switch', theme: 'white_switch',
                version: '3.7.1-1', interactive_timeout: 30, ai_provider_mode: 'cloud', ai_model: '' };
            window.__installed = [
                { name: 'AutoClaw', logo: 'autoclaw.png', letter: 'A', color: '#2563EB', via: 'process' },
                { name: 'ZCode', logo: 'zcode.png', letter: 'Z', color: '#2563EB', via: 'process' },
                { name: 'Aider', logo: null, letter: 'Ai', color: '#0D9488', via: 'path' },
            ];
            window.__scans = 0;
            window.pywebview = { api: {
                get_config: async () => cfg, init_ui_ready: async () => true,
                report_ui_error: async () => true, get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [], show_confirm: async () => true, show_alert: async () => true,
                update_config: async (k, v) => v, save_ai_config: async () => ({ ok: true }),
                get_ai_token_usage: async () => ({ model: '', usage: {}, total: { tokens: 0, requests: 0 } }),
                reset_ai_token_usage: async () => ({ ok: true }),
                list_installed_agents: async () => window.__installed,
                scan_agent_processes: async () => { window.__scans += 1; return []; },
                get_agent_activity: async () => [{ name: 'AutoClaw', exe: 'autoclaw.exe', count: 1, pids: [7] }],
                get_suppression_rules: async () => [],
                list_ai_rule_drafts: async () => [],
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`, { timeout: 30000, waitUntil: 'domcontentloaded' });
        await page.waitForFunction(() => document.querySelector('.app-container')?.classList.contains('fade-in'), null, { timeout: 15000 });

        // 1. 扫描按钮必须已移除
        assert.equal(await page.locator('#ai_agent_scan').count(), 0, '「扫描本机」按钮应已移除');

        // 2. 进入 AI 页 → 自动扫进程 + 按已安装渲染图标
        await page.click('.nav-btn[data-target="ai_window"]');
        await page.waitForFunction(() => document.getElementById('ai_window')?.classList.contains('active'));
        await page.waitForFunction(() => document.querySelectorAll('#ai_agent_icons .ai-chip').length > 0, null, { timeout: 5000 });

        const icons = await page.$$eval('#ai_agent_icons .ai-chip', chips => chips.map(chip => ({
            title: chip.title,
            img: chip.querySelector('img')?.getAttribute('src') || '',
            hasBadge: !!chip.querySelector('svg.ai-chip-badge'),
        })));
        assert.deepEqual(icons.map(i => i.title), ['AutoClaw', 'ZCode', 'Aider'], '只渲染已安装的,且按目录顺序');
        assert.ok(icons[0].img.includes('autoclaw.png'), 'AutoClaw 用真实图标');
        assert.ok(icons[2].hasBadge, '无方形图标的 Aider 走字母徽标');
        assert.equal(await page.locator('#ai_agent_none').isHidden(), true, '有安装项时空态提示隐藏');
        assert.equal(await page.evaluate(() => window.__scans), 1, '进页面应自动扫一次进程(替代原按钮)');

        // 3. 活动列表仍然渲染(自动扫描后的数据)
        const activity = await page.textContent('#ai_agent_results_item');
        assert.ok(activity.includes('AutoClaw'), `活动列表应显示自动扫描结果,实际: ${activity}`);

        // 4. 空态:第二台「什么都没装」的机器,走真实进页路径
        const page2 = await browser.newPage({ viewport: { width: 1280, height: 900 } });
        page2.on('pageerror', error => errors.push(String(error).slice(0, 200)));
        await page2.addInitScript(() => {
            const cfg = { first_launch: false, language: 'simplified_switch', theme: 'white_switch',
                version: '3.7.1-1', interactive_timeout: 30, ai_provider_mode: 'cloud', ai_model: '' };
            window.pywebview = { api: {
                get_config: async () => cfg, init_ui_ready: async () => true,
                report_ui_error: async () => true, get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [], show_confirm: async () => true, show_alert: async () => true,
                update_config: async (k, v) => v, save_ai_config: async () => ({ ok: true }),
                get_ai_token_usage: async () => ({ model: '', usage: {}, total: { tokens: 0, requests: 0 } }),
                reset_ai_token_usage: async () => ({ ok: true }),
                list_installed_agents: async () => [],
                scan_agent_processes: async () => [],
                get_agent_activity: async () => [],
                get_suppression_rules: async () => [],
                list_ai_rule_drafts: async () => [],
            } };
        });
        await page2.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`, { timeout: 30000, waitUntil: 'domcontentloaded' });
        await page2.waitForFunction(() => document.querySelector('.app-container')?.classList.contains('fade-in'), null, { timeout: 15000 });
        await page2.click('.nav-btn[data-target="ai_window"]');
        await page2.waitForFunction(() => document.getElementById('ai_window')?.classList.contains('active'));
        await page2.waitForFunction(() => document.getElementById('ai_agent_none') !== null, null, { timeout: 5000 });
        await page2.waitForTimeout(400);
        const emptyState = await page2.evaluate(() => ({
            chips: document.querySelectorAll('#ai_agent_icons .ai-chip').length,
            hintHidden: document.getElementById('ai_agent_none').hidden,
        }));
        assert.deepEqual(emptyState, { chips: 0, hintHidden: false }, '无安装项:图标清空 + 空态提示显示');
        await page2.close();

        const output = process.argv[2];
        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.screenshot({ path: path.join(output, 'agent-hardening.png') });
        }
        assert.deepEqual(errors, [], `页面不应有 JS 错误: ${errors.join(' | ')}`);
        console.log('Agent hardening UI: PASS (按钮移除/已安装过滤/字母徽标/自动扫描/空态)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error('Agent hardening UI: FAIL', error.message); process.exit(1); });
