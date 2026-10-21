/* 日志行动作名的本地化(Playwright + 本机 Edge)
   后端 write_log 的 action 是英文标识,界面靠 i18n 翻译;新功能漏加 key 时
   getMsg 会原样回退,日志页就变成英文。本测试把当前后端实际使用、且对用户
   可见(is_ui_log_entry)的 action 全部喂进实时日志,断言没有一条回退成英文。
   用法: NODE_PATH=<node_modules> node tests/test_log_i18n_ui.cjs [screenshot_dir] */
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

// 必须与 PYAS_*.py 里 write_log 的字面 action 对齐;新增日志动作时这里也要加
const VISIBLE_ACTIONS = [
    'AI Suggestion', 'AI Suggestion Applied', 'AI Token Usage',
    'Alert Decision Remembered', 'Alert Decision Reused',
    'Clean Junk', 'Config Rollback', 'Config Update',
    'Deferred Scan Allow', 'Deferred Scan Block', 'Driver Block', 'Driver Identity',
    'Driver Protection', 'Driver Service', 'Driver Unload Authorization',
    'False Positive Reported', 'File Allow', 'File Block', 'File Event Recovery',
    'File Extract', 'File Lock Deferred', 'File Watcher', 'Load Engine', 'MBR Repaired',
    'Memory Boost', 'Modern Context Menu', 'Network Allow', 'Network Block',
    'Popup Blocker', 'Process Allow', 'Process Block', 'Process DLL Allow',
    'Process DLL Block', 'Protection Recovery', 'Scan Completed', 'Scan Engine',
    'Suppression Hit', 'System', 'System Repair', 'System Restart',
    'Update Download', 'Update Install', 'Virus Delete', 'Virus Delete Deferred',
    'Virus Detected', 'manage_autostart', 'manage_startup',
];

// 这些是诊断/堆栈动作,is_ui_log_entry 已判定不进界面,不该出现在这里
const HIDDEN_ACTIONS = ['Exception', 'Diagnostic'];

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
        const page = await browser.newPage({ viewport: { width: 1100, height: 760 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript((actions) => {
            const cfg = { first_launch: false, language: 'simplified_switch', theme: 'white_switch', version: 'test', interactive_timeout: 30 };
            window.pywebview = { api: {
                get_config: async () => cfg,
                init_ui_ready: async () => true,
                report_ui_error: async () => true,
                get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                show_confirm: async () => true,
                show_alert: async () => true,
                update_config: async (key, value) => { cfg[key] = value; return value; },
                get_logs: async () => actions.map((action, index) => ({
                    id: `fx-${index}`,
                    time_str: `2026-10-10 10:${String(index).padStart(2, '0')}:00`,
                    level: 'INFO',
                    action,
                    source: `C:\\fixture\\${action}.exe`,
                    detail: `detail for ${action}`,
                })),
            } };
        }, VISIBLE_ACTIONS);
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`);
        await page.waitForFunction(() => document.querySelector('.app-container').classList.contains('fade-in'));

        // 打开实时日志(默认标签即首页),等列表填满
        await page.waitForFunction(
            (expected) => document.querySelectorAll('#home_log_list .home-log-item').length === expected,
            VISIBLE_ACTIONS.length, { timeout: 20000 });

        const rendered = await page.$$eval('#home_log_list .home-log-item .hl-action',
            els => els.map(el => el.textContent.trim()));

        // 1) 每个动作都渲染出来了
        assert.equal(rendered.length, VISIBLE_ACTIONS.length,
            `期望 ${VISIBLE_ACTIONS.length} 条日志,实际 ${rendered.length}`);

        // 2) 没有一条把英文 action 原样回退出来
        const leaked = rendered.filter(text => VISIBLE_ACTIONS.includes(text) || HIDDEN_ACTIONS.includes(text));
        assert.deepEqual(leaked, [],
            `以下 action 缺少 i18n 键,界面显示成了英文原文: ${leaked.join(', ')}`);

        // 3) 抽查几条确实是中文译文(而非空串或键名)
        const sample = await page.$$eval('#home_log_list .home-log-item', items => items.map(li => ({
            action: li.querySelector('.hl-action')?.textContent.trim(),
            source: li.querySelector('.hl-source')?.textContent.trim(),
        })));
        const find = (action) => {
            const row = sample.find(entry => entry.source === `C:\\fixture\\${action}.exe`);
            assert(row, `日志里找不到 action=${action} 的行`);
            return row.action;
        };
        assert.equal(find('File Block'), '文件拦截', 'File Block 应译为中文');
        assert.equal(find('File Watcher'), '文件实时防护', 'File Watcher 应译为中文');

        // 详情句式翻译:后端固定英文模板 + 内嵌路径,应整体渲染成中文
        const translated = await page.evaluate(() =>
            window.translateLogDetail('Real-time file protection is on (watching the user profile for file changes)'));
        assert.equal(translated, '文件实时防护已开启',
            '开启详情不再重复行动作名里已经说明的监听范围');

        const warnText = await page.evaluate(() =>
            window.translateLogDetail('Real-time file protection cannot watch D:/demo; will retry'));
        assert.equal(warnText, '文件实时防护无法监听 D:/demo，稍后重试',
            '无法监听时的告警要有中文,并保留路径');
        assert.equal(find('Suppression Hit'), '命中抑制规则', 'Suppression Hit 应译为中文');
        assert.equal(find('AI Token Usage'), 'Token 用量', 'AI Token Usage 应译为中文');
        assert.equal(find('Alert Decision Remembered'), '已记住放行决定', 'Alert Decision Remembered 应译为中文');
        assert.equal(find('Modern Context Menu'), '新版右键菜单', 'Modern Context Menu 应译为中文');

        const output = process.argv[2];
        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.screenshot({ path: path.join(output, 'log-i18n.png') });
        }
        assert.deepEqual(errors, [], `页面不应有 JS 错误: ${errors.join(' | ')}`);
        console.log(`Log i18n: PASS (${VISIBLE_ACTIONS.length} 个可见日志动作全部本地化,无英文回退)`);
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error('Log i18n: FAIL', error.message); process.exit(1); });
