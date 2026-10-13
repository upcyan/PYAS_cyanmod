/* 无障碍与键盘可达性测试(Playwright + 本机 Edge)
   覆盖:自定义下拉组合框语义/方向键/Enter/Esc/Home/End、卡片入口可聚焦可回车激活、
         纯图标按钮可访问名、最大化-还原标签联动、令牌化焦点环。
   用法: NODE_PATH=<node_modules> node tests/test_a11y_ui.cjs [screenshot_dir] */
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
    let browser;
    try {
        browser = await chromium.launch({
            executablePath: process.env.EDGE_EXECUTABLE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
            headless: true,
        });
        const page = await browser.newPage({ viewport: { width: 1024, height: 700 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error).slice(0, 200)));
        await page.addInitScript(() => {
            const cfg = {
                first_launch: false, language: 'simplified_switch', theme: 'white_switch',
                version: '3.0.0', interactive_timeout: 30, ai_provider_mode: 'local', ai_model: '',
            };
            window.pywebview = { api: {
                get_config: async () => cfg, init_ui_ready: async () => true,
                report_ui_error: async () => true, get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [], show_confirm: async () => true, show_alert: async () => true,
                update_config: async (k, v) => v, save_ai_config: async () => ({ ok: true }),
                get_ai_token_usage: async () => ({ model: '', usage: {}, total: { tokens: 0, requests: 0 } }),
                reset_ai_token_usage: async () => ({ ok: true }),
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`, { timeout: 20000 });
        await page.waitForFunction(() => document.querySelector('.app-container')?.classList.contains('fade-in'), null, { timeout: 15000 });

        const output = process.argv[2];

        // ===== 1. 纯图标按钮:可访问名 + 悬停提示 =====
        const navLabels = await page.evaluate(() => {
            const out = {};
            document.querySelectorAll('.nav-btn[data-target]').forEach(btn => {
                out[btn.dataset.target] = { label: btn.getAttribute('aria-label'), title: btn.title };
            });
            for (const id of ['about_button', 'minimize_button', 'maximize_button', 'close_button']) {
                const el = document.getElementById(id);
                out[id] = { label: el.getAttribute('aria-label'), title: el.title };
            }
            return out;
        });
        assert.equal(navLabels.home_window.label, '首页');
        assert.equal(navLabels.setting_window.label, '设置');
        assert.equal(navLabels.ai_window.label, 'AI');
        assert.equal(navLabels.close_button.label, '关闭');
        assert.equal(navLabels.minimize_button.label, '最小化');
        assert.equal(navLabels.maximize_button.label, '最大化');
        for (const [key, value] of Object.entries(navLabels)) {
            assert.ok(value.label, `${key} 必须有 aria-label`);
            assert.equal(value.title, value.label, `${key} 的 title 应与 aria-label 一致`);
        }
        // 最大化/还原是同一按钮的两种状态,标签需联动
        await page.evaluate(() => window.syncMaximizeIcon(true));
        assert.equal(await page.getAttribute('#maximize_button', 'aria-label'), '还原');
        await page.evaluate(() => window.syncMaximizeIcon(false));
        assert.equal(await page.getAttribute('#maximize_button', 'aria-label'), '最大化');

        // 普通模式(后端不带 dev_channel)版本号后不出现「开发者模式」标识
        assert.equal(await page.evaluate(() => document.getElementById('title_dev_badge')?.classList.contains('hidden')),
            true, '普通模式下版本号后不应出现开发者模式标识');

        // ===== 2. 卡片入口:可聚焦 + 语义 + 回车激活 =====
        const card = await page.evaluate(() => {
            const el = document.querySelector('.quick-item[data-target="quarantine_window"]');
            const icon = el.querySelector('.icon-action-btn');
            return {
                tag: el.tagName, role: el.getAttribute('role'), tabindex: el.getAttribute('tabindex'),
                label: el.getAttribute('aria-label'),
                iconTabindex: icon.getAttribute('tabindex'), iconHidden: icon.getAttribute('aria-hidden'),
            };
        });
        assert.equal(card.tag, 'DIV');
        assert.equal(card.role, 'button');
        assert.equal(card.tabindex, '0');
        assert.ok(card.label, '卡片入口必须有可访问名');
        assert.equal(card.iconTabindex, '-1', '卡片内箭头按钮不应进入焦点序列');
        assert.equal(card.iconHidden, 'true');

        await page.focus('.quick-item[data-target="quarantine_window"]');
        await page.keyboard.press('Enter');
        await page.waitForFunction(() => document.getElementById('quarantine_window').classList.contains('active'));
        await page.click('.nav-btn[data-target="home_window"]');

        // 空格同样可激活
        await page.focus('.quick-item[data-target="quarantine_window"]');
        await page.keyboard.press(' ');
        await page.waitForFunction(() => document.getElementById('quarantine_window').classList.contains('active'));
        await page.click('.nav-btn[data-target="home_window"]');

        // ===== 3. 自定义下拉:组合框语义 + 键盘操作 =====
        await page.click('.nav-btn[data-target="setting_window"]');
        await page.waitForFunction(() => document.getElementById('setting_window').classList.contains('active'));
        // 注意:必须按具体 select 取触发器 —— DOM 里第一个触发器属于未激活页面,聚焦会失败
        const trigger = page.locator('#theme_select + .custom-select-wrapper .custom-select-trigger');
        const triggerInfo = await trigger.evaluate(el => ({
            role: el.getAttribute('role'),
            tabindex: el.getAttribute('tabindex'),
            haspopup: el.getAttribute('aria-haspopup'),
            expanded: el.getAttribute('aria-expanded'),
            controls: el.getAttribute('aria-controls'),
            label: el.getAttribute('aria-label'),
        }));
        assert.equal(triggerInfo.role, 'combobox');
        assert.equal(triggerInfo.tabindex, '0', '下拉触发器必须可聚焦');
        assert.equal(triggerInfo.haspopup, 'listbox');
        assert.equal(triggerInfo.expanded, 'false');
        assert.ok(triggerInfo.controls, '必须关联 aria-controls');
        assert.ok(triggerInfo.label, '下拉必须有可访问名');

        // 用真实键盘路径聚焦(程序化 focus() 不会匹配 :focus-visible)
        const triggerSelector = '#theme_select + .custom-select-wrapper .custom-select-trigger';
        await page.evaluate(() => document.querySelector('.nav-btn[data-target="setting_window"]').focus());
        let reached = false;
        for (let i = 0; i < 60 && !reached; i += 1) {
            await page.keyboard.press('Tab');
            reached = await page.evaluate(sel => document.activeElement?.matches?.(sel) || false, triggerSelector);
        }
        assert.equal(reached, true, '应能通过 Tab 键走到下拉触发器');
        await page.waitForTimeout(400);   // 焦点环有 250ms 过渡,等过渡结束再读计算样式
        const ring = await page.evaluate(() => {
            const el = document.activeElement;
            return { focusVisible: el.matches(':focus-visible'), shadow: getComputedStyle(el).boxShadow };
        });
        assert.equal(ring.focusVisible, true, '键盘聚焦必须匹配 :focus-visible');
        assert.ok(/rgba?\(0, 122, 255/.test(ring.shadow), `键盘聚焦应有令牌化焦点环,实际: ${ring.shadow}`);

        await page.keyboard.press('ArrowDown');
        await page.waitForFunction(() => document.querySelector('.custom-select-wrapper.open'));
        const opened = await page.evaluate(() => {
            const wrapper = document.querySelector('.custom-select-wrapper.open');
            const triggerEl = wrapper.querySelector('.custom-select-trigger');
            const list = document.querySelector('body > ul.custom-select-options[role="listbox"]');
            return {
                expanded: triggerEl.getAttribute('aria-expanded'),
                activeDescendant: triggerEl.getAttribute('aria-activedescendant'),
                listRole: list?.getAttribute('role'),
                listId: list?.id,
                options: [...(list?.querySelectorAll('[role="option"]') || [])].map(o => ({
                    selected: o.getAttribute('aria-selected'), id: o.id, active: o.classList.contains('active'),
                })),
            };
        });
        assert.equal(opened.expanded, 'true');
        assert.equal(opened.listRole, 'listbox');
        assert.equal(opened.listId, triggerInfo.controls, '菜单 id 必须与 aria-controls 一致');
        assert.ok(opened.activeDescendant, '打开后必须设置 aria-activedescendant');
        assert.equal(opened.options[0].active, true, '打开时高亮当前项');
        assert.equal(opened.activeDescendant, opened.options[0].id);
        assert.ok(opened.options.some(o => o.selected === 'true'), '必须有一项标记 aria-selected');
        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.screenshot({ path: path.join(output, 'a11y-select-open.png') });
        }

        // 方向键移动高亮,Home/End 到首尾
        await page.keyboard.press('ArrowDown');
        assert.notEqual(await page.evaluate(() => document.activeElement.getAttribute('aria-activedescendant')),
            opened.activeDescendant, '方向键应移动高亮项');
        await page.keyboard.press('End');
        const endId = await page.evaluate(() => document.activeElement.getAttribute('aria-activedescendant'));
        await page.keyboard.press('Home');
        const homeId = await page.evaluate(() => document.activeElement.getAttribute('aria-activedescendant'));
        assert.notEqual(homeId, endId, 'Home/End 应分别到首尾');
        assert.equal(homeId, opened.options[0].id);

        // Esc 关闭并把焦点还给触发器
        await page.keyboard.press('Escape');
        await page.waitForFunction(() => !document.querySelector('.custom-select-wrapper.open'));
        assert.equal(await page.evaluate(() => document.activeElement.classList.contains('custom-select-trigger')), true,
            'Esc 关闭后焦点应回到触发器');
        assert.equal(await trigger.getAttribute('aria-expanded'), 'false');

        // 键盘选中:ArrowDown 打开 → End 跳到末项 → Enter 提交,值写回隐藏的原生 select
        const before = await page.evaluate(() => document.getElementById('theme_select').value);
        await page.keyboard.press('ArrowDown');
        await page.keyboard.press('End');
        await page.keyboard.press('Enter');
        await page.waitForFunction(() => !document.querySelector('.custom-select-wrapper.open'));
        const after = await page.evaluate(() => ({
            value: document.getElementById('theme_select').value,
            text: document.querySelector('#theme_select + .custom-select-wrapper .custom-select-text').textContent,
            selectedAria: document.querySelectorAll('#theme_select + .custom-select-wrapper .custom-select-option[aria-selected="true"]').length,
        }));
        assert.equal(after.value, 'black_switch', 'Enter 应提交末项(黑色主題)');
        assert.notEqual(after.value, before, '提交后值必须变化');
        assert.equal(after.selectedAria, 1, '提交后仅一项 aria-selected=true');
        assert.ok(after.text.length > 0);

        assert.deepEqual(errors, []);
        console.log('A11y UI: PASS (combobox ARIA + arrow/Home/End/Enter/Esc, card entries focusable & Enter/Space activatable, icon-button labels, focus ring, max/restore label sync)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
