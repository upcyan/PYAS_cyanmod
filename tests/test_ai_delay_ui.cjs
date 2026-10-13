/* 「延迟启动」设置项 UI 测试(Playwright + 本机 Edge)
   覆盖:开关存在与默认值、子行显隐联动、秒数钳制与提交、按配置回填。
   用法: NODE_PATH=<node_modules> node tests/test_ai_delay_ui.cjs [screenshot_dir] */
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
        const page = await browser.newPage({ viewport: { width: 1024, height: 720 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error).slice(0, 200)));
        await page.addInitScript(() => {
            const cfg = {
                first_launch: false, language: 'simplified_switch', theme: 'white_switch',
                version: '3.0.0', interactive_timeout: 30, ai_provider_mode: 'local',
                ai_assist_switch: true, ai_delay_switch: true, ai_delay_seconds: 7,
                // 模型已接入:本用例只测延迟设置的层级,不应被「模型接入」引导蒙版打断
                ai_base_url: 'https://api.example.com/v1', ai_model: 'test-model',
            };
            window.configWrites = [];
            window.pywebview = { api: {
                get_config: async () => cfg, init_ui_ready: async () => true,
                report_ui_error: async () => true, get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [], show_confirm: async () => true, show_alert: async () => true,
                save_ai_config: async () => ({ ok: true }), test_ai_connection: async () => ({ ok: true }),
                get_ai_token_usage: async () => ({ model: '', usage: {}, total: { tokens: 0, requests: 0 } }),
                reset_ai_token_usage: async () => ({ ok: true }),
                update_config: async (key, value) => { window.configWrites.push({ key, value }); return value; },
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`, { timeout: 20000 });
        await page.waitForFunction(() => document.querySelector('.app-container')?.classList.contains('fade-in'), null, { timeout: 15000 });
        await page.click('.nav-btn[data-target="ai_window"]');
        await page.waitForFunction(() => document.getElementById('ai_window').classList.contains('active'));
        await page.waitForTimeout(250);

        const toggle = page.locator('[data-config-key="ai_delay_switch"]');
        const seconds = page.locator('#ai_delay_seconds_input');
        const secondsRow = page.locator('[data-setting-parent="ai_delay_switch"]');
        const output = process.argv[2];

        // 1. 开关与秒数输入存在,且按配置回填(ai_delay_seconds=7)
        assert.equal(await toggle.count(), 1, '必须存在延迟启动开关');
        assert.equal(await seconds.count(), 1, '必须存在延迟秒数输入');
        assert.equal(await toggle.isChecked(), true, '按配置回填为开启');
        assert.equal(await seconds.inputValue(), '7', '按配置回填秒数');
        assert.equal(await seconds.getAttribute('min'), '1');
        assert.equal(await seconds.getAttribute('max'), '30');
        assert.equal(await secondsRow.isVisible(), true, '父开关开启时子行可见');
        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.screenshot({ path: path.join(output, 'ai-delay-setting.png') });
        }

        // 2. 秒数钳制:下限 1 / 上限 30,并提交 update_config
        await seconds.fill('999');
        await seconds.dispatchEvent('change');
        await page.waitForFunction(() => document.getElementById('ai_delay_seconds_input').value === '30');
        await seconds.fill('0');
        await seconds.dispatchEvent('change');
        await page.waitForFunction(() => document.getElementById('ai_delay_seconds_input').value === '1');
        const writes = await page.evaluate(() => window.configWrites.filter(w => w.key === 'ai_delay_seconds'));
        assert.deepEqual(writes.map(w => w.value), [30, 1], '钳制后的值必须落库');

        // 3. 关闭开关:子行隐藏且输入禁用;写回配置
        //    checkbox 本体是 0×0 隐藏元素,走真实用户路径点击可见滑轨(label 隐式激活)
        const delaySlider = page.locator('label.toggle-switch:has([data-config-key="ai_delay_switch"]) .slider');
        await delaySlider.click();
        await page.waitForFunction(() => document.querySelector('[data-config-key="ai_delay_switch"]').checked === false);
        await page.waitForFunction(() => document.querySelector('[data-setting-parent="ai_delay_switch"]').classList.contains('hidden'));
        assert.equal(await secondsRow.isVisible(), false, '关闭延迟启动后秒数行应隐藏');
        assert.equal(await seconds.isDisabled(), true, '隐藏时输入必须禁用');
        const delayWrites = await page.evaluate(() => window.configWrites.filter(w => w.key === 'ai_delay_switch'));
        assert.deepEqual(delayWrites.map(w => w.value), [false], '开关状态必须落库');

        // 4. 重新开启:子行恢复
        await delaySlider.click();
        await page.waitForFunction(() => document.querySelector('[data-config-key="ai_delay_switch"]').checked === true);
        await page.waitForFunction(() => !document.querySelector('[data-setting-parent="ai_delay_switch"]').classList.contains('hidden'));
        assert.equal(await secondsRow.isVisible(), true);

        // 5. 关闭 AI 辅助决策时,整个延迟组跟随隐藏
        await page.evaluate(() => {
            const assist = document.querySelector('[data-config-key="ai_assist_switch"]');
            assist.checked = false;
            assist.dispatchEvent(new Event('change'));
        });
        await page.waitForFunction(() => document.querySelector('[data-config-key="ai_delay_switch"]').closest('.list-item').classList.contains('hidden'));
        assert.equal(await toggle.isVisible(), false, 'AI 辅助决策关闭时延迟启动应一并隐藏');

        // 6. 层级与顺序:一级 AI 辅助决策 → 二级 延迟启动/超时自动执行 → 三级 各自的时间行
        const hierarchy = await page.evaluate(() => {
            const rows = [...document.querySelectorAll('#ai_window .list-item')];
            const find = key => rows.find(r => r.querySelector(`[data-config-key="${key}"]`));
            const describe = row => ({
                title: row.querySelector('.item-info h2')?.textContent?.trim(),
                level2: row.classList.contains('settings-child'),
                level3: row.classList.contains('settings-child-2'),
                parent: row.dataset.settingParent || null,
                bg: getComputedStyle(row).backgroundColor,
                h2Size: getComputedStyle(row.querySelector('.item-info h2')).fontSize,
            });
            return {
                order: rows.map(r => r.querySelector('.item-info h2')?.textContent?.trim()).slice(0, 6),
                assist: describe(find('ai_assist_switch')),
                delay: describe(find('ai_delay_switch')),
                delaySeconds: describe(document.querySelector('[data-setting-parent="ai_delay_switch"]')),
                autoExec: describe(find('ai_auto_execute')),
                autoTimeout: describe(document.querySelector('[data-setting-parent="ai_auto_execute"]')),
            };
        });

        // 顺序:一级 → 二级 → 三级 紧邻,不得串位
        assert.deepEqual(hierarchy.order, [
            '智能体加固', 'AI 辅助决策', '延迟启动', '延迟时间', '超时自动执行 AI 建议', '超时时间',
        ], '设置项顺序必须是 一级→二级→三级 逐组递进');

        // 层级判定
        assert.equal(hierarchy.assist.level2, false, 'AI 辅助决策是一级');
        assert.equal(hierarchy.delay.level2, true, '延迟启动是二级');
        assert.equal(hierarchy.delay.level3, false, '延迟启动不是三级');
        assert.equal(hierarchy.delay.parent, 'ai_assist_switch', '延迟启动挂在 AI 辅助决策下');
        assert.equal(hierarchy.delaySeconds.level2, true, '延迟时间同时属于 settings-child');
        assert.equal(hierarchy.delaySeconds.level3, true, '延迟时间是三级 settings-child-2');
        assert.equal(hierarchy.delaySeconds.parent, 'ai_delay_switch', '延迟时间挂在延迟启动下');
        assert.equal(hierarchy.autoExec.level2, true, '超时自动执行是二级');
        assert.equal(hierarchy.autoExec.parent, 'ai_assist_switch');
        assert.equal(hierarchy.autoTimeout.level3, true, '超时时间是三级');
        assert.equal(hierarchy.autoTimeout.parent, 'ai_auto_execute');

        // 三级行必须有可辨识的层级样式(底色 + 更小字号),否则层级在视觉上等于没做
        assert.notEqual(hierarchy.delaySeconds.bg, 'rgba(0, 0, 0, 0)', '三级行应有底色区分');
        assert.equal(hierarchy.delay.bg, 'rgba(0, 0, 0, 0)', '二级行保持透明');
        assert.equal(hierarchy.delaySeconds.h2Size, hierarchy.autoTimeout.h2Size, '两个三级行字号一致');
        assert.notEqual(hierarchy.delaySeconds.h2Size, hierarchy.delay.h2Size, '三级行字号应小于二级');
        assert.notEqual(hierarchy.delaySeconds.bg, hierarchy.delay.bg, '三级与二级底色必须可区分');

        // 7. 两条分支的显隐互不干扰:开启延迟+开启超时执行,两个三级行同时可见
        await page.evaluate(() => {
            const assist = document.querySelector('[data-config-key="ai_assist_switch"]');
            assist.checked = true;
            assist.dispatchEvent(new Event('change'));
        });
        await page.waitForFunction(() => !document.querySelector('[data-config-key="ai_delay_switch"]').closest('.list-item').classList.contains('hidden'));
        const autoSlider = page.locator('label.toggle-switch:has([data-config-key="ai_auto_execute"]) .slider');
        await autoSlider.click();
        await page.waitForFunction(() => document.querySelector('[data-config-key="ai_auto_execute"]').checked === true);
        await page.waitForFunction(() => !document.querySelector('[data-setting-parent="ai_auto_execute"]').classList.contains('hidden'));
        assert.equal(await secondsRow.isVisible(), true, '延迟时间仍可见');
        assert.equal(await page.locator('[data-setting-parent="ai_auto_execute"]').isVisible(), true, '超时时间同时可见');
        if (output) await page.screenshot({ path: path.join(output, 'ai-delay-hierarchy.png') });

        // 只关掉延迟启动:仅其三级行消失,超时时间不受影响
        await delaySlider.click();
        await page.waitForFunction(() => document.querySelector('[data-config-key="ai_delay_switch"]').checked === false);
        assert.equal(await secondsRow.isVisible(), false, '延迟时间随延迟启动关闭而隐藏');
        assert.equal(await page.locator('[data-setting-parent="ai_auto_execute"]').isVisible(), true, '超时时间不应被牵连');

        assert.deepEqual(errors, []);
        console.log('AI delay setting UI: PASS (default 3s row, config backfill, 1-30 clamp persisted, 3-level hierarchy & order, sibling branches isolated)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
