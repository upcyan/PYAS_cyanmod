/* 「AI 辅助决策 → 模型接入」引导蒙版 UI 测试(Playwright + 本机 Edge)
   覆盖:确认后模型未接入才引导、蒙版四块围出的洞口对准「模型接入」且不覆盖它、
        洞口外点击被拦截、右上角叉号可关闭、模型已接入时不打扰、主开关状态保持。
   用法: NODE_PATH=<node_modules> node tests/test_ai_guide_ui.cjs [screenshot_dir] */
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
                ai_model: '', ai_base_url: '', ai_assist_switch: false,
                ai_delay_switch: true, ai_delay_seconds: 3, ai_auto_execute: false,
            };
            window.pywebview = { api: {
                get_config: async () => cfg, init_ui_ready: async () => true,
                report_ui_error: async () => true, get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [], show_confirm: async () => true, show_alert: async () => true,
                save_ai_config: async () => ({ ok: true }), test_ai_connection: async () => ({ ok: true }),
                get_ai_token_usage: async () => ({ model: '', usage: {}, total: { tokens: 0, requests: 0 } }),
                reset_ai_token_usage: async () => ({ ok: true }),
                update_config: async (key, value) => value,
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`, { timeout: 20000 });
        await page.waitForFunction(() => document.querySelector('.app-container')?.classList.contains('fade-in'), null, { timeout: 15000 });
        await page.click('.nav-btn[data-target="ai_window"]');
        await page.waitForFunction(() => document.getElementById('ai_window').classList.contains('active'));
        await page.waitForTimeout(300);

        const output = process.argv[2];
        const assistInput = page.locator('[data-config-key="ai_assist_switch"]');
        const assistLabel = assistInput.locator('xpath=..');
        const guide = page.locator('#ai_model_guide');

        // 0. 前置:模型未配置 + 开关默认关
        assert.equal(await assistInput.isChecked(), false, 'ai_assist_switch 初始应为关闭');
        assert.equal(await guide.count(), 0, '未开启前不应有引导蒙版');

        // 1. 开启并确认 → 模型未接入,弹出引导蒙版
        await assistLabel.click();
        await page.waitForSelector('#ai_model_guide', { timeout: 5000 });
        assert.equal(await assistInput.isChecked(), true, '确认后主开关应保持开启');
        assert.equal(await guide.count(), 1, '模型未接入时必须出现引导蒙版');

        // 2. 结构:四块 dim + 高亮环 + 引导文字 + 右上角叉号
        const structure = await guide.evaluate((layer) => {
            const parts = [...layer.querySelectorAll('.ai-guide-dim')].map(el => el.dataset.part);
            const tip = layer.querySelector('.ai-guide-tip');
            const close = layer.querySelector('.ai-guide-close');
            return {
                parts: parts.sort(),
                hasRing: !!layer.querySelector('.ai-guide-ring'),
                title: layer.querySelector('#ai_guide_title')?.textContent?.trim() || '',
                desc: layer.querySelector('#ai_guide_desc')?.textContent?.trim() || '',
                closeAria: close?.getAttribute('aria-label') || '',
                role: layer.getAttribute('role'),
                ariaModal: layer.getAttribute('aria-modal'),
                closeRight: close ? (window.innerWidth - close.getBoundingClientRect().right) : -1,
                closeTop: close ? close.getBoundingClientRect().top : -1,
                tipVisible: tip ? tip.getBoundingClientRect().width > 0 : false,
            };
        });
        assert.deepEqual(structure.parts, ['bottom', 'left', 'right', 'top'], '必须四块 dim 围出洞口');
        assert.equal(structure.hasRing, true, '必须有高亮环标出目标区块');
        assert.ok(structure.title.length > 0, '必须有引导标题');
        assert.ok(structure.desc.length > 0, '必须有引导说明文字');
        assert.ok(structure.closeAria.length > 0, '叉号必须有 aria-label');
        assert.equal(structure.role, 'dialog', '引导层应为 dialog');
        assert.equal(structure.ariaModal, 'true', '引导层应为 aria-modal');
        assert.ok(structure.closeRight >= 0 && structure.closeRight < 80, '叉号应贴在蒙版右上角');
        assert.ok(structure.closeTop >= 0 && structure.closeTop < 80, '叉号应贴在上边缘');
        assert.equal(structure.tipVisible, true, '引导文字必须可见');

        // 3. 洞口必须正好对准「模型接入」:没有任何 dim 与该区块相交
        // Enabling assistance expands rows and starts a smooth scroll; await actual alignment.
        await page.waitForFunction(() => {
            const layer = document.getElementById('ai_model_guide');
            const target = document.getElementById('ai_model_group').getBoundingClientRect();
            return [...layer.querySelectorAll('.ai-guide-dim')].every(el => {
                const d = el.getBoundingClientRect();
                return d.right <= target.left + .5 || d.left >= target.right - .5
                    || d.bottom <= target.top + .5 || d.top >= target.bottom - .5;
            });
        });
        const hole = await page.evaluate(() => {
            const layer = document.getElementById('ai_model_guide');
            const target = document.getElementById('ai_model_group').getBoundingClientRect();
            const dims = [...layer.querySelectorAll('.ai-guide-dim')].map(el => el.getBoundingClientRect());
            const intersect = dims.filter(d => !(d.right <= target.left + 0.5 || d.left >= target.right - 0.5
                || d.bottom <= target.top + 0.5 || d.top >= target.bottom - 0.5));
            const cx = target.left + target.width / 2;
            const cy = target.top + Math.min(24, target.height / 2);
            const hitEl = document.elementFromPoint(cx, cy);
            return {
                intersecting: intersect.length,
                hitInside: !!(hitEl && hitEl.closest('#ai_model_group')),
                modeSelectHit: (() => {
                    // 原生 select 被自定义下拉替代(display:none),要测可见的 trigger
                    const trigger = document.querySelector('#ai_mode_select + .custom-select-wrapper .custom-select-trigger');
                    if (!trigger) return null;
                    const r = trigger.getBoundingClientRect();
                    if (!r.width || !r.height) return null;
                    const el = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
                    return !!(el && el.closest('#ai_model_group'));
                })(),
                urlInputHit: (() => {
                    const r = document.getElementById('ai_base_url_input').getBoundingClientRect();
                    const el = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
                    return !!(el && el.closest('#ai_model_group'));
                })(),
                topDimHeight: dims[0] ? dims[0].height : -1,
            };
        });
        assert.equal(hole.intersecting, 0, '洞口的「模型接入」区块不能被任何遮罩覆盖');
        assert.equal(hole.hitInside, true, '洞口中心应命中模型接入区块(可读可点)');
        assert.equal(hole.urlInputHit, true, '洞口内的服务地址输入框应可点击');
        assert.equal(hole.modeSelectHit, true, '洞口内的模式下拉(自定义 trigger)应可点击');
        assert.ok(hole.topDimHeight > 0, '模型接入之上的区域必须被蒙版盖住');

        // 4. 焦点已到模型接入:首个待填字段获得焦点(必须在下面的拦截点击之前验,点击会移走焦点)
        const focused = await page.evaluate(() => document.activeElement?.id || '');
        assert.ok(['ai_base_url_input', 'ai_model_input', 'ai_mode_select'].includes(focused),
            `焦点应落在模型接入区,实际: ${focused}`);

        // 5. 洞口外(左侧导航)的点击必须被拦下,不能穿透到下层
        const navHome = await page.locator('.nav-btn[data-target="home_window"]').boundingBox();
        await page.mouse.click(navHome.x + navHome.width / 2, navHome.y + navHome.height / 2);
        await page.waitForTimeout(250);
        assert.equal(await page.locator('#ai_window.active').count(), 1, '蒙版必须拦下洞口外的点击');

        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.screenshot({ path: path.join(output, 'ai-model-guide.png') });
        }

        // 6. 右上角叉号关闭
        await page.click('#ai_model_guide .ai-guide-close');
        await page.waitForTimeout(200);
        assert.equal(await guide.count(), 0, '叉号必须能关闭引导蒙版');
        assert.equal(await assistInput.isChecked(), true, '关闭引导不影响已确认的主开关');

        // 7. 模型已接入时不再打扰
        await page.fill('#ai_base_url_input', 'https://api.example.com/v1');
        await page.fill('#ai_model_input', 'test-model');
        await assistLabel.click();                       // 关
        await page.waitForTimeout(150);
        assert.equal(await assistInput.isChecked(), false, '可再次关闭');
        await assistLabel.click();                       // 再开 + 确认
        await page.waitForTimeout(400);
        assert.equal(await guide.count(), 0, '模型已接入时不应再出现引导蒙版');
        assert.equal(await assistInput.isChecked(), true, '此时开关应正常开启');

        // 8. 云端模式缺 API 金钥同样应引导
        await page.evaluate(() => {
            const select = document.getElementById('ai_mode_select');
            select.value = 'cloud';
            select.dispatchEvent(new Event('change', { bubbles: true }));
        });
        await page.waitForTimeout(150);
        await assistLabel.click();
        await page.waitForTimeout(150);
        await assistLabel.click();
        await page.waitForTimeout(400);
        assert.equal(await guide.count(), 1, '云端模式缺 API 金钥应重新引导');
        await page.evaluate(() => window.closeAiModelGuide());

        assert.deepEqual(errors, [], `页面不应有 JS 报错: ${errors.join(' | ')}`);
        console.log('AI model guide UI: PASS (confirm gate, mask hole, click block, close button, configured skip, cloud key check)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => {
    console.error('AI model guide UI: FAIL -', error.message);
    process.exit(1);
});
