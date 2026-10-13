/* Run with Playwright available: node tests/test_threat_ai_ui.cjs [screenshot-dir]
   覆盖:AI 分析中七彩流光边、分析后面板结论、建议动作点击、失败态、未启用态。 */
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
        const page = await browser.newPage({ viewport: { width: 860, height: 560 } });
        const errors = [];
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript(() => {
            window.aiTest = { state: 'analyzing', verdict: '', label: 'AI 分析中…', hint: '', decisions: [], blank: false, focusReports: [] };
            window.pywebview = { api: {
                ready: async () => true,
                snapshot: async () => (window.aiTest.blank ? null : ({
                    id: 'r1', title: '网络防护', message: '检测到进程正连接已知恶意地址。', count: 1,
                    events: [{ id: 'net', title: '网络防护', count: 1, active: true }],
                    can_remember: true, identity_summary: 'C:\\fixture\\example.exe',
                    process: { name: 'demo.exe', path: 'C:\\fixture\\demo.exe' },
                    theme: 'white_switch', language: 'simplified_switch', remaining: null,
                    waiting: '等待您选择', allow: '本次允许', block: '拦截', countdown: '',
                    ai: window.aiTest.state ? {
                        state: window.aiTest.state, verdict: window.aiTest.verdict,
                        label: window.aiTest.label, hint: window.aiTest.hint,
                    } : null,
                })),
                decide: async (id, choice) => { window.aiTest.decisions.push({ id, choice }); return true; },
                set_focus: async (state) => { window.aiTest.focusReports.push(state); return true; },
                minimize: async () => true,
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/threat.html`);
        await page.getByRole('button', { name: '拦截', exact: true }).waitFor();
        await page.waitForFunction(() => !document.getElementById('threat_block').disabled);

        // 0b. 前后台上报:主程序据此决定 AI 结果要不要另外推送
        assert.ok(await page.evaluate(() => window.aiTest.focusReports.length > 0),
            '弹窗必须在加载后上报一次前后台状态');
        await page.evaluate(() => {
            window.dispatchEvent(new Event('blur'));
            window.dispatchEvent(new Event('focus'));
        });
        assert.deepEqual(await page.evaluate(() => window.aiTest.focusReports.slice(-2)), [false, true],
            '失焦/获焦必须如实上报');

        // 0. 永久允许=放行语义:绿色实底(白字,对比度达标);拦截保持主色实底
        const permanentStyle = await page.evaluate(() => {
            const style = getComputedStyle(document.getElementById('threat_permanent'));
            return { bg: style.backgroundColor, color: style.color };
        });
        assert.equal(permanentStyle.bg, 'rgb(30, 126, 52)');
        assert.equal(permanentStyle.color, 'rgb(255, 255, 255)');

        const aiButton = page.locator('#threat_ai');
        const panel = page.locator('#ai_result');

        // 1. 分析中:按钮可见置灰、带流光类、伪元素动画名为 ai-rainbow-rotate;面板隐藏
        await page.waitForFunction(() => !document.getElementById('threat_ai').hidden);
        assert.equal(await aiButton.getAttribute('class'), 'action-btn modern-btn ai-btn is-analyzing');
        assert.equal(await aiButton.isDisabled(), true);
        assert.equal(await page.locator('#threat_ai_label').textContent(), 'AI 分析中…');
        assert.equal(await panel.isVisible(), false, 'panel must stay hidden while analyzing');
        const anim = await page.evaluate(() => {
            const style = getComputedStyle(document.getElementById('threat_ai'), '::before');
            return { name: style.animationName, duration: style.animationDuration, timing: style.animationTimingFunction };
        });
        assert.equal(anim.name, 'ai-rainbow-rotate');
        assert.equal(anim.duration, '2.6s');
        assert.equal(anim.timing, 'linear');

        // 1b. 流光必须是「动态且不掉边」:圆形七彩盘远大于按钮对角线,旋转时覆盖恒定;
        //     内衬底色带模糊羽化,彩色由外缘向内渐变过渡(不是硬切边)
        const rainbow = await page.evaluate(() => {
            const button = document.getElementById('threat_ai');
            const box = button.getBoundingClientRect();
            const before = getComputedStyle(button, '::before');
            const after = getComputedStyle(button, '::after');
            return {
                radius: before.borderRadius,
                width: parseFloat(before.width),
                diagonal: Math.hypot(box.width, box.height),
                afterFilter: after.filter,
                afterInset: after.top,
            };
        });
        assert.equal(rainbow.radius, '50%', 'rainbow must be a disc so rotation never uncovers the button');
        assert.ok(rainbow.width > rainbow.diagonal * 1.5,
            `disc (${rainbow.width}px) must dwarf button diagonal (${rainbow.diagonal.toFixed(1)}px)`);
        assert.ok(rainbow.afterFilter.includes('blur'), 'inner cover must be feathered (inward gradient), got ' + rainbow.afterFilter);
        assert.equal(rainbow.afterInset, '4px');
        const output = process.argv[2];
        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.screenshot({ path: path.join(output, 'threat-ai-analyzing.png') });
        }

        // 1c. 延迟启动:按钮显示倒计时标签,不带流光,不显示结论面板(用户可先行决策跳过分析)
        await page.evaluate(() => {
            Object.assign(window.aiTest, {
                state: 'delay', verdict: '', label: '3 秒后启动 AI 决策',
                hint: '延迟启动中：现在自行决定即可完全跳过 AI 分析，不消耗 token。',
            });
        });
        await page.waitForFunction(() => !document.getElementById('threat_ai').classList.contains('is-analyzing'));
        assert.equal(await aiButton.getAttribute('class'), 'action-btn modern-btn ai-btn', 'delay 态不得出现流光');
        assert.equal(await page.locator('#threat_ai_label').textContent(), '3 秒后启动 AI 决策');
        assert.equal(await aiButton.isDisabled(), true, 'delay 期不可点击(尚无建议)');
        assert.equal(await panel.isVisible(), false, 'delay 期不显示结论面板');
        assert.ok((await aiButton.getAttribute('title')).includes('token'), 'delay 期应给出省 token 的悬停说明');

        // 1d. 倒计时:后端每次快照重算剩余秒数,界面必须跟着刷新(不能停在首次的读数)
        await page.evaluate(() => { window.aiTest.label = '2 秒后启动 AI 决策'; });
        await page.waitForFunction(() => document.getElementById('threat_ai_label').textContent === '2 秒后启动 AI 决策', null, { timeout: 4000 });
        await page.evaluate(() => { window.aiTest.label = '1 秒后启动 AI 决策'; });
        await page.waitForFunction(() => document.getElementById('threat_ai_label').textContent === '1 秒后启动 AI 决策', null, { timeout: 4000 });

        // 2. 分析完成(建议拦截):按钮可点击,面板展示结论+原因
        await page.evaluate(() => {
            Object.assign(window.aiTest, {
                state: 'ready', verdict: 'block',
                label: 'AI 建议拦截', hint: '该地址命中恶意 C2 名单,且进程无有效签名。',
            });
        });
        await page.waitForFunction(() => !document.getElementById('threat_ai').disabled);
        assert.equal(await aiButton.getAttribute('class'), 'action-btn modern-btn ai-btn', 'rainbow class removed after analysis');
        assert.equal(await page.evaluate(() => getComputedStyle(document.getElementById('threat_ai'), '::before').animationName),
            'none', 'rainbow animation must stop the moment analysis completes');
        assert.equal(await panel.isVisible(), true);
        assert.equal(await page.locator('#ai_result_title').textContent(), 'AI 分析结果');
        const verdictChip = page.locator('#ai_result_verdict');
        assert.equal(await verdictChip.textContent(), 'AI 建议拦截');
        assert.equal(await verdictChip.getAttribute('class'), 'ai-result-verdict verdict-block');
        assert.equal(await page.locator('#ai_result_reason').textContent(), '该地址命中恶意 C2 名单,且进程无有效签名。');
        if (output) await page.screenshot({ path: path.join(output, 'threat-ai-ready-block.png') });

        // 3. 点击建议动作:执行 AI 结论(block)
        await aiButton.click();
        await page.waitForFunction(() => window.aiTest.decisions.length === 1);
        assert.deepEqual(await page.evaluate(() => window.aiTest.decisions), [{ id: 'r1', choice: 'block' }]);

        // 4. 建议放行:chip 用允许色
        await page.evaluate(() => {
            window.aiTest.decisions.length = 0;
            Object.assign(window.aiTest, { state: 'ready', verdict: 'allow', label: 'AI 建议放行', hint: '文件签名有效,行为符合安装器特征。' });
        });
        await page.waitForFunction(() => document.getElementById('ai_result_verdict').classList.contains('verdict-allow'));
        assert.equal(await page.locator('#ai_result_verdict').textContent(), 'AI 建议放行');
        await aiButton.click();
        await page.waitForFunction(() => window.aiTest.decisions.length === 1);
        assert.deepEqual(await page.evaluate(() => window.aiTest.decisions), [{ id: 'r1', choice: 'allow' }]);

        // 5. 分析失败:面板显示不可用标题+原因,按钮保持置灰
        await page.evaluate(() => {
            Object.assign(window.aiTest, { state: 'failed', verdict: '', label: 'AI 建议不可用', hint: 'AI 服务未返回有效建议;已保持等待您决定,不会自动放行。' });
        });
        await page.waitForFunction(() => document.getElementById('ai_result_verdict').classList.contains('verdict-failed'));
        assert.equal(await page.locator('#ai_result_title').textContent(), 'AI 分析不可用');
        assert.equal(await aiButton.isDisabled(), true);
        if (output) await page.screenshot({ path: path.join(output, 'threat-ai-failed.png') });

        // 6. 未启用 AI:按钮与面板都隐藏
        await page.evaluate(() => { window.aiTest.state = ''; });
        await page.waitForFunction(() => document.getElementById('threat_ai').hidden);
        assert.equal(await panel.isVisible(), false);

        // 7. 深色主题下面板与流光仍工作(主题变量驱动)
        await page.evaluate(() => {
            Object.assign(window.aiTest, { state: 'ready', verdict: 'block', label: 'AI 建议拦截', hint: '深色主题结论。' });
        });
        await page.waitForFunction(() => document.getElementById('ai_result').classList.contains('hidden') === false);
        await page.evaluate(() => window.PyasTheme.apply('black_switch'));
        await page.waitForFunction(() => getComputedStyle(document.documentElement).getPropertyValue('--bg-panel').trim() === 'rgb(28, 28, 30)');
        assert.equal(await panel.isVisible(), true);
        if (output) await page.screenshot({ path: path.join(output, 'threat-ai-dark.png') });

        // 8. 告警消失(snapshot 为空):「分析中」状态与流光立即清除,不残留
        await page.evaluate(() => {
            Object.assign(window.aiTest, { blank: true, state: 'analyzing', verdict: '', label: 'AI 分析中…' });
        });
        await page.waitForFunction(() => document.getElementById('threat_ai').hidden);
        assert.equal(await aiButton.getAttribute('class'), 'action-btn modern-btn ai-btn', 'stale analyzing class must be cleared');
        assert.equal(await page.evaluate(() => getComputedStyle(document.getElementById('threat_ai'), '::before').animationName),
            'none', 'rainbow must not linger after the alert is gone');
        assert.equal(await panel.isVisible(), false);

        assert.deepEqual(errors, []);
        console.log('Threat AI UI: PASS (dynamic rainbow edge w/ inward feather, disc coverage, delay state w/o analysis, result panel, block/allow actions, stop-on-complete, cleared-when-gone, failed state, disabled state, dark theme)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
