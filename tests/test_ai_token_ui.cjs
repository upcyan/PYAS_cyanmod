/* Run with Playwright available: node tests/test_ai_token_ui.cjs [screenshot-dir]
   覆盖:token 累计展示(按模型分账)、切换模型后计数切换、新模型零计数、重置流程。 */
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
            window.tokenTest = {
                model: 'gpt-4o-mini',
                usage: {
                    'gpt-4o-mini': { tokens: 1234, requests: 5 },
                    'qwen2.5:7b': { tokens: 88, requests: 2 },
                },
                resetCalls: [],
                confirms: 0,
                alerts: [],
            };
            const cfg = { first_launch: false, language: 'simplified_switch', theme: 'white_switch', version: 'test', interactive_timeout: 30 };
            const total = () => ({
                tokens: Object.values(window.tokenTest.usage).reduce((sum, item) => sum + item.tokens, 0),
                requests: Object.values(window.tokenTest.usage).reduce((sum, item) => sum + item.requests, 0),
            });
            window.pywebview = { api: {
                get_config: async () => cfg,
                init_ui_ready: async () => true,
                report_ui_error: async () => true,
                get_pending_threat_count: async () => 0,
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => [],
                get_ai_token_usage: async () => ({ model: window.tokenTest.model, usage: window.tokenTest.usage, total: total() }),
                reset_ai_token_usage: async (model) => {
                    window.tokenTest.resetCalls.push(model || null);
                    if (model) delete window.tokenTest.usage[model];
                    else window.tokenTest.usage = {};
                    return { ok: true, model: window.tokenTest.model, usage: window.tokenTest.usage, total: total() };
                },
                save_ai_config: async (url, model) => { window.tokenTest.model = model; return { ok: true }; },
                show_confirm: async () => { window.tokenTest.confirms += 1; return true; },
                show_alert: async (...args) => { window.tokenTest.alerts.push(args); },
                update_config: async (key, value) => { cfg[key] = value; return value; },
            } };
        });
        await page.goto(`http://127.0.0.1:${server.address().port}/templates/index.html`);
        await page.waitForFunction(() => document.querySelector('.app-container').classList.contains('fade-in'));

        await page.locator('.nav-btn[data-target="ai_window"]').click();
        await page.waitForFunction(() => document.getElementById('ai_window').classList.contains('active'));

        const summary = page.locator('#ai_token_summary');
        const resetBtn = page.locator('#ai_token_reset');

        // 1. 当前模型 gpt-4o-mini:展示自己的累计 + 全部模型总计
        await page.waitForFunction(() => document.getElementById('ai_token_summary').textContent.includes('1,234'));
        assert.equal(await summary.textContent(), '1,234 tokens · 5 次请求 · 全部模型累计 1,322 tokens');
        assert.equal(await resetBtn.isDisabled(), false);

        // 2. 切到已用过的模型 qwen2.5:7b:计数切换到该模型自己的账(仍附全部模型总计)
        await page.fill('#ai_model_input', 'qwen2.5:7b');
        await page.locator('#ai_model_input').dispatchEvent('change');
        await page.waitForFunction(() => document.getElementById('ai_token_summary').textContent.includes('88'));
        assert.equal(await summary.textContent(), '88 tokens · 2 次请求 · 全部模型累计 1,322 tokens');
        assert.equal(await page.evaluate(() => window.tokenTest.model), 'qwen2.5:7b');

        // 3. 切到全新模型:零计数空态,重置按钮禁用
        await page.fill('#ai_model_input', 'brand-new-model');
        await page.locator('#ai_model_input').dispatchEvent('change');
        await page.waitForFunction(() => document.getElementById('ai_token_summary').textContent === '暂无消耗记录');
        assert.equal(await resetBtn.isDisabled(), true);

        // 4. 重置流程:确认弹窗 -> 只重置当前模型 -> 空态;其余模型不受影响
        await page.fill('#ai_model_input', 'qwen2.5:7b');
        await page.locator('#ai_model_input').dispatchEvent('change');
        await page.waitForFunction(() => document.getElementById('ai_token_summary').textContent.includes('88'));
        await resetBtn.click();
        await page.waitForFunction(() => window.tokenTest.resetCalls.length === 1);
        assert.deepEqual(await page.evaluate(() => window.tokenTest.resetCalls), ['qwen2.5:7b']);
        assert.equal(await page.evaluate(() => window.tokenTest.confirms), 1, '重置前必须确认');
        assert.equal(await page.evaluate(() => window.tokenTest.alerts.length), 1, '重置后提示');
        await page.waitForFunction(() => document.getElementById('ai_token_summary').textContent === '暂无消耗记录');
        assert.deepEqual(await page.evaluate(() => Object.keys(window.tokenTest.usage)), ['gpt-4o-mini'], '其他模型计数不受影响');

        // 5. 未配置模型时展示提示(切回空模型名)
        await page.fill('#ai_model_input', '');
        await page.locator('#ai_model_input').dispatchEvent('change');
        await page.waitForFunction(() => document.getElementById('ai_token_summary').textContent === '尚未配置模型');

        const output = process.argv[2];
        if (output) {
            fs.mkdirSync(output, { recursive: true });
            await page.locator('.nav-btn[data-target="ai_window"]').click();
            await page.fill('#ai_model_input', 'gpt-4o-mini');
            await page.locator('#ai_model_input').dispatchEvent('change');
            await page.waitForFunction(() => document.getElementById('ai_token_summary').textContent.includes('1,234'));
            await page.screenshot({ path: path.join(output, 'ai-token-usage.png') });
        }

        assert.deepEqual(errors, []);
        console.log('AI token usage UI: PASS (per-model counters, model switching, new model zero state, reset with confirm, no-model hint)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
