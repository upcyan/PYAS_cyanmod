/* 拦截弹窗密度回归(2026-10-19):
   用户反馈「信息要尽量不用滚动就能看全」。真机 720×600 下原布局溢出 142px,
   三处结构性浪费:单条告警仍留 148px 左栏、证据两列两行、页脚两套动作叠加。

   这里锁四条容易回退的结论(全部用真实渲染量,不看截图):
     1. 标准告警在 720×600 下详情区无滚动;
     2. 单条告警不出队列栏,两条以上才出现(且仍不滚动);
     3. 详情区够宽时证据摊成四列一行;
     4. 误报面板打开时收起常规决策区,提交/取消留在可视范围内。

   夹具刻意做成「真机上那种长度」:四行摘要、长路径、两句 AI 理由。
   overflow 允许 0,不允许 1 —— 1px 就会触发滚动条。
*/
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' };

const buildSnapshot = (events, overrides) => Object.assign({
    id: 'a1', title: '进程防护', events, count: events.length,
    theme: 'white_switch', language: 'simplified_switch', can_remember: true,
    identity_summary: 'C:\\fixture\\PYAS_Launcher.exe\nSHA-256: ' + 'a'.repeat(64),
    remaining: null, waiting: '等待您选择；关闭窗口仅收起，不执行操作。', countdown: '',
    allow: '本次允许', block: '拦截',
    summary: '检测到可疑程序正在启动，现已暂停并等待您处理。拦截将终止该进程；放行将恢复其运行。',
    evidence: {
        engine: 'ml', score: 83, score_kind: 'model_probability', category: 'Malware',
        platform: 'WinPE', family: 'General', generic: true,
        raw_label: 'Malware:WinPE/General.83!ml',
    },
    file: {
        name: 'PYAS_Launcher.exe',
        path: 'E:\\Project Files\\PYAS_Cyanmod\\Payload\\PYAS_Launcher.exe',
        sha256: 'b'.repeat(64),
    },
    process: { name: 'PYAS_Launcher.exe', path: 'E:\\Project Files\\PYAS_Cyanmod\\Payload\\PYAS_Launcher.exe' },
    ai: {
        state: 'ready', verdict: 'block', label: 'AI 建议拦截',
        hint: '仅有ML通用检测，缺少具体恶意行为证据；路径似开发项目但不足以证明合法，证据不足，暂拦截。',
    },
    message: '检测到可疑程序正在启动。\n进程：PYAS_Launcher.exe',
    fp: {
        button: '如果您认为此拦截为误报，点此解除',
        scope_this: '仅解除此检测结果', scope_file: '解除此文件的所有检测',
        reason: '原因', reasons: [['false_positive', '确认是误报']],
        note: '补充说明（可选）', submit: '提交', cancel: '取消',
    },
}, overrides);

(async () => {
    const root = path.resolve(__dirname, '../Interface');
    const server = http.createServer((req, res) => {
        const file = path.resolve(root, '.' + new URL(req.url, 'http://localhost').pathname);
        if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
            res.writeHead(404); res.end(); return;
        }
        res.setHeader('Content-Type', MIME[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const url = `http://127.0.0.1:${server.address().port}/templates/threat.html`;
    let browser;
    const errors = [];

    const open = async snapshot => {
        const page = await browser.newPage({ viewport: { width: 720, height: 600 } });
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript(snap => {
            window.pywebview = { api: {
                ready: async () => true, snapshot: async () => snap, decide: async () => true,
                minimize: async () => true, set_focus: async () => true,
                report_false_positive: async () => true,
            } };
        }, snapshot);
        await page.goto(url);
        await page.waitForFunction(() => !document.getElementById('threat_block').disabled);
        await page.waitForTimeout(250);
        return page;
    };
    const overflow = page => page.evaluate(() => {
        const detail = document.querySelector('.threat-detail');
        return detail.scrollHeight - detail.clientHeight;
    });

    try {
        browser = await chromium.launch({
            executablePath: process.env.EDGE_EXECUTABLE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
            headless: true,
        });

        // 1 + 2a: 单条告警 —— 无左栏、无滚动
        const single = buildSnapshot([{ id: 'a1', title: '进程防护', count: 1, active: true }]);
        let page = await open(single);
        assert.equal(await page.locator('.threat-queue').isVisible(), false,
            '单条告警不该显示队列栏(1 条列表没有信息量,却吃掉 118px 宽度)');
        assert.ok(await overflow(page) <= 0, `单条告警仍有 ${await overflow(page)}px 溢出`);
        const cols = await page.evaluate(() =>
            getComputedStyle(document.querySelector('.detection-grid')).gridTemplateColumns.split(' ').length);
        assert.equal(cols, 4, '详情区够宽时证据应摊成四列一行');
        await page.close();

        // 2b: 三条告警 —— 左栏出现,仍然不滚动
        const multi = buildSnapshot([
            { id: 'a1', title: '进程防护', count: 1, active: true },
            { id: 'b1', title: '文件防护', count: 2, active: false },
            { id: 'c1', title: '网络防护', count: 1, active: false },
        ]);
        page = await open(multi);
        assert.equal(await page.locator('.threat-queue').isVisible(), true,
            '两条以上待处理告警必须显示队列栏');
        assert.ok(await overflow(page) <= 0, `三条告警时仍有 ${await overflow(page)}px 溢出`);
        await page.close();

        // 3: 误报面板 —— 常规决策区收起,提交/取消必须在视口内
        page = await open(single);
        await page.click('#threat_fp');
        await page.waitForTimeout(200);
        assert.equal(await page.locator('.threat-actions').isVisible(), false,
            '误报面板自带提交/取消,常规决策区应让位');
        assert.equal(await page.locator('.threat-meta').isVisible(), false,
            '误报面板打开时重复确认不适用,应一并收起');
        const submit = await page.locator('#threat_fp_submit').boundingBox();
        assert.ok(submit && submit.y + submit.height <= 600, '提交按钮必须留在视口内');
        const detailOverflow = await page.evaluate(() => {
            const footer = document.querySelector('.threat-footer');
            return footer.scrollHeight - footer.clientHeight;
        });
        assert.ok(detailOverflow <= 0, `误报面板不该让页脚自身滚动(${detailOverflow}px)`);
        await page.close();

        assert.deepEqual(errors, []);
        console.log('Threat density UI: PASS (单条/多条无滚动, 四列证据, 误报面板不顶飞按钮)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
