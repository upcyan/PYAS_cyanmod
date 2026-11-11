/* 扫描页进度路径中段省略(Playwright + 本机 Edge)
   回归(2026-11-11):长路径曾以 overflow-x:auto 呈现,横向滚动条占掉进度区。
   现在:
   1. 长路径压缩成「最前面路径 + … + 文件名」,不出横向滚动条(overflow:hidden)
   2. 窗口缩放时按新宽度重新计算省略位置(变窄更狠、变宽还原头部)
   3. 短路径原样显示;目录结尾路径保留「段名/」;超长文件名保住扩展名结尾
   4. finishScan 的完成消息不能被 resize 时的旧路径覆盖(消息态/路径态互斥)
   用法: NODE_PATH=<node_modules> node tests/test_scan_progress_path_ui.cjs */
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const ROOT = path.resolve(__dirname, '../Interface');
const LONG_PATH = 'C:/Users/cadw/AppData/Local/Microsoft/Edge/User Data/Default/Extensions/'
    + 'ekhngnigjebipkidcgknelmjmjeleph/1.8.12302_0/resource/public/' + 'x'.repeat(60) + '/manifest.json';

(async () => {
    const server = http.createServer((req, res) => {
        const file = path.resolve(ROOT, '.' + new URL(req.url, 'http://x').pathname);
        if (!file.startsWith(ROOT + path.sep) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
        const mime = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml' };
        res.setHeader('Content-Type', mime[path.extname(file)] || 'application/octet-stream');
        res.end(fs.readFileSync(file));
    });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const url = `http://127.0.0.1:${server.address().port}/templates/index.html`;

    const browser = await chromium.launch({
        executablePath: process.env.EDGE_EXECUTABLE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
        headless: true,
    });
    const page = await browser.newPage({ viewport: { width: 1000, height: 760 } });
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    await page.addInitScript(() => {
        window.pywebview = { api: {
            get_config: async () => ({ first_launch: false, language: 'simplified_switch', theme: 'white_switch',
                process_switch: true, document_switch: true, system_switch: true, network_switch: true, driver_switch: true }),
            init_ui_ready: async () => true, report_ui_error: async () => true,
            get_pending_threat_count: async () => 0,
            get_pending_threat_queue: async () => ({ count: 0, events: [] }),
            get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
            get_logs: async () => [],
            remove_list_items: async () => true,
            manage_named_list: async () => true,
            extract_list_items: async () => true,
            select_folder: async () => [],
            show_alert: async () => true, show_confirm: async () => true,
        } };
    });
    await page.goto(url);
    await page.waitForFunction(() => document.querySelector('.app-container').classList.contains('fade-in'));

    // 切到扫描页(progress_text 必须可见才有宽度),并摆出真实扫描态:
    // 两组按钮(模式/处置)都隐藏,标题区旁只剩「停止」按钮
    await page.evaluate(() => {
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.getElementById('scan_window').classList.add('active');
        document.getElementById('scan_mode_group').classList.add('hidden');
        document.getElementById('scan_action_group').classList.add('hidden');
        document.getElementById('stop_btn').classList.remove('hidden');
    });
    await page.waitForTimeout(150);

    const state = () => page.evaluate(() => {
        const el = document.getElementById('progress_text');
        return { text: el.textContent, scrollW: el.scrollWidth, clientW: el.clientWidth,
            ellipsisCount: (el.textContent.match(/…/g) || []).length,
            hasI18n: el.hasAttribute('data-i18n'), hasDynamic: el.hasAttribute('data-dynamic-msg') };
    });
    const noOverflow = (s) => assert.ok(s.scrollW <= s.clientW + 1,
        `不允许横向溢出(会出滚动条/裁字): scrollW=${s.scrollW} clientW=${s.clientW} text=${s.text}`);
    const waitNoOverflow = () => page.waitForFunction(() => {
        const el = document.getElementById('progress_text');
        return el.scrollWidth <= el.clientWidth + 1;
    }, { timeout: 3000 });

    // 1. 短路径:原样显示,不多不少
    await page.evaluate(() => window.updateScanProgress('C:/bootmgr'));
    let s = await state();
    assert.equal(s.text, 'C:/bootmgr', '短路径必须原样显示');
    noOverflow(s);

    // 2. 长路径:头部 + … + 文件名,且不溢出
    await page.evaluate((p) => window.updateScanProgress(p), LONG_PATH);
    await waitNoOverflow();
    s = await state();
    assert.notEqual(s.text, LONG_PATH, '长路径必须被压缩');
    assert.ok(s.text.startsWith('C:/'), `应保留最前面路径: ${s.text}`);
    assert.ok(s.text.endsWith('/manifest.json'), `应保留文件名: ${s.text}`);
    assert.equal(s.ellipsisCount, 1, '中段恰好一个省略号');
    assert.equal(s.hasI18n, false, '路径态不挂 data-i18n');
    noOverflow(s);
    const wideLen = s.text.length;

    // 3. 变窄:重新省略,更狠,仍保住文件名
    await page.setViewportSize({ width: 480, height: 760 });
    await page.waitForFunction((prev) => document.getElementById('progress_text').textContent.length < prev,
        wideLen, { timeout: 3000 });
    await waitNoOverflow();
    s = await state();
    noOverflow(s);
    assert.ok(s.text.startsWith('C:/'), `变窄后仍应保留最前面路径: ${s.text}`);
    assert.ok(s.text.endsWith('/manifest.json'), `变窄后仍应保留文件名: ${s.text}`);
    assert.equal(s.ellipsisCount, 1, '变窄后仍是单个省略号');
    const narrowLen = s.text.length;
    assert.ok(narrowLen < wideLen, `变窄后显示应更短: ${narrowLen} vs ${wideLen}`);

    // 4. 变宽:头部恢复变长
    await page.setViewportSize({ width: 1000, height: 760 });
    await page.waitForFunction((prev) => document.getElementById('progress_text').textContent.length > prev,
        narrowLen, { timeout: 3000 });
    await waitNoOverflow();
    s = await state();
    noOverflow(s);
    assert.ok(s.text.endsWith('/manifest.json'), `变宽后仍应保留文件名: ${s.text}`);

    // 5. 目录结尾路径(后端把 \ 换成 / 后目录扫描目标长这样):保留「段名/」
    const dirPath = 'C:/Users/cadw/AppData/Local/Microsoft/Edge/User Data/Default/Extensions/ekhngnigjebipkidcgknelmjmjeleph/1.8.12302_0/resource/public/';
    await page.evaluate((p) => window.updateScanProgress(p), dirPath);
    await waitNoOverflow();
    s = await state();
    noOverflow(s);
    assert.ok(s.text.endsWith('public/'), `目录结尾应保留段名和分隔符: ${s.text}`);
    assert.equal(s.ellipsisCount, 1, '目录路径恰好一个省略号');

    // 6. 文件名本身超长:保住扩展名结尾
    const longName = 'C:/very/long/directory/structure/that/will/not/fit/into/the/progress/line/at/all/'
        + 'z'.repeat(180) + '.json';
    await page.evaluate((p) => window.updateScanProgress(p), longName);
    await waitNoOverflow();
    s = await state();
    noOverflow(s);
    assert.ok(s.text.startsWith('…'), `头部放不下时应从尾部截: ${s.text}`);
    assert.ok(s.text.endsWith('.json'), `超长文件名应保住扩展名: ${s.text}`);
    assert.equal(s.ellipsisCount, 1, '超长文件名恰好一个省略号');

    // 7. 删除进度同一条路
    await page.evaluate((p) => window.updateDeleteProgress(p), LONG_PATH);
    await waitNoOverflow();
    s = await state();
    noOverflow(s);
    assert.ok(s.text.endsWith('/manifest.json'), `删除进度也应保住文件名: ${s.text}`);
    assert.equal(await page.locator('#scan_window .section-title').textContent(), '正在删除', '删除进度标题');

    // 8. finishScan 完成消息:resize 不得被旧路径覆盖(消息态/路径态互斥)
    await page.evaluate(() => window.finishScan('scan_virus_desc', 0));
    const doneText = await page.locator('#progress_text').textContent();
    await page.setViewportSize({ width: 640, height: 760 });
    await page.waitForTimeout(200);
    await page.setViewportSize({ width: 1000, height: 760 });
    await page.waitForTimeout(200);
    assert.equal(await page.locator('#progress_text').textContent(), doneText, '完成消息不应被旧路径覆盖');
    s = await state();
    assert.equal(s.hasI18n, true, '消息态挂回 data-i18n');

    // 9. 消息态之后重新进入路径态,继续正常省略
    await page.evaluate((p) => window.updateScanProgress(p), LONG_PATH);
    await waitNoOverflow();
    s = await state();
    noOverflow(s);
    assert.ok(s.text.endsWith('/manifest.json'), `重新进路径态应继续省略: ${s.text}`);

    assert.deepEqual(errors, [], '不允许页面 JS 报错');

    await browser.close();
    server.close();
    console.log('Scan progress path middle-ellipsis: PASS (长短路径/缩放自适应/目录结尾/超长文件名/删除进度/消息态互斥)');
})().catch(e => { console.error('FAIL ' + e.message); process.exit(1); });
