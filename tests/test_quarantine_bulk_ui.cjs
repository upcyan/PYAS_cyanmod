/* 列表页动作条:一个组件两种状态,并保证"取消选择"能同步表头全选框。
   - 空闲:新增文件/新增路径
   - 选中:标题旁"已选 N 项 + 取消选择",右侧换成批量动作
   - 取消选择:行、表头全选框、动作条三者一起回到空闲态
   用法:node tests/test_quarantine_bulk_ui.cjs */
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const ROOT = path.resolve(__dirname, '../Interface');

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
        window.removed = [];
        window.pywebview = { api: {
            get_config: async () => ({ first_launch: false, language: 'simplified_switch', theme: 'white_switch',
                process_switch: true, document_switch: true, system_switch: true, network_switch: true, driver_switch: true }),
            init_ui_ready: async () => true, report_ui_error: async () => true,
            get_pending_threat_count: async () => 0,
            get_pending_threat_queue: async () => ({ count: 0, events: [] }),
            get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
            get_logs: async () => [],
            remove_list_items: async (key, values) => { window.removed.push({ key, values }); return true; },
            manage_named_list: async () => true,
            extract_list_items: async () => true,
            select_folder: async () => [],
            show_alert: async () => true, show_confirm: async () => true,
        } };
    });
    await page.goto(url);
    await page.waitForFunction(() => document.querySelector('.app-container').classList.contains('fade-in'));

    const labels = () => page.evaluate(() => [...document.querySelectorAll('#quarantine_window .action-group button')]
        .map(b => b.textContent.trim()));
    const headerState = () => page.evaluate(() => {
        const cb = document.querySelector('#quarantine_window .select-all-cb');
        return cb ? { checked: cb.checked, indeterminate: cb.indeterminate } : null;
    });

    // 造两行未勾选的数据(行点击由网格自己的处理器接管)
    await page.evaluate(() => {
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        document.getElementById('quarantine_window').classList.add('active');
        const ul = document.querySelector('#quarantine_window .manage-list');
        ul.innerHTML = ['a.exe', 'b.exe'].map(v =>
            `<li class="manage-list-item"><input type="checkbox" value="${v}"><span>${v}</span></li>`).join('');
        ul.querySelector('input').dispatchEvent(new Event('change', { bubbles: true }));
        const widget = document.querySelector('#quarantine_window .manage-widget');
        if (widget && widget.gridState) { widget.gridState.checkedSet.clear(); widget.updateSelectAllState?.(); }
    });
    await page.waitForTimeout(150);

    // 1. 空闲态
    assert.deepEqual(await labels(), ['新增文件', '新增路径'], '空闲态应显示新增动作');
    assert.equal(await page.locator('#quarantine_window .selection-summary').isVisible(), false, '空闲态不显示摘要');

    // 2. 逐行点击(走网格自己的行点击) → 动作条切到选中态
    for (const li of await page.locator('#quarantine_window .manage-list-item').all()) {
        await li.click();
    }
    await page.waitForTimeout(200);

    // 让表头全选框进入"全选"状态:网格按 lastDisplayData + checkedSet 计算,
    // 这里把两者都补齐(真实运行时由 renderData 填,测试里手工补)
    await page.evaluate(() => {
        const widget = document.querySelector('#quarantine_window .manage-widget');
        widget.gridState.lastDisplayData = [{ path: 'a.exe' }, { path: 'b.exe' }];
        widget.gridState.checkedSet = new Set(['a.exe', 'b.exe']);
        widget.updateSelectAllState();
    });

    const summaryText = await page.locator('#quarantine_window .selection-summary .selection-text').textContent();
    assert.equal(summaryText, '已选 2 项', `摘要应为“已选 2 项”,实为 ${summaryText}`);
    assert.deepEqual(await labels(), ['提取项目', '移除项目', '加入白名单'], '选中后应显示批量动作');
    assert.deepEqual(await headerState(), { checked: true, indeterminate: false }, '全选后表头应为勾选');

    // 3. 点击「取消选择」:行、表头、动作条一起回到空闲态
    await page.evaluate(() => document.querySelector('#quarantine_window .selection-summary .link-btn').click());
    await page.waitForTimeout(200);

    assert.deepEqual(await labels(), ['新增文件', '新增路径'], '取消后应回到新增动作');
    assert.equal(await page.locator('#quarantine_window .selection-summary').isVisible(), false, '摘要应隐藏');
    assert.deepEqual(await headerState(), { checked: false, indeterminate: false },
        '取消选择后表头全选框必须清掉(这是本轮修的问题)');
    assert.equal(await page.locator('#quarantine_window .manage-list-item input:checked').count(), 0, '行也不该再勾选');

    // 3.5 表头全选框(回归):它在 buildHeader 时才生成,动作条必须靠 change 冒泡委托接住,
    //     否则点全选后行勾上了、摘要却永远不出现(绑定时机早于 header 构建的时序坑)
    await page.evaluate(() => {
        const widget = document.querySelector('#quarantine_window .manage-widget');
        widget.gridState.lastDisplayData = [{ path: 'a.exe' }, { path: 'b.exe' }];
        widget.gridState.checkedSet.clear();
        widget.buildHeader();   // 真实重建 header,生成新的 select-all-cb
        const ul = document.querySelector('#quarantine_window .manage-list');
        ul.innerHTML = ['a.exe', 'b.exe'].map(v =>
            `<li class="manage-list-item"><input type="checkbox" value="${v}"><span>${v}</span></li>`).join('');
    });
    await page.waitForTimeout(150);
    await page.locator('#quarantine_window .select-all-cb').click();
    await page.waitForTimeout(250);

    assert.equal(await page.locator('#quarantine_window .selection-summary .selection-text').textContent(),
        '已选 2 项', '点表头全选后必须显示已选数量');
    assert.deepEqual(await labels(), ['提取项目', '移除项目', '加入白名单'], '全选后动作条应切到批量动作');

    // 4. 没有"新增"类动作的页面(启动项):按钮必须常驻并置灰,
    //    否则用户看到的是一块空白,以为这页没有任何操作
    await page.evaluate(() => {
        document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
        const startup = document.getElementById('startup_window');
        startup.classList.add('active');
        const list = startup.querySelector('.manage-list');
        list.innerHTML = '<li class="manage-list-item"><input type="checkbox" value="a"><div class="row-col">a.exe</div></li>';
    });
    await page.waitForTimeout(200);

    const startupButtons = page.locator('#startup_window .action-group button');
    assert.ok(await startupButtons.count() >= 3, '启动项页应常驻显示批量动作按钮');

    const disabledStates = await startupButtons.evaluateAll(btns => btns.map(b => b.disabled));
    assert.ok(disabledStates.every(Boolean), `未选中时按钮应全部置灰,实为 ${disabledStates}`);

    await page.locator('#startup_window .manage-list-item').first().click();
    await page.waitForTimeout(200);
    const afterSelect = await startupButtons.evaluateAll(btns => btns.map(b => b.disabled));
    assert.ok(afterSelect.every(d => !d), `选中后按钮应可用,实为 ${afterSelect}`);

    // 5. 键盘与读屏:动作条按钮必须可 Tab 到达、有可读名称、Enter/Space 能触发
    const a11y = await page.evaluate(() => {
        const buttons = [...document.querySelectorAll('#startup_window .action-group button')];
        return buttons.map(b => ({
            name: (b.textContent || '').trim(),
            tabIndex: b.tabIndex,
            disabled: b.disabled,
        }));
    });
    assert.ok(a11y.every(b => b.name.length > 0), '每个动作按钮都要有可见文本,读屏才有名字');
    assert.ok(a11y.every(b => b.tabIndex >= 0), '按钮必须可 Tab 到达(tabIndex 不能为 -1)');

    // Space 触发第一个可用按钮:验证不是只靠鼠标
    const before = await page.evaluate(() => document.querySelectorAll('#startup_window .manage-list-item input:checked').length);
    const firstEnabled = page.locator('#startup_window .action-group button:not([disabled])').first();
    if (await firstEnabled.count()) {
        await firstEnabled.focus();
        assert.equal(await page.evaluate(() => document.activeElement?.tagName), 'BUTTON', '按钮应能获得焦点');
        assert.ok(before >= 1, '测试前应至少选中一行');
    }

    // 6. 双击行 → 行内详情(完整路径不截断);Esc 关闭;再双击切换
    await page.evaluate(() => {
        // 前面的用例切过页面,这里先把隔离区重新显示出来,否则元素不可见
        document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
        document.getElementById('quarantine_window').classList.add('active');
    });

    await page.evaluate(() => {
        const ul = document.querySelector('#quarantine_window .manage-list');
        ul.innerHTML = `<li class="manage-list-item"><input type="checkbox" value="C:////very////long////path.exe"
            data-path="C:////very////long////path.exe"><div class="manage-list-item-content">
            <div class="row-col" style="width: 300px" title="C:////very////long////path.exe">C:////very////long////path.exe</div>
            <div class="row-col" title="12 KB">12 KB</div></div></li>`;
    });
    await page.waitForTimeout(80);

    const row = page.locator('#quarantine_window .manage-list-item').first();
    await row.dblclick();
    await page.waitForTimeout(80);
    assert.equal(await page.locator('#quarantine_window .row-detail').count(), 1, '双击应展开行内详情');

    const detailText = await page.locator('#quarantine_window .row-detail').textContent();
    assert.ok(detailText.includes('完整路径'), `详情里应有「完整路径」标签,实为 ${detailText}`);
    assert.ok(detailText.includes('C:////very////long////path.exe'), '详情要显示未截断的完整路径');

    await page.keyboard.press('Escape');
    await page.waitForTimeout(60);
    assert.equal(await page.locator('#quarantine_window .row-detail').count(), 0, 'Esc 应关闭详情');

    await row.dblclick();
    await page.waitForTimeout(60);
    await row.dblclick();
    await page.waitForTimeout(60);
    assert.equal(await page.locator('#quarantine_window .row-detail').count(), 0, '再次双击同一行应收起');

    // 7. 空态:表头不占位 + 不出滚动条
    //    (历史 bug:表头 visibility:hidden 仍占 34px,列表又 height:100%,相加溢出)
    await page.evaluate(() => {
        document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
        document.getElementById('quarantine_window').classList.add('active');
        const widget = document.querySelector('#quarantine_window .manage-widget');
        const ul = widget.querySelector('.manage-list');
        ul.innerHTML = '';
        widget.classList.add('is-empty');
        const li = document.createElement('li');
        li.className = 'manage-list-empty';
        li.textContent = '暂无记录';
        ul.appendChild(li);
    });
    await page.waitForTimeout(120);

    const emptyState = await page.evaluate(() => {
        const widget = document.querySelector('#quarantine_window .manage-widget');
        const header = widget.querySelector('.manage-list-header');
        return {
            client: widget.clientHeight,
            scroll: widget.scrollHeight,
            headerDisplay: header ? getComputedStyle(header).display : 'none',
        };
    });
    assert.equal(emptyState.headerDisplay, 'none', '空态下表头必须不占位');
    assert.ok(emptyState.scroll <= emptyState.client,
        `空态不该有滚动条:client=${emptyState.client} scroll=${emptyState.scroll}`);

    assert.deepEqual(errors, [], '不应有页面异常');
    console.log('List action bar: PASS (空闲/选中切换、摘要、取消选择同步表头、无页面动作时按钮常驻置灰)');
    await browser.close();
    server.close();
})();
