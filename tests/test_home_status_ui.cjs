/* Run with Playwright available: node tests/test_home_status_ui.cjs [screenshot-dir]
   回归(2026-10-15):
   1. 首页总述必须跟着五个防护灯走
      五个灯 = config 里 process/document/system/network/driver 的 *_switch。
      文案原本写死在模板的 data-i18n 上:新装默认五个模块全关,于是出现
      「一边写『此设备已受到防护』、一边五个灰点」的自相矛盾。
   2. 实时日志没有记录时必须给空态文案
      原来一条日志都没有时给空字符串,新装首启面板是一整块空白,看不出是没数据还是加载失败;
      而筛选命不中时又借用了更新日志的词(「暂无更新记录」),两个空态必须分开说。
   3. 图标按钮一个口径:命中区都 32x32、画形都 20px
      .icon-btn 原为 24px(比例 0.75,比 nav-btn 44/24 还密),同一标题行里还有 18px 放大镜。
   4. 控件高度统一走 --control-height
      .modern-btn 原来靠 padding 撑出 37px,设置页里被写成固定 40px,同一组件两个来源。
   5. 快捷卡片的缩放补偿
      卡片尺寸乘 --quick-scale,描边变量必须反向除回去,否则卡片变窄时图标一起变细。
   6. 驱动防护豁免(driver_alert_exempt,设置页开关,默认开)
      内核驱动装不上的机器不该永远挂着「防护未完全开启」:开着豁免时驱动灯仍如实显示,
      只是不参与总述判断;关掉后回到五灯口径。 */
const { chromium } = require('playwright');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const SWITCH_KEYS = ['process_switch', 'document_switch', 'system_switch', 'network_switch', 'driver_switch'];

const baseCfg = (overrides) => Object.assign({
    first_launch: false, language: 'simplified_switch', theme: 'white_switch', version: 'test',
    interactive_timeout: 30, ai_provider_mode: 'local', ai_model: '', ai_base_url: '',
    ai_assist_switch: false, ai_delay_switch: true, ai_delay_seconds: 3, ai_auto_execute: false,
    process_switch: false, document_switch: false, system_switch: false,
    network_switch: false, driver_switch: false,
    // 真机上 get_config 给的是 pyas_default 合并用户配置后的结果,默认含这一项且为开
    driver_alert_exempt: true,
}, overrides);

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
    const url = `http://127.0.0.1:${server.address().port}/templates/index.html`;
    let browser;
    const errors = [];

    const openPage = async (cfg, viewport) => {
        const page = await browser.newPage({ viewport: viewport || { width: 1100, height: 760 } });
        page.on('pageerror', error => errors.push(String(error)));
        await page.addInitScript((stubCfg) => {
            window.pywebview = { api: {
                get_config: async () => stubCfg,
                init_ui_ready: async () => true,
                report_ui_error: async () => true,
                get_pending_threat_count: async () => 0,
                get_pending_threat_queue: async () => ({ count: 0, events: [] }),
                get_context_menu_status: async () => ({ mode: 'disabled', notice: '' }),
                get_logs: async () => window.__logs || [],
                show_confirm: async () => true,
                show_alert: async () => true,
                update_config: async (key, value) => { stubCfg[key] = value; return value; },
            } };
        }, cfg);
        await page.goto(url);
        await page.waitForFunction(() => document.querySelector('.app-container').classList.contains('fade-in'));
        return page;
    };

    try {
        browser = await chromium.launch({
            executablePath: process.env.EDGE_EXECUTABLE || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
            headless: true,
        });

        // ---------- 1. 三态总述 ----------
        const cases = [
            { name: '全关(新装默认)', on: [], title: '实时防护未开启', warn: true, glyph: '#i-shield' },
            { name: '全开', on: SWITCH_KEYS, title: '此设备已受到防护', warn: false, glyph: '#i-shield-check' },
            { name: '部分(3/5)', on: SWITCH_KEYS.slice(0, 3), title: '防护未完全开启', warn: true, glyph: '#i-shield' },
        ];
        for (const c of cases) {
            const cfg = baseCfg();
            c.on.forEach(k => { cfg[k] = true; });
            const page = await openPage(cfg);
            const state = await page.evaluate(() => {
                const brand = document.querySelector('.status-brand');
                return {
                    title: brand.querySelector('.state-title').textContent,
                    warn: brand.classList.contains('state-warn'),
                    glyph: brand.querySelector('.state-icon use').getAttribute('href'),
                    onLights: document.querySelectorAll('.protect-light.on').length,
                    lights: document.querySelectorAll('.protect-light').length,
                    iconColor: getComputedStyle(brand.querySelector('.state-icon')).color,
                };
            });
            assert.equal(state.title, c.title, `${c.name}: 总述文案应跟着灯走`);
            assert.equal(state.warn, c.warn, `${c.name}: state-warn 类`);
            assert.equal(state.glyph, c.glyph, `${c.name}: 未全开时不该再显示带对勾的盾`);
            assert.equal(state.lights, 5, `${c.name}: 应有五个防护灯`);
            assert.equal(state.onLights, c.on.length, `${c.name}: 亮起的灯数应等于开启的模块数`);
            if (c.warn) {
                assert.notEqual(state.iconColor, 'rgb(10, 132, 255)', `${c.name}: 未全开时图标应为警示色`);
            }
            await page.close();
        }

        // ---------- 2. 空态文案 ----------
        const emptyPage = await openPage(baseCfg());   // get_logs -> []
        await emptyPage.waitForFunction(() => document.querySelector('#home_log_list .home-log-empty'));
        assert.equal(await emptyPage.locator('#home_log_list .home-log-empty').textContent(),
            '暂无日志记录', '一条日志都没有时应给空态文案,而不是空白面板');

        // 有日志但筛选命不中:必须用日志自己的词,不能借更新日志的「暂无更新记录」
        const filterPage = await openPage(baseCfg());
        await filterPage.evaluate(() => { window.__logs = []; });
        await filterPage.evaluate(() => {
            window.__logs = [
                { id: 'l1', time_str: '2026-10-15 10:00:00', level: 'INFO', action: 'System', source: 'UI test', detail: '' },
            ];
        });
        await filterPage.evaluate(() => { window.updateLogs(window.__logs[0]); });
        await filterPage.waitForFunction(() => document.querySelectorAll('#home_log_list .home-log-item').length === 1);
        await filterPage.locator('.log-filter[data-filter="BLOCK"]').click();
        await filterPage.waitForFunction(() => document.querySelector('#home_log_list .home-log-empty'));
        const filterText = await filterPage.locator('#home_log_list .home-log-empty').textContent();
        assert.equal(filterText, '此分类暂无记录', '筛选命不中时应用日志自己的空态词');
        await filterPage.close();
        await emptyPage.close();

        // ---------- 3/4/5. 尺寸口径与缩放补偿 ----------
        for (const width of [1100, 520]) {
            const page = await openPage(baseCfg({ process_switch: true }), { width, height: 760 });
            const dims = await page.evaluate(() => {
                const px = (el, prop) => parseFloat(getComputedStyle(el)[prop]);
                // 取不缩放的上下文:快捷卡片里的箭头会被 --quick-scale 缩放(那是设计如此),不参与口径比较
                const backBtn = document.querySelector('#custom_protect_window .icon-btn');
                const rowBtn = document.querySelector('#protect_window .icon-action-btn');
                const home = document.getElementById('home_log_export');
                return {
                    backBox: backBtn.offsetWidth + 'x' + backBtn.offsetHeight,
                    backGlyph: px(backBtn.querySelector('svg'), 'width'),
                    rowBox: rowBtn.offsetWidth + 'x' + rowBtn.offsetHeight,
                    rowGlyph: px(rowBtn.querySelector('svg'), 'width'),
                    homeBtnHeight: home.offsetHeight,
                };
            });
            assert.equal(dims.backGlyph, 20, `宽 ${width}: .icon-btn 画形应为 20px`);
            assert.equal(dims.rowGlyph, 20, `宽 ${width}: .icon-action-btn 画形应为 20px`);
            assert.equal(dims.backBox, dims.rowBox, `宽 ${width}: 两个图标按钮命中区应同为 32x32`);
            assert.equal(dims.homeBtnHeight, 40, `宽 ${width}: .modern-btn 高度应取 --control-height`);

            // 缩放补偿:同一张卡片在宽/窄视口下,图标物理描边必须一致
            const strokes = await page.evaluate(() => {
                const measure = (host) => {
                    const svg = host.tagName.toLowerCase() === 'svg' ? host : host.querySelector('svg');
                    const rect = svg.getBoundingClientRect();
                    const wrap = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                    wrap.setAttribute('viewBox', '0 0 24 24');
                    wrap.style.width = rect.width + 'px';
                    wrap.style.height = rect.height + 'px';
                    wrap.style.position = 'absolute';
                    wrap.style.opacity = '0';
                    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
                    g.style.strokeWidth = 'var(--icon-stroke, 2)';
                    wrap.appendChild(g);
                    host.appendChild(wrap);
                    const raw = getComputedStyle(g).strokeWidth;   // 形如 calc(1.5px)
                    host.removeChild(wrap);
                    const m = /(-?[\d.]+)px/.exec(raw);
                    return m ? parseFloat(m[1]) * rect.width / 24 : NaN;   // 物理描边 = 变量 x (渲染px / 24)
                };
                const item = document.querySelector('.quick-item');
                return {
                    scale: parseFloat(getComputedStyle(document.querySelector('.quick-actions-row'))
                        .getPropertyValue('--quick-scale') || '1'),
                    icon: measure(item.querySelector('.item-icon')),
                };
            });
            assert.ok(strokes.icon > 0, `宽 ${width}: 探针未取到描边`);
            assert.ok(Math.abs(strokes.icon - 2.375) < 0.02,
                `宽 ${width}(scale=${strokes.scale}): 卡片缩放后物理描边应仍为 2.375px,实为 ${strokes.icon.toFixed(3)}`);
            await page.close();
        }

        // ---------- 6. 语言切换后总述不能残留旧语言 ----------
        const langPage = await openPage(baseCfg());
        assert.equal(await langPage.locator('.status-brand .state-title').textContent(), '实时防护未开启');
        await langPage.evaluate(() => {
            // 只把总述重置成默认值,模拟 translateText 对 [data-i18n] 的重写,再走同一个语言切换入口
            document.querySelector('.status-brand .state-title').textContent = '此设备已受到防护';
            const sel = document.getElementById('lang_select');
            sel.value = 'english_switch';
            sel.dispatchEvent(new Event('change', { bubbles: true }));
        });
        await langPage.waitForFunction(() =>
            document.querySelector('.status-brand .state-title').textContent === 'Realtime Protection is Off');
        assert.equal(await langPage.locator('.status-brand .state-title').textContent(),
            'Realtime Protection is Off', '切英文后总述必须跟着翻译');
        await langPage.close();

        // ---------- 7. 驱动防护豁免(默认开的设置页开关) ----------
        const fourOn = { process_switch: true, document_switch: true, system_switch: true, network_switch: true };
        const toggleSel = 'label.toggle-switch:has([data-config-key="driver_alert_exempt"]) .slider';
        const readBrand = (page) => page.evaluate(() => {
            const brand = document.querySelector('.status-brand');
            return {
                title: brand.querySelector('.state-title').textContent,
                warn: brand.classList.contains('state-warn'),
                glyph: brand.querySelector('.state-icon use').getAttribute('href'),
                driverLight: document.getElementById('light_driver').classList.contains('on'),
                onLights: document.querySelectorAll('.protect-light.on').length,
            };
        });

        // 7a 开着豁免:四项开、驱动关 —— 首页照样说「已受到防护」,但驱动灯仍是灰的(不撒谎)
        const exemptPage = await openPage(baseCfg(fourOn));
        assert.equal(await exemptPage.locator('input[data-config-key="driver_alert_exempt"]').isChecked(), true,
            '7a: 设置页开关默认应为开(跟随配置)');
        let brand = await readBrand(exemptPage);
        assert.equal(brand.title, '此设备已受到防护', '7a: 豁免开启时驱动未开也算防护完整');
        assert.equal(brand.warn, false, '7a: 豁免开启时不该给警示色');
        assert.equal(brand.glyph, '#i-shield-check', '7a: 豁免开启时应是带对勾的盾');
        assert.equal(brand.driverLight, false, '7a: 驱动灯必须仍如实反映驱动未开启');
        assert.equal(brand.onLights, 4, '7a: 亮灯数应为 4(驱动那盏不亮)');

        // 7b 在界面上关掉豁免:总述要立刻回到五灯口径,不用重启
        //     (开关在设置页,非当前页元素不可点,先切过去)
        await exemptPage.click('.nav-btn[data-target="setting_window"]');
        await exemptPage.waitForFunction(() => document.getElementById('setting_window').classList.contains('active'));
        await exemptPage.locator(toggleSel).click();
        await exemptPage.waitForFunction(() =>
            document.querySelector('.status-brand .state-title').textContent === '防护未完全开启');
        brand = await readBrand(exemptPage);
        assert.equal(brand.warn, true, '7b: 关掉豁免后应回到警示态');
        assert.equal(brand.glyph, '#i-shield', '7b: 关掉豁免后应换回素盾');
        // 再打开又回到「已受到防护」
        await exemptPage.locator(toggleSel).click();
        await exemptPage.waitForFunction(() =>
            document.querySelector('.status-brand .state-title').textContent === '此设备已受到防护');
        await exemptPage.close();

        // 7c 配置里豁免为关(老配置被显式关闭):四项开、驱动关 = 未完全开启
        const strictPage = await openPage(baseCfg(Object.assign({}, fourOn, { driver_alert_exempt: false })));
        brand = await readBrand(strictPage);
        assert.equal(brand.title, '防护未完全开启', '7c: 豁免关闭时驱动未开必须算作防护不完整');
        assert.equal(brand.glyph, '#i-shield', '7c: 豁免关闭时应是素盾');
        await strictPage.close();

        // ---------- 8. 首页隐藏驱动灯(忽略驱动防护状态的二级选项,默认关) ----------
        // 8a 默认不隐藏:同一份四开一关的配置,驱动灯仍要在
        const defaultPage = await openPage(baseCfg(fourOn));
        assert.equal(await defaultPage.locator('#light_driver').isHidden(), false,
            '8a: driver_home_hidden 默认关,驱动灯必须还在');
        await defaultPage.close();

        // 8b 配置为开:灯消失,但元素还在(只加 hidden 类,不删节点)
        const hiddenPage = await openPage(baseCfg(Object.assign({}, fourOn, { driver_home_hidden: true })));
        brand = await readBrand(hiddenPage);
        assert.equal(await hiddenPage.locator('#light_driver').count(), 1,
            '8b: 隐藏应走 hidden 类,不该把灯从 DOM 里删掉');
        assert.equal(await hiddenPage.locator('#light_driver').isHidden(), true,
            '8b: driver_home_hidden 开启后首页不该显示驱动灯');
        assert.equal(brand.title, '此设备已受到防护',
            '8b: 灯都看不见了就不能再拿它参与总述,否则会出现「看不见的那格拖后腿」');
        assert.equal(brand.onLights, 4, '8b: 亮灯数仍是 4,只是第五格不显示');

        // 8c 二级行只在父开关打开时出现,点一下立刻反映到首页(不用重启)
        await hiddenPage.click('.nav-btn[data-target="setting_window"]');
        await hiddenPage.waitForFunction(() => document.getElementById('setting_window').classList.contains('active'));
        const childRow = hiddenPage.locator('[data-setting-parent="driver_alert_exempt"]');
        await childRow.waitFor({ state: 'visible' });
        assert.equal(await hiddenPage.locator('input[data-config-key="driver_home_hidden"]').isChecked(), true,
            '8c: 二级开关状态要跟随配置');
        await hiddenPage.locator('label.toggle-switch:has([data-config-key="driver_home_hidden"]) .slider').click();
        await hiddenPage.waitForFunction(() => !document.getElementById('light_driver').classList.contains('hidden'));
        // 此刻停在设置页,首页整页 visibility:hidden,isHidden() 恒真 —— 只能看类
        assert.equal(await hiddenPage.evaluate(() => document.getElementById('light_driver').classList.contains('hidden')), false,
            '8c: 关掉二级开关后驱动灯要立刻回来');
        await hiddenPage.close();

        // 8d 父开关关掉时,二级行必须收起来(它是「忽略驱动防护状态」的从属选项)
        const parentOffPage = await openPage(baseCfg(Object.assign({}, fourOn, { driver_alert_exempt: false })));
        await parentOffPage.click('.nav-btn[data-target="setting_window"]');
        await parentOffPage.waitForFunction(() => document.getElementById('setting_window').classList.contains('active'));
        assert.equal(await parentOffPage.locator('[data-setting-parent="driver_alert_exempt"]').isHidden(), true,
            '8d: 父开关关闭时二级行应隐藏');
        await parentOffPage.close();

        assert.deepEqual(errors, []);
        console.log('Home status UI: PASS (三态总述/换素盾/空态两种文案/图标按钮同口径/控件高度/缩放补偿/切换语言/驱动豁免/驱动灯隐藏)');
    } finally {
        if (browser) await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
