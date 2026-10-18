['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    document.addEventListener(eventName, e => {
        e.preventDefault();
    });
});

window.addEventListener('error', (e) => {
    try { window.pywebview?.api?.report_ui_error('runtime-js', String(e.message || e)); } catch (_) {}
});

document.addEventListener('DOMContentLoaded', () => {
    const { dict, langMap } = window.AppI18n;

    const appState = {
        lang: "english_switch",
        theme: "system_switch",
        scanning: false,
        firstLaunch: false,
        taskmgrTimer: null,
        taskmgrActive: false,
        netmonTimer: null,
        netmonActive: false,
        virusMap: new Map(),
        virusResults: [],
        junkList: [],
        upstreamTracked: "3.7.0",
        configCache: null
    };

    const menuTextMap = {
        traditional_switch: {
            modern: '已添加新版選單', legacy: '已添加傳統選單', disabled: '未添加右鍵選單', pending: '正在確認選單狀態', failed: '右鍵選單添加失敗',
            title: '新版右鍵選單添加失敗', fallback: '已回退至傳統選單，可在「顯示更多選項」中使用掃描。',
            certificate: 'Windows 不信任此選單包的簽名憑證（0x800B0109）。', reason: '失敗原因：'
        },
        simplified_switch: {
            modern: '已添加新版菜单', legacy: '已添加传统菜单', disabled: '未添加右键菜单', pending: '正在确认菜单状态', failed: '右键菜单添加失败',
            title: '新版右键菜单添加失败', fallback: '已回退至传统菜单，可在“显示更多选项”中使用扫描。',
            certificate: 'Windows 不信任此菜单包的签名证书（0x800B0109）。', reason: '失败原因：'
        },
        english_switch: {
            modern: 'Modern menu added', legacy: 'Original menu added', disabled: 'Context menu disabled', pending: 'Checking menu status', failed: 'Context menu registration failed',
            title: 'Modern context menu registration failed', fallback: 'Scanning is available in the original menu under “Show more options”.',
            certificate: 'Windows does not trust the menu package signing certificate (0x800B0109).', reason: 'Reason: '
        }
    };
    const menuTexts = () => menuTextMap[appState.lang] || menuTextMap.english_switch;
    let menuStatusInFlight = false;
    const renderMenuStatus = () => {
        const label = document.getElementById('context_menu_status');
        if (label) label.textContent = menuTexts()[appState.menuMode || 'pending'];
    };
    window.refreshContextMenuStatus = async () => {
        const api = window.pywebview?.api;
        if (!api?.get_context_menu_status || menuStatusInFlight) return;
        menuStatusInFlight = true;
        try {
            const status = await api.get_context_menu_status();
            appState.menuMode = status.mode;
            renderMenuStatus();
            if (status.notice) {
                const text = menuTexts();
                const reason = /0x800b0109/i.test(status.notice) ? text.certificate + '\n\n' + status.notice : status.notice;
                await api.show_alert(text.title, (status.mode === 'legacy' ? text.fallback + '\n\n' : '') + text.reason + reason, 'warning');
            }
        } catch (error) { console.error('Menu status failed', error); }
        finally { menuStatusInFlight = false; }
    };

    const reverseI18nMap = Object.entries(dict["traditional_switch"]).reduce((acc, [key, val]) => {
        acc[val] = key;
        return acc;
    }, {});

    const initI18nKeys = () => {
        document.querySelectorAll("[data-i18n]").forEach(el => {
            let key = el.getAttribute('data-i18n');
            if (!key) {
                const text = el.textContent.trim();
                key = reverseI18nMap[text] || text;
                el.setAttribute('data-i18n', key);
            }
            el.dataset.originText = el.textContent.trim();
        });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
            let key = el.getAttribute('data-i18n-placeholder');
            if (reverseI18nMap[key]) {
                el.setAttribute('data-i18n-placeholder', reverseI18nMap[key]);
            }
            el.dataset.originPlaceholder = el.getAttribute('placeholder');
        });
        document.querySelectorAll("option[data-i18n]").forEach(el => {
            let key = el.getAttribute('data-i18n');
            if (!key) {
                const text = el.textContent.trim();
                key = reverseI18nMap[text] || text;
                el.setAttribute('data-i18n', key);
            }
        });
    };

    let openCustomSelect = null;
    let customSelectSeq = 0;

    const closeCustomSelect = (restoreFocus = false) => {
        if (!openCustomSelect) return;
        const { wrapper, trigger, menu } = openCustomSelect;
        wrapper.classList.remove('open');
        menu.classList.remove('open');
        menu.removeAttribute('style');
        // 同步 ARIA:关闭后收起状态、清掉高亮项
        trigger.setAttribute('aria-expanded', 'false');
        trigger.removeAttribute('aria-activedescendant');
        menu.querySelectorAll('.custom-select-option.active').forEach(el => el.classList.remove('active'));
        if (wrapper.isConnected) wrapper.appendChild(menu);
        else menu.remove();
        openCustomSelect = null;
        if (restoreFocus && trigger.isConnected) trigger.focus({ preventScroll: true });
    };

    const positionCustomSelect = () => {
        if (!openCustomSelect) return;
        const { wrapper, trigger, menu } = openCustomSelect;
        const rect = trigger.getBoundingClientRect();
        const viewport = window.visualViewport;
        const leftEdge = (viewport?.offsetLeft || 0) + 8;
        const topEdge = (viewport?.offsetTop || 0) + 8;
        const rightEdge = leftEdge + (viewport?.width || document.documentElement.clientWidth) - 16;
        const bottomEdge = topEdge + (viewport?.height || document.documentElement.clientHeight) - 16;
        if (!wrapper.isConnected || !trigger.getClientRects().length ||
            getComputedStyle(trigger).visibility === 'hidden' ||
            rect.bottom <= topEdge || rect.top >= bottomEdge ||
            rect.right <= leftEdge || rect.left >= rightEdge) {
            closeCustomSelect();
            return;
        }
        const above = Math.max(0, rect.top - topEdge - 8);
        const below = Math.max(0, bottomEdge - rect.bottom - 8);
        const opensUp = above > below;
        const available = opensUp ? above : below;
        if (available < 32) {
            closeCustomSelect();
            return;
        }
        menu.style.maxHeight = `${Math.min(260, available)}px`;
        menu.style.maxWidth = `${rightEdge - leftEdge}px`;
        menu.style.minWidth = `${Math.min(rect.width, rightEdge - leftEdge)}px`;
        menu.style.setProperty('--select-enter-offset', opensUp ? '4px' : '-4px');
        menu.style.left = `${Math.max(leftEdge, Math.min(rect.left, rightEdge - menu.offsetWidth))}px`;
        menu.style.top = `${opensUp ? rect.top - 8 - menu.offsetHeight : rect.bottom + 8}px`;
    };

    document.addEventListener('click', () => closeCustomSelect());
    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') closeCustomSelect();
    });
    document.addEventListener('scroll', (event) => {
        if (openCustomSelect && !openCustomSelect.menu.contains(event.target)) closeCustomSelect();
    }, true);
    window.addEventListener('resize', positionCustomSelect);
    window.visualViewport?.addEventListener('resize', positionCustomSelect);
    window.visualViewport?.addEventListener('scroll', positionCustomSelect);

    const getMsg = (key) => (dict[appState.lang] || dict["english_switch"])[key] || key;

    // 图标按钮的可访问名在下方初始化,这里先占位,保证切语言时能安全调用
    let refreshIconButtonLabels = () => {};

    let startupOverlayClosed = false;
    const closeStartupOverlay = () => {
        if (startupOverlayClosed) return;
        startupOverlayClosed = true;

        const overlay = document.getElementById('loading_overlay');
        if (overlay && !overlay.classList.contains('fade-out')) {
            overlay.classList.add('fade-out');
        }

        setTimeout(() => {
            document.querySelector('.app-container')?.classList.add('fade-in');
        }, 400);
    };

    const showStartupError = (message) => {
        const overlay = document.getElementById('loading_overlay');
        if (!overlay || startupOverlayClosed) return;

        overlay.classList.add('startup-error');
        overlay.innerHTML = `
            <div class="startup-error-box">
                <h1>PYAS failed to open</h1>
                <p>${escapeHtml(message)}</p>
            </div>`;
    };

    setTimeout(() => {
        if (!startupOverlayClosed) {
            showStartupError("PYAS WebView2 initialization is taking too long. The application will retry automatically.");
        }
    }, 20000);

    const formatMsg = (key, ...args) => {
        let msg = getMsg(key);
        args.forEach((arg, i) => msg = msg.split(`{${i}}`).join(arg));
        return msg;
    };

    const escapeHtml = (unsafe) => {
        if (typeof unsafe !== 'string') return unsafe;
        return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    };

    const cols = {
        log: [{key: 'time_str', label: 'col_date', flex: 1.5, defaultDesc: true}, {key: 'level', label: 'col_type', flex: 0.8, isI18n: true}, {key: 'action', label: 'col_func', flex: 1.2, isI18n: true}, {key: 'source', label: 'col_path', flex: 3}],
        process: [{key: 'name', label: 'col_name', flex: 1.5}, {key: 'pid', label: 'col_pid', flex: 0.5}, {key: 'path', label: 'col_path', flex: 3}],
        startup: [{key: 'type', label: 'col_type', flex: 0.5, isI18n: true}, {key: 'name', label: 'col_name', flex: 1.5}, {key: 'status', label: 'col_status', flex: 0.5, isI18n: true}, {key: 'path', label: 'col_path', flex: 3}],
        virus: [{key: 'label', label: 'col_type', flex: 1, isI18n: true}, {key: 'path', label: 'col_path', flex: 3}],
        pathOnly: [{key: 'path', label: 'col_path', flex: 1}],
        fileList: [{key: 'time_str', label: 'col_date', flex: 1.5}, {key: 'path', label: 'col_path', flex: 5}],
        junk: [{key: 'path', label: 'col_path', flex: 3}, {key: 'sizeStr', label: 'col_size', flex: 1}],
        popup: [{key: 'mode', label: 'col_status', flex: 0.7, isI18n: true}, {key: 'exe', label: 'col_prog', flex: 1}, {key: 'class', label: 'col_class', flex: 1}, {key: 'title', label: 'col_title', flex: 2}],
        repair: [{key: 'display', label: 'col_repair', flex: 1, isI18n: true}, {key: 'path', label: 'col_path', flex: 3}],
        netmon: [{key: 'name', label: 'col_name', flex: 1.5}, {key: 'pid', label: 'col_pid', flex: 0.5}, {key: 'downStr', label: 'col_down_speed', flex: 1}, {key: 'upStr', label: 'col_up_speed', flex: 1}, {key: 'connCount', label: 'col_conn_count', flex: 0.8}],
        release: [{key: 'kind', label: 'col_type', flex: 1, isI18n: true}, {key: 'action', label: 'col_func', flex: 1.2, isI18n: true}, {key: 'source', label: 'col_path', flex: 3}, {key: 'hash', label: 'col_hash', flex: 1.3}, {key: 'status', label: 'col_status', flex: 0.9}, {key: 'hits', label: 'col_hits', flex: 0.55}, {key: 'createdStr', label: 'col_created', flex: 1.15}]
    };

    const formatReleaseTime = (epoch) => {
        const stamp = Number(epoch || 0);
        if (!(stamp > 0)) return '-';
        const date = new Date(stamp * 1000);
        const pad = value => String(value).padStart(2, '0');
        return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
    };

    const buildReleaseRows = (data) => {
        const rows = [];
        (data.permanent || []).forEach(item => rows.push({
            kind: 'release_kind_permanent', action: item.action || '',
            source: item.source || '-', hash: item.sha256 || '-',
            status: '-', hits: String(item.hits || 0),
            created: Number(item.created || 0), createdStr: formatReleaseTime(item.created),
            value: 'p:' + (item.key || ''),
        }));
        (data.suppress || []).forEach(item => rows.push({
            kind: 'release_kind_suppress', action: item.action || '',
            source: item.source || '-', hash: item.sha256 || '-',
            status: formatMsg('release_days_left', String(item.days_left || 0)),
            hits: String(item.hits || 0),
            created: Number(item.created || 0), createdStr: formatReleaseTime(item.created),
            value: 's:' + (item.id || ''),
        }));
        return rows;
    };

    const buildCustomSelectElement = (select) => {
        select.style.display = 'none';
        const wrapper = document.createElement('div');
        wrapper.className = 'custom-select-wrapper';
        // 每个下拉有唯一 id,供 aria-controls / aria-activedescendant 关联
        const menuId = `custom-select-menu-${++customSelectSeq}`;
        
        const selectedOpt = select.options[select.selectedIndex];
        const triggerKey = selectedOpt ? selectedOpt.getAttribute('data-i18n') : '';
        const triggerTextContent = selectedOpt ? getMsg(triggerKey || selectedOpt.textContent) : '';

        const triggerHTML = `
            <div class="custom-select-trigger">
                <span class="custom-select-text" ${triggerKey ? `data-i18n="${triggerKey}"` : ''}>${triggerTextContent}</span>
                <div class="custom-select-icon"><svg aria-hidden="true" focusable="false"><use href="#i-chevron-down"/></svg></div>
            </div>`;
        wrapper.innerHTML = triggerHTML;
        
        const optionsContainer = document.createElement('ul');
        optionsContainer.className = 'custom-select-options';

        const phantom = document.createElement('div');
        phantom.className = 'custom-select-phantom';
        phantom.setAttribute('aria-hidden', 'true');
        
        Array.from(select.options).forEach(option => {
            if (option.disabled) return;
            const optKey = option.getAttribute('data-i18n');
            const optText = optKey ? getMsg(optKey) : option.textContent;
            
            const li = document.createElement('li');
            li.className = `custom-select-option ${option.selected ? 'selected' : ''}`;
            li.textContent = optText;
            li.dataset.value = option.value;
            li.id = `${menuId}-opt-${optionsContainer.children.length}`;
            li.setAttribute('role', 'option');
            li.setAttribute('aria-selected', option.selected ? 'true' : 'false');
            if (optKey) li.setAttribute('data-i18n', optKey);
            
            li.addEventListener('click', (e) => {
                e.stopPropagation();
                select.value = option.value;
                const triggerText = wrapper.querySelector('.custom-select-text');
                triggerText.textContent = li.textContent;
                if (optKey) triggerText.setAttribute('data-i18n', optKey);
                
                closeCustomSelect();
                optionsContainer.querySelectorAll('.custom-select-option').forEach(el => {
                    el.classList.remove('selected');
                    el.setAttribute('aria-selected', 'false');
                });
                li.classList.add('selected');
                li.setAttribute('aria-selected', 'true');
                select.dispatchEvent(new Event('change'));
            });
            optionsContainer.appendChild(li);

            const phantomSpan = document.createElement('span');
            phantomSpan.textContent = optText;
            if (optKey) phantomSpan.setAttribute('data-i18n', optKey);
            phantom.appendChild(phantomSpan);
        });
        
        wrapper.appendChild(phantom);
        wrapper.appendChild(optionsContainer);
        select.parentNode.insertBefore(wrapper, select.nextSibling);
        
        const trigger = wrapper.querySelector('.custom-select-trigger');
        // 组合框语义:可聚焦 + 完整 ARIA;可访问名优先取所在行的标题(值由选项本身传达)
        const rowLabel = select.closest('.list-item')?.querySelector('.item-info h2')?.textContent?.trim();
        trigger.tabIndex = 0;
        trigger.setAttribute('role', 'combobox');
        trigger.setAttribute('aria-haspopup', 'listbox');
        trigger.setAttribute('aria-expanded', 'false');
        trigger.setAttribute('aria-controls', menuId);
        trigger.setAttribute('aria-label', rowLabel || triggerTextContent || 'Select');
        optionsContainer.id = menuId;
        optionsContainer.setAttribute('role', 'listbox');
        optionsContainer.setAttribute('tabindex', '-1');

        const optionItems = () => [...optionsContainer.querySelectorAll('.custom-select-option')];
        const activeIndex = () => {
            const items = optionItems();
            const current = items.findIndex(el => el.classList.contains('active'));
            if (current >= 0) return current;
            const selected = items.findIndex(el => el.classList.contains('selected'));
            return selected >= 0 ? selected : 0;
        };
        const setActive = (index) => {
            const items = optionItems();
            if (!items.length) return;
            const bounded = Math.max(0, Math.min(items.length - 1, index));
            items.forEach((el, i) => el.classList.toggle('active', i === bounded));
            trigger.setAttribute('aria-activedescendant', items[bounded].id);
            items[bounded].scrollIntoView({ block: 'nearest' });
        };
        const openMenu = () => {
            if (select.disabled || wrapper.classList.contains('open')) return;
            wrapper.classList.add('open');
            document.body.appendChild(optionsContainer);
            optionsContainer.classList.add('open');
            openCustomSelect = { wrapper, trigger, menu: optionsContainer };
            trigger.setAttribute('aria-expanded', 'true');
            positionCustomSelect();
        };
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = wrapper.classList.contains('open');
            closeCustomSelect();
            if (!isOpen) openMenu();
        });
        trigger.addEventListener('keydown', (event) => {
            const isOpen = wrapper.classList.contains('open');
            const items = optionItems();
            switch (event.key) {
                case 'ArrowDown':
                case 'ArrowUp':
                    event.preventDefault();
                    if (!isOpen) { openMenu(); setActive(event.key === 'ArrowDown' ? 0 : items.length - 1); }
                    else setActive(activeIndex() + (event.key === 'ArrowDown' ? 1 : -1));
                    break;
                case 'Home':
                case 'End':
                    if (!isOpen) return;
                    event.preventDefault();
                    setActive(event.key === 'Home' ? 0 : items.length - 1);
                    break;
                case 'Enter':
                case ' ':
                    event.preventDefault();
                    if (isOpen) items[activeIndex()]?.click();
                    else openMenu();
                    break;
                case 'Escape':
                    if (!isOpen) return;
                    event.preventDefault();
                    event.stopPropagation();
                    closeCustomSelect(true);
                    break;
                case 'Tab':
                    if (isOpen) closeCustomSelect();
                    break;
                default:
                    // 首字母跳转:从当前高亮项之后开始,循环查找
                    if (isOpen && event.key.length === 1) {
                        const key = event.key.toLowerCase();
                        const start = activeIndex();
                        for (let step = 1; step <= items.length; step += 1) {
                            const idx = (start + step) % items.length;
                            if ((items[idx].textContent || '').trim().toLowerCase().startsWith(key)) {
                                event.preventDefault();
                                setActive(idx);
                                break;
                            }
                        }
                    }
            }
        });
    };

    const updateCustomSelectUI = (selectId, val) => {
        const select = document.getElementById(selectId);
        if (!select) return;
        select.value = val;
        const wrapper = select.nextElementSibling;
        if (openCustomSelect?.wrapper === wrapper) closeCustomSelect();
        if (wrapper && wrapper.classList.contains('custom-select-wrapper')) {
            const triggerText = wrapper.querySelector('.custom-select-text');
            const selectedOpt = select.options[select.selectedIndex];
            if (selectedOpt) {
                const optKey = selectedOpt.getAttribute('data-i18n');
                triggerText.textContent = optKey ? getMsg(optKey) : selectedOpt.textContent;
                if (optKey) triggerText.setAttribute('data-i18n', optKey);
            }
            wrapper.querySelectorAll('.custom-select-option').forEach(el => {
                el.classList.toggle('selected', el.dataset.value === val);
            });
        }
    };

    const translateText = (lang) => {
        appState.lang = lang;
        document.querySelectorAll("[data-i18n]").forEach(el => {
            const key = el.getAttribute('data-i18n');
            if (key) el.textContent = getMsg(key);
        });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
            const key = el.getAttribute('data-i18n-placeholder');
            if (key) el.setAttribute('placeholder', getMsg(key));
        });
        document.querySelectorAll('.manage-widget, .virus-widget').forEach(widget => {
            if (widget.buildHeader) widget.buildHeader();
            if (widget.renderData) widget.renderData();
        });
        document.documentElement.lang = langMap[lang] || "en";
        const decisionTitle = document.getElementById('clear_alert_rules_title');
        const decisionDescription = document.getElementById('clear_alert_rules_desc');
        if (decisionTitle) decisionTitle.textContent = /^zh/.test(document.documentElement.lang) ? '清除已记住的告警决定' : 'Clear remembered alert decisions';
        if (decisionDescription) decisionDescription.textContent = /^zh/.test(document.documentElement.lang) ? '撤销永久允许及短期重复决定规则（重复窗口随确认次数延长，最长 1 小时）；保留普通白名单' : 'Revoke permanent and short-lived alert rules; keep the regular whitelist';

        const progressText = document.getElementById('progress_text');
        if (progressText && progressText.dataset.dynamicMsg) {
            try {
                const msgs = JSON.parse(progressText.dataset.dynamicMsg);
                if (msgs[lang]) progressText.textContent = msgs[lang];
            } catch (e) {}
        }
        renderMenuStatus();
        refreshAiTokenUsage();
        refreshIconButtonLabels();
        // 首页总述不是固定文案(跟着防护灯走),translateText 刚把它重置成了默认值,这里重算
        if (appState.configCache) updateProtectionLights(appState.configCache);
    };

    const applyTheme = (theme) => {
        // 单一入口:主题解析/变量注入统一交给 PyasTheme,避免与 theme.js 双份维护
        appState.theme = theme;
        window.PyasTheme.apply(theme);
    };

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
        if (appState.theme === "system_switch") applyTheme("system_switch");
    });

    const renderDataGrid = (containerSelector, dataList, columns, valKey, defaultChecked = false) => {
        const widget = document.querySelector(`${containerSelector} .manage-widget`) || document.querySelector(`${containerSelector} .virus-widget`);
        const listUl = document.querySelector(`${containerSelector} .manage-list`) || document.querySelector(`${containerSelector} .virus-list`);
        const searchInput = document.querySelector(`${containerSelector} .search-box input`);
        if (!widget || !listUl) return;

        const isInit = !widget.gridState;
        if (isInit) {
            const containerWidth = widget.clientWidth || 800;
            const availableWidth = Math.max(containerWidth - 60 - (columns.length * 16), 400); 
            const totalFlex = columns.reduce((sum, c) => sum + (c.flex || 1), 0);
            
            widget.gridState = {
                sortKey: columns[0]?.key || '', sortAsc: !(columns[0] && columns[0].defaultDesc), filterText: "",
                colWidths: columns.map(c => Math.max(((c.flex || 1) / totalFlex) * availableWidth, 60)),
                checkedSet: new Set()
            };
            
            widget.gridState.colWidths.forEach((w, idx) => widget.style.setProperty(`--col-${idx}`, `${w}px`));
            const header = document.createElement('div');
            header.className = 'manage-list-header';
            widget.insertBefore(header, widget.firstChild);

            widget.buildHeader = () => {
                const headerColsHtml = columns.map((col, idx) => `
                    <div class="col-header" data-key="${col.key}" data-idx="${idx}" style="width: var(--col-${idx}); flex: 0 0 auto;">
                        <span class="header-text" data-i18n="${col.label}">${getMsg(col.label)}</span>
                        <span class="sort-icon">${widget.gridState.sortKey === col.key ? (widget.gridState.sortAsc ? '▲' : '▼') : ''}</span>
                        <div class="col-resizer"></div>
                    </div>`).join('');

                header.innerHTML = `<input type="checkbox" class="select-all-cb" title="${getMsg('btn_select_all')}"><div class="header-cols-container">${headerColsHtml}</div>`;

                header.querySelectorAll('.col-header').forEach(el => {
                    el.addEventListener('click', () => {
                        const key = el.dataset.key;
                        widget.gridState.sortAsc = widget.gridState.sortKey === key ? !widget.gridState.sortAsc : true;
                        widget.gridState.sortKey = key;
                        widget.buildHeader(); 
                        widget.renderData(widget.gridState.filterText, false); 
                    });
                });

                header.querySelectorAll('.col-resizer').forEach(resizer => {
                    resizer.addEventListener('mousedown', (e) => {
                        e.stopPropagation();
                        const idx = parseInt(resizer.parentElement.dataset.idx);
                        const startX = e.clientX;
                        const startWidth = widget.gridState.colWidths[idx];

                        const onMouseMove = (me) => {
                            const newWidth = Math.max(startWidth + (me.clientX - startX), 40);
                            widget.gridState.colWidths[idx] = newWidth;
                            widget.style.setProperty(`--col-${idx}`, `${newWidth}px`);
                        };
                        const onMouseUp = () => {
                            document.body.classList.remove('resizing-active');
                            document.removeEventListener('mousemove', onMouseMove);
                            document.removeEventListener('mouseup', onMouseUp);
                        };
                        document.body.classList.add('resizing-active');
                        document.addEventListener('mousemove', onMouseMove);
                        document.addEventListener('mouseup', onMouseUp);
                    });
                    resizer.addEventListener('click', (e) => e.stopPropagation());
                });

                const selectAllCb = header.querySelector('.select-all-cb');
                if (selectAllCb) {
                    selectAllCb.addEventListener('change', (e) => {
                        const isChecked = e.target.checked;
                        listUl.querySelectorAll('.manage-list-item input[type="checkbox"]').forEach(cb => cb.checked = isChecked);
                        (widget.gridState.lastDisplayData || []).forEach(item => {
                            const valStr = String(item[valKey]);
                            isChecked ? widget.gridState.checkedSet.add(valStr) : widget.gridState.checkedSet.delete(valStr);
                            if (containerSelector === '#scan_window') appState.virusMap.set(valStr, isChecked);
                        });
                        if (containerSelector === '#scan_window') checkVirusListEmpty();
                    });
                }
            };
            widget.buildHeader();

            listUl.addEventListener('click', (e) => {
                const li = e.target.closest('.manage-list-item');
                if (!li) return;
                const cb = li.querySelector('input[type="checkbox"]');
                if (e.target.tagName !== 'INPUT') cb.checked = !cb.checked;
                
                cb.checked ? widget.gridState.checkedSet.add(cb.value) : widget.gridState.checkedSet.delete(cb.value);
                if (containerSelector === '#scan_window') {
                    appState.virusMap.set(cb.value, cb.checked);
                    checkVirusListEmpty();
                }
                if (widget.updateSelectAllState) widget.updateSelectAllState();
            });

            if (searchInput) searchInput.addEventListener('input', (e) => widget.renderData(e.target.value, false));
        }

        const state = widget.gridState;
        widget.renderData = (filterText = state.filterText, resetDataCheck = false) => {
            state.filterText = filterText;
            if (resetDataCheck) {
                state.checkedSet.clear();
                if (defaultChecked) dataList.forEach(item => state.checkedSet.add(String(item[valKey])));
            } else {
                const validKeys = new Set(dataList.map(item => String(item[valKey])));
                for (const val of state.checkedSet) if (!validKeys.has(val)) state.checkedSet.delete(val);
                if (state.checkedSet.size === 0 && defaultChecked && dataList.length > 0) {
                    if (!listUl.querySelector('input[type="checkbox"]:checked')) {
                        dataList.forEach(item => state.checkedSet.add(String(item[valKey])));
                    }
                }
            }

            const header = widget.querySelector('.manage-list-header');
            const selectAllCb = header ? header.querySelector('.select-all-cb') : null;
            if (selectAllCb) selectAllCb.disabled = dataList.length === 0;

            const ft = filterText.toLowerCase();
            let displayData = dataList.filter(item => !filterText || columns.some(col => {
                const rawVal = String(item[col.key] || '');
                if (rawVal.toLowerCase().includes(ft)) return true;
                if (col.isI18n) {
                    const transVal = getMsg(rawVal);
                    if (transVal && transVal.toLowerCase().includes(ft)) return true;
                }
                return false;
            }));

            displayData.sort((a, b) => {
                const valA = a[state.sortKey] ?? '', valB = b[state.sortKey] ?? '';
                
                const rawKeyMap = { 'sizeStr': 'size', 'downStr': 'down', 'upStr': 'up', 'createdStr': 'created' };
                if (rawKeyMap[state.sortKey] && rawKeyMap[state.sortKey] in a && rawKeyMap[state.sortKey] in b) {
                    const rawKey = rawKeyMap[state.sortKey];
                    return state.sortAsc ? a[rawKey] - b[rawKey] : b[rawKey] - a[rawKey];
                }

                const numA = parseFloat(valA), numB = parseFloat(valB);
                if (!isNaN(numA) && !isNaN(numB) && String(valA).trim() !== '' && String(valB).trim() !== '') return state.sortAsc ? numA - numB : numB - numA;
                return state.sortAsc ? String(valA).localeCompare(String(valB)) : String(valB).localeCompare(String(valA));
            });

            widget.gridState.lastDisplayData = displayData;
            widget.updateSelectAllState = () => {
                if (!selectAllCb) return;
                const cData = widget.gridState.lastDisplayData || [];
                if (cData.length === 0) { selectAllCb.checked = false; selectAllCb.indeterminate = false; return; }
                const checkedCount = cData.filter(item => containerSelector === '#scan_window' ? appState.virusMap.get(String(item[valKey])) : widget.gridState.checkedSet.has(String(item[valKey]))).length;
                selectAllCb.checked = (checkedCount > 0 && checkedCount === cData.length);
                selectAllCb.indeterminate = (checkedCount > 0 && checkedCount < cData.length);
            };

            const MAX_ITEMS = 1000;
            const limitData = displayData.slice(0, MAX_ITEMS);
            
            let htmlContent = limitData.map(item => {
                const itemValStr = String(item[valKey]);
                let isChecked = containerSelector === '#scan_window' ? (appState.virusMap.get(itemValStr) ?? true) : state.checkedSet.has(itemValStr);
                if (containerSelector === '#scan_window') appState.virusMap.set(itemValStr, isChecked);
                
                const rowColsHtml = columns.map((col, idx) => {
                    const rawVal = String(item[col.key] || '');
                    let valStr = col.isI18n ? getMsg(rawVal) : rawVal;
                    if (rawVal === '未知路徑' || rawVal === 'path_unknown') valStr = getMsg('path_unknown');
                    return `<div class="row-col" style="width: var(--col-${idx}); flex: 0 0 auto;" title="${escapeHtml(valStr)}">${escapeHtml(valStr)}</div>`;
                }).join('');

                const rowAttrs = [
                    item.level ? `data-level="${escapeHtml(String(item.level))}"` : '',
                    item.action ? `data-action="${escapeHtml(String(item.action))}"` : '',
                    (item.pid !== undefined && item.pid !== null && item.pid !== '') ? `data-pid="${escapeHtml(String(item.pid))}"` : ''
                ].filter(Boolean).join(' ');

                return `<li class="manage-list-item" ${rowAttrs}><input type="checkbox" value="${escapeHtml(itemValStr)}" ${isChecked ? 'checked' : ''} data-path="${escapeHtml(item.path || '')}"><div class="manage-list-item-content">${rowColsHtml}</div></li>`;
            }).join('');

            if (displayData.length > MAX_ITEMS) {
                htmlContent += `<li class="manage-list-item" style="pointer-events: none; justify-content: center;"><div style="color: var(--text-secondary); padding: 10px;">${escapeHtml(formatMsg("msg_too_many", MAX_ITEMS))}</div></li>`;
            }

            const scrollContainer = listUl.parentElement;
            const scrollTop = scrollContainer ? scrollContainer.scrollTop : 0;
            listUl.innerHTML = htmlContent;
            if (scrollContainer) scrollContainer.scrollTop = scrollTop;
            widget.updateSelectAllState();
        };
        widget.renderData(state.filterText, isInit);
    };

    const getCheckedValues = (selector) => {
        if (selector === '#log_export_window') {
            const widget = document.querySelector(`${selector} .manage-widget`);
            if (widget?.gridState) return Array.from(widget.gridState.checkedSet);
        }
        return Array.from(document.querySelectorAll(`${selector} .manage-list-item input[type="checkbox"]:checked`)).map(cb => cb.value);
    };
    const formatSize = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const rebuildCustomSelect = (selectId) => {
        const select = document.getElementById(selectId);
        if (!select) return;
        if (openCustomSelect?.wrapper === select.nextElementSibling) closeCustomSelect();
        let sibling = select.nextElementSibling;
        while (sibling && sibling.classList.contains('custom-select-wrapper')) {
            const toRemove = sibling;
            sibling = sibling.nextElementSibling;
            toRemove.remove();
        }
        buildCustomSelectElement(select);
    };

    const changeScanSelectMode = (mode) => {
        const select = document.getElementById('scan_method_select');
        if (!select) return;
        select.innerHTML = `<option value="none" selected disabled data-i18n="btn_select">${getMsg('btn_select')}</option>`;
        if (mode === 'scan') {
            select.innerHTML += `
                <option value="smart" data-i18n="scan_smart">${getMsg('scan_smart')}</option>
                <option value="file" data-i18n="scan_file">${getMsg('scan_file')}</option>
                <option value="path" data-i18n="scan_path">${getMsg('scan_path')}</option>
                <option value="full" data-i18n="scan_full">${getMsg('scan_full')}</option>`;
        } else if (mode === 'action') {
            select.innerHTML += `
                <option value="delete" data-i18n="act_del">${getMsg('act_del')}</option>
                <option value="ignore" data-i18n="act_ignore">${getMsg('act_ignore')}</option>
                <option value="quarantine" data-i18n="act_quarantine">${getMsg('act_quarantine')}</option>
                <option value="whitelist" data-i18n="act_white">${getMsg('act_white')}</option>`;
        }
        rebuildCustomSelect('scan_method_select');
    };

    const checkVirusListEmpty = () => {
        updateCustomSelectUI('scan_method_select', 'none');
        if (appState.virusResults.length === 0) {
            appState.virusMap.clear();
            changeScanSelectMode('scan');
            const title = document.querySelector('#scan_window .section-title');
            const text = document.getElementById('progress_text');
            if (title) { 
                title.setAttribute('data-i18n', 'scan_virus'); 
                title.textContent = getMsg('scan_virus'); 
            }
            if (text) {
                text.setAttribute('data-i18n', 'scan_virus_desc');
                text.removeAttribute('data-dynamic-msg');
                text.textContent = getMsg('scan_virus_desc');
            }
        }
    };

    const triggerScan = (method) => {
        if (!window.pywebview) return;
        appState.scanning = true;
        appState.virusMap.clear();
        appState.virusResults = [];
        renderDataGrid('#scan_window', appState.virusResults, cols.virus, 'path', true);
        changeScanSelectMode('scan');
        document.getElementById('scan_method_select')?.classList.add('hidden');
        const stopBtn = document.getElementById('stop_btn');
        if (stopBtn) {
            stopBtn.classList.remove('hidden');
            stopBtn.disabled = false;
            delete stopBtn.dataset.stopping;
        }

        const title = document.querySelector('#scan_window .section-title');
        const text = document.getElementById('progress_text');
        if (title) { title.setAttribute('data-i18n', 'status_scanning'); title.textContent = getMsg('status_scanning'); }
        if (text) { text.setAttribute('data-i18n', 'msg_init'); text.removeAttribute('data-dynamic-msg'); text.textContent = getMsg('msg_init'); }
        window.pywebview.api.trigger_scan(method);
    };

    const handleVirusActions = (action) => {
        if (!window.pywebview) return;
        const paths = Array.from(appState.virusMap.entries()).filter(([_, checked]) => checked).map(([p]) => p);
        if (paths.length === 0) return updateCustomSelectUI('scan_method_select', 'none');

        const wrapper = document.getElementById('scan_method_select').nextElementSibling;
        if (wrapper) wrapper.style.pointerEvents = 'none';

        const finalize = () => {
            if (wrapper) wrapper.style.pointerEvents = '';
            checkVirusListEmpty();
        };

        const removeItems = (removedPaths) => {
            const removedSet = new Set(removedPaths);
            removedPaths.forEach(p => appState.virusMap.delete(p));
            appState.virusResults = appState.virusResults.filter(r => !removedSet.has(r.path));
            renderDataGrid('#scan_window', appState.virusResults, cols.virus, 'path', false);
        };

        if (action === 'delete') {
            window.pywebview.api.solve_scan(paths).then((deleted) => { removeItems(deleted); finalize(); });
        } else if (action === 'ignore') {
            window.pywebview.api.remove_virus_result(paths).then(() => { removeItems(paths); finalize(); });
        } else if (action === 'quarantine' || action === 'whitelist') {
            const listKey = action === 'quarantine' ? 'quarantine' : 'white_list';
            window.pywebview.api.manage_named_list(listKey, paths, 'add').then(() => {
                window.pywebview.api.remove_virus_result(paths).then(() => { removeItems(paths); finalize(); });
            });
        }
    };

    const fetchProcs = () => {
        if (!appState.taskmgrActive || !window.pywebview) return;
        const widget = document.querySelector('#taskmgr_window .manage-widget');
        const blockFetch = (widget && widget.gridState?.checkedSet.size > 0) || document.querySelector('.custom-context-menu.show') || document.body.classList.contains('resizing-active');
        
        if (!blockFetch) {
            window.pywebview.api.get_process_list().then(procs => {
                const mapped = procs.map(p => ({ name: p.name, pid: p.pid, path: (p.path && p.path !== "None" && p.path !== "Unknown") ? p.path : "path_unknown" }));
                renderDataGrid('#taskmgr_window', mapped, cols.process, 'pid', false);
                if (appState.taskmgrActive) appState.taskmgrTimer = setTimeout(fetchProcs, 1000);
            }).catch(() => { if (appState.taskmgrActive) appState.taskmgrTimer = setTimeout(fetchProcs, 1000); });
        } else {
            if (appState.taskmgrActive) appState.taskmgrTimer = setTimeout(fetchProcs, 1000);
        }
    };
    
    const fetchNetmon = () => {
        if (!appState.netmonActive || !window.pywebview) return;
        const widget = document.querySelector('#netmon_window .manage-widget');
        const blockFetch = (widget && widget.gridState?.checkedSet.size > 0) || document.querySelector('.custom-context-menu.show') || document.body.classList.contains('resizing-active');
        
        if (!blockFetch) {
            window.pywebview.api.get_traffic_list().then(list => {
                const mapped = list.map(item => ({
                    name: item.name,
                    pid: item.pid,
                    downStr: formatSize(item.down) + '/s',
                    down: item.down,
                    upStr: formatSize(item.up) + '/s',
                    up: item.up,
                    connCount: item.conn,
                    path: (item.path && item.path !== "None" && item.path !== "Unknown") ? item.path : "path_unknown"
                }));
                renderDataGrid('#netmon_window', mapped, cols.netmon, 'pid', false);
                if (appState.netmonActive) appState.netmonTimer = setTimeout(fetchNetmon, 1000);
            }).catch(() => { if (appState.netmonActive) appState.netmonTimer = setTimeout(fetchNetmon, 1000); });
        } else {
            if (appState.netmonActive) appState.netmonTimer = setTimeout(fetchNetmon, 1000);
        }
    };

    const fetchStartup = () => {
        if (!window.pywebview) return;
        const listUl = document.querySelector('#startup_window .manage-list');
        if (listUl && !listUl.children.length) {
            listUl.innerHTML = `<li class="manage-list-item" style="pointer-events: none; justify-content: center; height: 100%; border: none;"><div style="color: var(--text-secondary); padding: 40px; font-size: 15px;">${getMsg('msg_init')}</div></li>`;
        }
        window.pywebview.api.get_startup_list().then(items => {
            const mapped = items.map(item => ({ id: item.id, type: item.type, name: item.name, status: item.status === 'enabled' ? 'status_enabled' : 'status_disabled', path: item.path || 'path_unknown' }));
            renderDataGrid('#startup_window', mapped, cols.startup, 'id', false);
        });
    };

    const fetchJunk = () => {
        if (!window.pywebview) return;
        const widget = document.querySelector('#junk_window .manage-widget');
        if (widget?.gridState) widget.gridState.checkedSet.clear();
        const listUl = document.querySelector('#junk_window .manage-list');
        if (listUl && !listUl.children.length) {
            listUl.innerHTML = `<li class="manage-list-item" style="pointer-events: none; justify-content: center; height: 100%; border: none;"><div style="color: var(--text-secondary); padding: 40px; font-size: 15px;">${getMsg('msg_init')}</div></li>`;
        }
        window.pywebview.api.scan_system_junk().then(list => {
            appState.junkList = list.map(item => ({ path: item.path, sizeStr: formatSize(item.size), size: item.size }));
            renderDataGrid('#junk_window', appState.junkList, cols.junk, 'path', true);
        });
    };

    const fetchRepair = () => {
        if (!window.pywebview) return;
        const listUl = document.querySelector('#repair_window .manage-list');
        if (listUl && !listUl.children.length) {
            listUl.innerHTML = `<li class="manage-list-item" style="pointer-events: none; justify-content: center; height: 100%; border: none;"><div style="color: var(--text-secondary); padding: 40px; font-size: 15px;">${getMsg('msg_init')}</div></li>`;
        }
        window.pywebview.api.scan_system_repair().then(list => renderDataGrid('#repair_window', list, cols.repair, 'id', true));
    };

    const refreshConfigLists = () => {
        if (!window.pywebview) return;
        window.pywebview.api.get_config().then(cfg => {
            const formatTime = (ts) => {
                if (!ts) return '-';
                const d = new Date(ts * 1000);
                const pad = n => n.toString().padStart(2, '0');
                return `[${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}]`;
            };
            const mapList = (arr) => (arr || []).map(i => ({
                path: i.file || (typeof i === 'string' ? i : ''),
                time_str: formatTime(i.time)
            }));
            renderDataGrid('#whitelist_window', mapList(cfg.white_list), cols.fileList, 'path');
            renderDataGrid('#quarantine_window', mapList(cfg.quarantine), cols.fileList, 'path');
            renderDataGrid('#custom_protect_window', mapList(cfg.custom_rule), cols.fileList, 'path');
            const popupRules = (cfg.block_list || []).map((item, index) => ({ mode: item.schema_version === 2 ? (item.match_mode === 'title' ? 'popup_fallback' : 'popup_adaptive') : 'popup_fallback', exe: item.exe || '*', class: item.class || '*', title: item.title || '*', value: item.id || `legacy:${index}` }));
            renderDataGrid('#popup_window', popupRules, cols.popup, 'value');
        });
    };

    const switchPage = (targetId) => {
        if (targetId === 'ai_window') loadAiPageData?.();
        const oldActive = document.querySelector('.page.active');
        if (oldActive && oldActive.id !== targetId) {
            if (oldActive.id === 'junk_window') {
                appState.junkList = [];
                renderDataGrid('#junk_window', [], cols.junk, 'path', true);
                const input = document.querySelector('#junk_window .search-box input');
                if (input) input.value = '';
            } else if (oldActive.id === 'repair_window') {
                renderDataGrid('#repair_window', [], cols.repair, 'id', true);
            }
        }

        closeCustomSelect();
        document.querySelectorAll('.page, .nav-btn').forEach(el => el.classList.remove('active'));
        document.getElementById(targetId)?.classList.add('active');
        document.querySelector(`aside .nav-btn[data-target="${targetId}"]`)?.classList.add('active');
        
        appState.taskmgrActive = targetId === 'taskmgr_window';
        if (appState.taskmgrActive) fetchProcs();
        else if (appState.taskmgrTimer) { clearTimeout(appState.taskmgrTimer); appState.taskmgrTimer = null; }

        appState.netmonActive = targetId === 'netmon_window';
        if (appState.netmonActive) fetchNetmon();
        else if (appState.netmonTimer) { clearTimeout(appState.netmonTimer); appState.netmonTimer = null; }

        if (targetId === 'startup_window') fetchStartup();
        if (targetId === 'junk_window') fetchJunk();
        if (targetId === 'repair_window') fetchRepair();

        if (['whitelist_window', 'quarantine_window', 'popup_window', 'custom_protect_window'].includes(targetId)) refreshConfigLists();

        if (targetId === 'release_window' && window.pywebview) {
            window.pywebview.api.list_release_records().then(data => {
                renderDataGrid('#release_window', buildReleaseRows(data), cols.release, 'value', false);
            }).catch(() => {});
        }

        if (targetId === 'about_window') loadChangelogs();
        if (targetId === 'ai_window') refreshAiTokenUsage();
        if (targetId === 'home_window') {
            if (homeLogFilter === 'pending') fetchPendingThreatQueue();
            if (homeLogDirty) renderHomeLogs();
        }

        if (targetId === 'log_export_window' && window.pywebview) {
            window.pywebview.api.get_logs().then(logs => {
                const logList = logs.reverse().map(log => ({ time_str: `[${log.time_str}]`, level: log.level, action: log.action, source: log.source || '-', id: log.id }));
                renderDataGrid('#log_export_window', logList, cols.log, 'id', true);
            });
        }
    };

    window.addVirusResult = (label, path) => {
        if (!appState.virusMap.has(path)) {
            appState.virusResults.push({ label, path });
            appState.virusMap.set(path, true);
            const widget = document.querySelector('#scan_window .virus-widget');
            if (widget && widget.renderData) {
                if (window.virusRenderTimeout) clearTimeout(window.virusRenderTimeout);
                window.virusRenderTimeout = setTimeout(() => widget.renderData(widget.gridState.filterText, false), 50);
            }
        }
    };

    window.updateScanProgress = (path) => {
        const title = document.querySelector('#scan_window .section-title');
        const text = document.getElementById('progress_text');
        if (title) { title.setAttribute('data-i18n', 'status_scanning'); title.textContent = getMsg('status_scanning'); }
        if (text) { text.removeAttribute('data-i18n'); text.removeAttribute('data-dynamic-msg'); text.textContent = path; }
    };

    window.updateDeleteProgress = (path) => {
        const title = document.querySelector('#scan_window .section-title');
        const text = document.getElementById('progress_text');
        if (title) { title.setAttribute('data-i18n', 'status_deleting'); title.textContent = getMsg('status_deleting'); }
        if (text) { text.removeAttribute('data-i18n'); text.removeAttribute('data-dynamic-msg'); text.textContent = path; }
    };

    window.finishScan = (msgData, count) => {
        appState.scanning = false;
        const title = document.querySelector('#scan_window .section-title');
        const text = document.getElementById('progress_text');
        if (title) { title.setAttribute('data-i18n', 'scan_virus'); title.textContent = getMsg('scan_virus'); }
        if (text) {
            if (typeof msgData === 'object' && msgData !== null) {
                text.removeAttribute('data-i18n');
                text.dataset.dynamicMsg = JSON.stringify(msgData);
                text.textContent = msgData[appState.lang] || msgData["english_switch"];
            } else {
                text.removeAttribute('data-dynamic-msg');
                text.setAttribute('data-i18n', msgData);
                text.textContent = getMsg(msgData);
            }
        }
        const stopBtn = document.getElementById('stop_btn');
        if (stopBtn) {
            stopBtn.classList.add('hidden');
            stopBtn.disabled = false;
            delete stopBtn.dataset.stopping;
        }
        document.getElementById('scan_method_select')?.classList.remove('hidden');
        changeScanSelectMode(count > 0 ? 'action' : 'scan');
        updateCustomSelectUI('scan_method_select', 'none');
    };

    const homeLogs = [];
    let homeLogFilter = 'all';
    let homeLogRenderTimer = null;

    let homeLogDirty = false;
    let homeLogSortDesc = true;
    let homeLogBackfillInFlight = false;

    // 待处理告警筛选:展示当前弹窗队列(与日志流无关),由 get_pending_threat_queue 提供
    let pendingThreatEvents = [];

    const renderPendingThreatList = (listUl) => {
        if (!pendingThreatEvents.length) {
            listUl.innerHTML = '<li class="home-log-empty">' + escapeHtml(getMsg('pending_threats_empty')) + '</li>';
            return;
        }
        listUl.innerHTML = pendingThreatEvents.map(e => {
            const title = String(e.title || '');
            const count = Number(e.count) || 1;
            const active = !!e.active;
            const meta = '×' + count + (active ? ' · ' + getMsg('pending_threats_active') : '');
            return '<li class="home-log-item lv-PENDING' + (active ? ' is-active' : '') + '" title="' + escapeHtml(title) + '">'
                + '<span class="hl-level">' + escapeHtml(getMsg('pending_threats')) + '</span>'
                + '<span class="hl-action">' + escapeHtml(title) + '</span>'
                + '<span class="hl-source">' + escapeHtml(meta) + '</span>'
                + '</li>';
        }).join('');
    };

    const applyPendingThreatQueue = (queue) => {
        pendingThreatEvents = Array.isArray(queue?.events) ? queue.events : [];
        if (homeLogFilter === 'pending') renderHomeLogs();
    };

    const fetchPendingThreatQueue = async () => {
        if (!window.pywebview?.api?.get_pending_threat_queue) return;
        try {
            applyPendingThreatQueue(await window.pywebview.api.get_pending_threat_queue());
        } catch (error) { console.error('Pending threats queue failed', error); }
    };
    window.fetchPendingThreatQueue = fetchPendingThreatQueue;

    // 空面板文案,两种情况分开说:一条日志都没有(新装首启的常态) vs 当前筛选没命中(换筛选就有)。
    // 前者原来直接写空字符串,整块圆角面板是一片空白,看不出是没数据还是加载失败。
    // 单独抽出来是因为 startup 的 backfill 空分支也要用它 —— 那里不能走 renderHomeLogs(见下方注释)。
    const paintHomeLogEmpty = () => {
        const listUl = document.getElementById('home_log_list');
        if (!listUl || homeLogFilter === 'pending') return;  // 待处理告警有自己的空态
        listUl.innerHTML = '<li class="home-log-empty">'
            + escapeHtml(getMsg(homeLogs.length ? 'log_filter_empty' : 'log_empty')) + '</li>';
    };

    const backfillHomeLogs = () => {
        if (!window.pywebview || homeLogBackfillInFlight) return;
        homeLogBackfillInFlight = true;
        window.pywebview.api.get_logs().then(logs => {
            homeLogBackfillInFlight = false;
            window.pywebview.api.report_ui_error('home-log-backfill', 'received ' + (logs ? logs.length : 'null') + ' entries');
            // 无历史日志时直接返回:绝不再回调 renderHomeLogs——
            // 空列表会再次触发 backfill,形成互递归把主线程微任务饿死(新装首启零日志即假死)
            // 但面板本身要有话说,否则新装首启是一整块空白,故在这里直接落空态文案。
            if (!logs || !logs.length) { paintHomeLogEmpty(); return; }
            const merged = [...logs];
            homeLogs.forEach(l => { if (!merged.some(m => m.id === l.id)) merged.push(l); });
            homeLogs.length = 0;
            merged.slice(-200).forEach(l => homeLogs.push(l));
            renderHomeLogs();
        }).catch(err => {
            homeLogBackfillInFlight = false;
            // 失败同样不回调渲染:理由同上,避免 backfill<->render 互递归
            window.pywebview.api.report_ui_error('home-log-backfill', 'failed: ' + String(err && err.message || err));
        });
    };

    const renderHomeLogs = () => {
        homeLogDirty = false;
        const listUl = document.getElementById('home_log_list');
        if (!listUl) return;
        if (!document.getElementById('home_window')?.classList.contains('active')) {
            homeLogDirty = true;
            return;
        }

        if (homeLogFilter === 'pending') {
            renderPendingThreatList(listUl);
            return;
        }

        // 智能体筛选:三类审计动作(检测/提权/事件关联),跨 INFO/WARN 两个级别
        const agentActions = ['Agent Detected', 'Agent Elevated', 'Agent Related Event'];
        const data = (homeLogFilter === 'all' ? homeLogs
            : homeLogFilter === 'agent' ? homeLogs.filter(l => agentActions.includes(String(l.action || '')))
            : homeLogs.filter(l => l.level === homeLogFilter))
            .slice(-200)
            .sort((a, b) => (homeLogSortDesc ? -1 : 1) * String(a.time_str || '').localeCompare(String(b.time_str || '')));

        if (!data.length) {
            paintHomeLogEmpty();
            if (!homeLogs.length) backfillHomeLogs();
            return;
        }

        listUl.innerHTML = data.map(e => {
            const lv = String(e.level || '');
            const actionRaw = String(e.action || '');
            const actionText = getMsg(actionRaw) !== actionRaw ? getMsg(actionRaw) : actionRaw;
            const attrs = lv === 'BLOCK'
                ? ' data-action="' + escapeHtml(actionRaw) + '" data-pid="' + escapeHtml(String(e.pid ?? '')) + '" data-path="' + escapeHtml(String(e.source || '')) + '"'
                : '';
            const sourceText = String(e.source || e.detail || '');
            const rowText = [e.time_str || '', getMsg(lv) || lv, actionText, sourceText].join('\t');
            const copyText = rowText + (e.detail && e.detail !== sourceText ? '\n' + e.detail : '');
            return '<li class="home-log-item lv-' + escapeHtml(lv) + '" data-copy-text="' + escapeHtml(copyText) + '"' + attrs + '>'
                + '<span class="hl-time">' + escapeHtml(e.time_str || '') + '</span>'
                + '<span class="hl-level">' + escapeHtml(getMsg(lv) || lv) + '</span>'
                + '<span class="hl-action">' + escapeHtml(actionText) + '</span>'
                + '<span class="hl-source" title="' + escapeHtml(sourceText) + '">' + escapeHtml(sourceText) + '</span>'
                + '</li>';
        }).join('');
    };

    const scheduleHomeLogRender = () => {
        clearTimeout(homeLogRenderTimer);
        homeLogRenderTimer = setTimeout(renderHomeLogs, 300);
    };

    let logGridTimer = null;
    let logGridBusy = false;
    let logGridDirty = false;
    const refreshLogGrid = async () => {
        logGridTimer = null;
        if (logGridBusy || !logGridDirty) return;
        if (!document.getElementById('log_export_window')?.classList.contains('active')) return;
        if (document.body.classList.contains('resizing-active')) {
            logGridTimer = setTimeout(refreshLogGrid, 300);
            return;
        }
        logGridBusy = true;
        logGridDirty = false;
        try {
            const logs = await window.pywebview.api.get_logs();
            if (document.getElementById('log_export_window')?.classList.contains('active')) {
                const logList = logs.reverse().map(log => ({ time_str: `[${log.time_str}]`, level: log.level, action: log.action, source: log.source || '-', id: log.id }));
                renderDataGrid('#log_export_window', logList, cols.log, 'id', true);
            }
        } catch (error) { console.error('Log refresh failed', error); }
        finally {
            logGridBusy = false;
            if (logGridDirty && logGridTimer === null) logGridTimer = setTimeout(refreshLogGrid, 300);
        }
    };
    window.updateLogs = (entry) => {
        if (!entry) return;
        if (entry && entry.id && !homeLogs.some(l => l.id === entry.id)) {
            homeLogs.push(entry);
            if (homeLogs.length > 200) homeLogs.splice(0, homeLogs.length - 200);
            scheduleHomeLogRender();
        }

        if (document.getElementById('log_export_window')?.classList.contains('active') && window.pywebview) {
            logGridDirty = true;
            if (!logGridBusy && logGridTimer === null) logGridTimer = setTimeout(refreshLogGrid, 300);
        }

        if ((entry.action === 'System' && entry.detail === 'Engine Initialization Complete') || (entry.level === 'WARN' && entry.action === 'init_engine_thread')) {
            closeStartupOverlay();
            if (window.onEngineReady) window.onEngineReady();
        }
    };

    window.triggerContextScan = (targets) => {
        if (appState.scanning) return;
        switchPage('scan_window');
        if (window.pywebview) {
            appState.scanning = true;
            appState.virusMap.clear();
            appState.virusResults = [];
            renderDataGrid('#scan_window', appState.virusResults, cols.virus, 'path', true);
            document.getElementById('scan_method_select')?.classList.add('hidden');
            const stopBtn = document.getElementById('stop_btn');
            if (stopBtn) { stopBtn.classList.remove('hidden'); stopBtn.disabled = false; delete stopBtn.dataset.stopping; }
            changeScanSelectMode('scan');
            
            const title = document.querySelector('#scan_window .section-title');
            const text = document.getElementById('progress_text');
            if (title) { title.setAttribute('data-i18n', 'status_scanning'); title.textContent = getMsg('status_scanning'); }
            if (text) { text.setAttribute('data-i18n', 'msg_init'); text.removeAttribute('data-dynamic-msg'); text.textContent = getMsg('msg_init'); }
            
            const paths = Array.isArray(targets) ? targets : [targets];
            window.pywebview.api.start_scan(paths);
        }
    };

    window.revertSwitch = () => {}; 

    document.querySelectorAll('[data-target]').forEach(btn => btn.addEventListener('click', (e) => switchPage(e.currentTarget.getAttribute('data-target'))));

    // --- 无障碍:卡片入口可聚焦 + 纯图标控件补可访问名 ---
    const navLabelKeys = {
        home_window: 'nav_home', scan_window: 'nav_scan', tool_window: 'nav_tool',
        protect_window: 'nav_protect', ai_window: 'nav_ai', setting_window: 'nav_settings',
    };
    const ctrlLabelKeys = {
        about_button: 'btn_about', minimize_button: 'btn_minimize',
        maximize_button: 'btn_maximize', close_button: 'btn_close',
    };

    const applyIconButtonLabels = () => {
        // 侧栏导航与窗口控制都是纯图标按钮:补 aria-label + title(悬停提示)
        Object.entries(navLabelKeys).forEach(([target, key]) => {
            const button = document.querySelector(`.nav-btn[data-target="${target}"]`);
            if (!button) return;
            button.setAttribute('aria-label', getMsg(key));
            button.title = getMsg(key);
        });
        Object.entries(ctrlLabelKeys).forEach(([id, key]) => {
            const button = document.getElementById(id);
            if (!button) return;
            button.setAttribute('aria-label', getMsg(key));
            button.title = getMsg(key);
        });
        // 最大化/还原是同一个按钮的两种状态,标签要跟着当前图标走
        const maximize = document.getElementById('maximize_button');
        if (maximize) {
            const maximized = document.getElementById('icon_restore')?.classList.contains('hidden') === false;
            maximize.setAttribute('aria-label', getMsg(maximized ? 'btn_restore' : 'btn_maximize'));
            maximize.title = getMsg(maximized ? 'btn_restore' : 'btn_maximize');
        }
        // 搜索框清空按钮(需随语言切换更新)
        document.querySelectorAll('.search-clear').forEach(button => {
            button.setAttribute('aria-label', getMsg('btn_clear_input'));
            button.title = getMsg('btn_clear_input');
        });
    };
    refreshIconButtonLabels = applyIconButtonLabels;

    // 输入框右侧「圆形 + 叉号」清空按钮:统一注入,避免在每处 HTML 里重复写
    const attachClearButton = (container, input) => {
        if (container.querySelector('.search-clear')) return;
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'search-clear';
        button.setAttribute('aria-label', getMsg('btn_clear_input'));
        button.title = getMsg('btn_clear_input');
        button.innerHTML = '<svg aria-hidden="true" focusable="false"><use href="#i-close"/></svg>';
        button.addEventListener('click', () => {
            input.value = '';
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
            input.focus();
        });
        container.appendChild(button);
        const sync = () => container.classList.toggle('has-value', input.value.length > 0);
        input.addEventListener('input', sync);
        input.addEventListener('change', sync);
        sync();
    };

    // 配置回填是 .value = 直接赋值,不触发 input/change,has-value 永远不会加上。
    // 这里显式按当前值重算一次,保证预填值的输入框也有清空按钮。
    const syncClearButtons = () => {
        document.querySelectorAll('.search-box, .input-clearable').forEach(box => {
            const input = box.querySelector('input');
            if (input) box.classList.toggle('has-value', input.value.length > 0);
        });
        const modelInput = document.getElementById('ai_model_input');
        const modelClear = document.getElementById('ai_model_clear');
        if (modelInput && modelClear) modelClear.hidden = !modelInput.value.length;
    };

    const initSearchClearButtons = () => {
        document.querySelectorAll('.search-box').forEach(box => {
            const input = box.querySelector('input');
            if (input) attachClearButton(box, input);
        });

        // 裸输入框:包一层 .input-clearable,按钮绝对定位在右侧。
        // #ai_model_input 已有自己的 model-combo-clear,跳过以免双按钮。
        document.querySelectorAll('input[type="text"], input[type="password"], input[type="number"]').forEach(input => {
            if (input.closest('.search-box') || input.closest('.input-clearable')) return;
            if (input.id === 'ai_model_input') return;
            const wrapper = document.createElement('div');
            wrapper.className = 'input-clearable';
            input.parentNode.insertBefore(wrapper, input);
            wrapper.appendChild(input);
            // 数字框右侧有原生步进箭头,清空按钮左移避开
            if (input.type === 'number') wrapper.classList.add('has-spinner');
            attachClearButton(wrapper, input);
        });
    };

    const makeCardEntriesAccessible = () => {
        document.querySelectorAll('[data-target]').forEach(element => {
            if (element.tagName === 'BUTTON' || element.tagName === 'A') return;
            element.tabIndex = 0;
            element.setAttribute('role', 'button');
            if (!element.hasAttribute('aria-label')) {
                const title = element.querySelector('.item-info h2, h2, .title')?.textContent?.trim();
                if (title) element.setAttribute('aria-label', title);
            }
            // 卡片内的箭头按钮只是视觉修饰:移出焦点序列,避免重复焦点与嵌套交互元素
            element.querySelectorAll('.icon-action-btn').forEach(icon => {
                icon.tabIndex = -1;
                icon.setAttribute('aria-hidden', 'true');
            });
        });
    };
    makeCardEntriesAccessible();
    initSearchClearButtons();
    applyIconButtonLabels();

    // 卡片入口支持回车/空格激活(与原生 button 一致)
    document.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        const card = event.target?.closest?.('[data-target]');
        if (!card || card.tagName === 'BUTTON' || card.tagName === 'A') return;
        if (event.target !== card && event.target.closest('button, input, select, textarea, a')) return;
        event.preventDefault();
        card.click();
    });
    document.getElementById('quick_scan_btn')?.addEventListener('click', () => { if (!appState.scanning) { switchPage('scan_window'); triggerScan('smart'); }});
    document.getElementById('quick_update_btn')?.addEventListener('click', () => checkForUpdates());
    document.getElementById('stop_btn')?.addEventListener('click', async (e) => {
        const stopBtn = e.currentTarget;
        if (!window.pywebview || stopBtn.dataset.stopping === '1') return;
        stopBtn.dataset.stopping = '1';
        try {
            await window.pywebview.api.stop_scan();
        } finally {
            delete stopBtn.dataset.stopping;
        }
    });
    document.getElementById('theme_select')?.addEventListener('change', (e) => { applyTheme(e.target.value); window.pywebview?.api.update_config('theme', e.target.value); });
    document.getElementById('lang_select')?.addEventListener('change', (e) => { translateText(e.target.value); window.pywebview?.api.update_config('language', e.target.value); });

    const syncInteractiveTimeoutState = () => {
        document.querySelectorAll('[data-setting-parent]').forEach(row => {
            const parent = document.querySelector(`[data-config-key="${row.dataset.settingParent}"]`);
            // 递归可见性:父开关所在行自身被隐藏(如三级行依赖二级行)时同样隐藏
            const parentRow = parent?.closest('.list-item');
            const parentVisible = !parentRow || !parentRow.classList.contains('hidden');
            const visible = !appState.firstLaunch && !!parent?.checked && parentVisible;
            row.classList.toggle('hidden', !visible);
            row.querySelectorAll('input, button').forEach(control => {
                control.disabled = !visible || parent.disabled || control.dataset.pending === '1';
            });
        });
        const interactive = document.querySelector('[data-config-key="interactive_switch"]');
        const automatic = document.querySelector('[data-config-key="interactive_auto_block"]');
        const timeoutInput = document.getElementById('interactive_timeout_input');
        // AI 輔助決策與超時自動攔截互斥:AI 開啟時自動攔截置灰,懸浮提示避讓原因
        const aiAssist = document.querySelector('[data-config-key="ai_assist_switch"]');
        const aiAutoExec = document.querySelector('[data-config-key="ai_auto_execute"]');
        const aiActive = !!aiAssist?.checked;
        // AI 辅助决策开启即避让:交互模式的超时处理(自动拦截/超时输入)整体停用;
        // 超时执行 AI 建议由二级开关另行接管(见 get_interactive_timeout)
        const aiMutex = aiActive;
        const aiMutexHint = aiMutex ? getMsg('ai_decision_hint') : '';
        if (automatic) {
            automatic.disabled = appState.firstLaunch || !interactive?.checked || interactive.disabled || aiMutex || automatic.dataset.pending === '1';
            automatic.title = aiMutexHint;
            automatic.closest('.list-item')?.setAttribute('title', aiMutexHint);
        }
        if (aiAutoExec && aiAssist && !aiActive) {
            aiAutoExec.checked = false;
        }
        if (timeoutInput) {
            timeoutInput.disabled = appState.firstLaunch || !interactive?.checked || interactive.disabled || aiActive || !automatic?.checked || automatic.disabled;
            timeoutInput.closest('.list-item')?.classList.toggle('hidden', appState.firstLaunch || !interactive?.checked || !automatic?.checked);
        }
    };

    document.getElementById('ai_auto_timeout_input')?.addEventListener('change', (e) => {
        if (!window.pywebview) return;
        let value = parseInt(e.target.value, 10);
        if (!Number.isFinite(value)) value = 60;
        value = Math.min(Math.max(value, 5), 600);
        e.target.value = value;
        window.pywebview.api.update_config('ai_auto_execute_timeout', value);
    });

    // 延迟启动秒数:与后端 AI_DELAY_MIN/MAX 保持一致(1–30 秒)
    document.getElementById('ai_delay_seconds_input')?.addEventListener('change', (e) => {
        if (!window.pywebview) return;
        let value = parseInt(e.target.value, 10);
        if (!Number.isFinite(value)) value = 3;
        value = Math.min(Math.max(value, 1), 30);
        e.target.value = value;
        window.pywebview.api.update_config('ai_delay_seconds', value);
    });

    document.getElementById('interactive_timeout_input')?.addEventListener('change', (e) => {
        if (!window.pywebview) return;
        let value = parseInt(e.target.value, 10);
        if (!Number.isFinite(value)) value = 30;
        value = Math.min(Math.max(value, 5), 300);
        e.target.value = value;
        window.pywebview.api.update_config('interactive_timeout', value);
    });

    // AI+ 页:本地/云端分流程(切换只改界面,字段统一由保存按钮提交)
    const AI_PLACEHOLDERS = {
        local: { url: 'http://127.0.0.1:11434/v1', model: 'qwen2.5:7b' },
        cloud: { url: 'https://api.openai.com/v1', model: 'gpt-4o-mini' },
    };
    // —— AI+ 页:按需加载与交互(抑制规则 / P3 草案 / P4 智能体 / Ollama)——
    var loadAiPageData;
    const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
    const scopeLabel = key => getMsg(`suppress_scope_${key}`) || key;
    let aiPageLoaded = false;

    loadAiPageData = async () => {
        const api = window.pywebview?.api;
        if (!api || aiPageLoaded) return;
        aiPageLoaded = true;
        // 进页面即扫一次进程(原「扫描本机」按钮的职责),再渲染活动列表与已安装图标
        try { await api.scan_agent_processes?.(); } catch (error) { console.error('Agent scan failed', error); }
        await Promise.all([renderSuppressionRules(), renderDrafts(), renderAgentActivity(), renderAgentIcons()]);
    };

    const renderSuppressionRules = async () => {
        const list = document.getElementById('suppress_list');
        const empty = document.getElementById('suppress_empty');
        if (!list) return;
        try {
            const rules = await window.pywebview.api.get_suppression_rules();
            empty?.classList.toggle('hidden', rules.length > 0);
            list.replaceChildren(...rules.map(rule => {
                const row = document.createElement('div');
                row.className = 'list-item suppress-row';
                const expired = rule.expires > 0 && rule.expires * 1000 < Date.now();
                row.innerHTML = `<div class="item-info"><p class="suppress-title">${esc(scopeLabel(rule.scope))}`
                    + ` · <span class="mono">${esc(rule.sha256.slice(0, 16))}…</span>`
                    + `${rule.signer ? ` · <span class="mono">${esc(rule.signer.slice(0, 12))}…</span>` : ''}</p>`
                    + `<p class="ai-hint">${esc(rule.note || rule.reason)} · ${getMsg('suppress_hits')}: ${rule.hits}`
                    + ` · ${getMsg('suppress_expires')}: ${new Date(rule.expires * 1000).toLocaleDateString()}`
                    + `${rule.source === 'ai' ? ' · AI' : ''}${expired ? ' · ⚠' : ''}</p></div>`;
                const del = document.createElement('button');
                del.className = 'modern-btn';
                del.textContent = getMsg('suppress_delete');
                del.addEventListener('click', async () => {
                    if (await window.pywebview.api.delete_suppression_rule(rule.id)) renderSuppressionRules();
                });
                row.appendChild(del);
                return row;
            }));
        } catch (error) { console.error('Suppression rules load failed', error); }
    };

    const renderDrafts = async () => {
        const list = document.getElementById('drafts_list');
        const empty = document.getElementById('drafts_empty');
        if (!list) return;
        try {
            const drafts = await window.pywebview.api.get_ai_rule_drafts();
            empty?.classList.toggle('hidden', drafts.length > 0);
            list.replaceChildren(...drafts.map(draft => {
                const row = document.createElement('div');
                row.className = 'list-item suppress-row';
                row.innerHTML = `<div class="item-info"><p class="mono">${esc(draft.sha256.slice(0, 24))}…</p>`
                    + `<p class="ai-hint">${esc(draft.note || draft.reason)} · AI</p></div>`;
                const ok = document.createElement('button');
                ok.className = 'modern-btn primary-btn';
                ok.textContent = getMsg('draft_approve');
                ok.addEventListener('click', async () => {
                    if (await window.pywebview.api.resolve_ai_rule_draft(draft.id, true)) {
                        aiPageLoaded = false; await loadAiPageData();
                    }
                });
                const no = document.createElement('button');
                no.className = 'modern-btn';
                no.textContent = getMsg('draft_reject');
                no.addEventListener('click', async () => {
                    if (await window.pywebview.api.resolve_ai_rule_draft(draft.id, false)) renderDrafts();
                });
                row.append(ok, no);
                return row;
            }));
        } catch (error) { console.error('Drafts load failed', error); }
    };

    // 智能体图标带:只显示本机已安装的(后端 L1 运行中 + L2 快捷方式/npm/安装路径)
    // 明细卡片默认收起,点图标带展开/收起;展开期间随刷新周期活更新
    const agentDetails = { open: false };

    const renderAgentIcons = async () => {
        const box = document.getElementById('ai_agent_icons');
        const empty = document.getElementById('ai_agent_none');
        if (!box) return;
        let installed = [];
        try {
            installed = (await window.pywebview?.api.list_installed_agents?.()) || [];
        } catch (error) { console.error('Installed agents load failed', error); }
        if (empty) empty.hidden = installed.length > 0;
        box.replaceChildren(...installed.map(agent => {
            const chip = document.createElement('span');
            chip.className = 'ai-chip';
            chip.title = agent.name;
            if (agent.logo) {
                const img = document.createElement('img');
                img.className = 'ai-chip-logo';
                img.src = `/static/img/logos/${agent.logo}`;
                img.alt = agent.name;
                img.dataset.letter = agent.letter || '?';
                img.dataset.color = agent.color || '#888';
                chip.appendChild(img);
            } else {
                // 没有方形图标(如 Aider 只有横版文字标):直接渲染字母徽标
                chip.innerHTML = agentBadge(agent.letter, agent.color);
            }
            return chip;
        }));
        bindChipLogoFallbacks();
    };

    const renderAgentActivity = async () => {
        const box = document.getElementById('ai_agent_results');
        const wrap = document.getElementById('ai_agent_results_item');
        if (!box) return;
        try {
            const activity = await window.pywebview.api.get_agent_activity();
            wrap?.classList.toggle('hidden', !agentDetails.open || activity.length === 0);
            box.replaceChildren(...activity.flatMap(item => {
                const p = document.createElement('p');
                p.className = 'ai-hint';
                // admin×N=提权进程数;✓=签名已验证;evt×N=相关拦截事件数。
                // 行缀是数据非 i18n 键,与「 pid」同风格
                p.textContent = `${item.name} · ${item.exe} · ${item.count} pid`
                    + (item.elevated ? ` · admin×${item.elevated}` : '')
                    + (item.verified ? ' · ✓' : '')
                    + (item.events ? ` · evt×${item.events}` : '');
                // 行为审计:本轮连接快照(端点行缩进排在产品行下)
                const net = (item.connections || []).map(c => {
                    const e = document.createElement('p');
                    e.className = 'ai-hint agent-net';
                    e.textContent = `↳ ${c.endpoint}`;
                    return e;
                });
                return [p, ...net];
            }));
        } catch (error) { console.error('Agent activity load failed', error); }
    };

    document.getElementById('ai_agent_icons')?.addEventListener('click', () => {
        agentDetails.open = !agentDetails.open;
        if (agentDetails.open) renderAgentActivity();
        else document.getElementById('ai_agent_results_item')?.classList.add('hidden');
    });

    document.getElementById('suppress_refresh')?.addEventListener('click', renderSuppressionRules);
    document.getElementById('drafts_generate')?.addEventListener('click', async () => {
        const api = window.pywebview?.api;
        if (!api) return;
        try {
            const res = await api.generate_ai_rule_drafts();
            if (res?.ok) { await renderDrafts(); }
            else window.pywebview.api.show_alert(getMsg('title_error'),
                res?.error === 'no_data' ? getMsg('draft_no_data') : getMsg('draft_failed'), 'warning');
        } catch (error) { console.error('Draft generation failed', error); }
    });
    // 模型名稱下拉组合框:首次聚焦时自动扫描,扫描结果缓存,点击输入框弹下拉选择
    const modelCombo = {
        models: null,   // null = 未扫描,[] = 扫描过但没找到
        scanning: false,
    };

    const renderModelMenu = (models) => {
        const menu = document.getElementById('ai_model_menu');
        const input = document.getElementById('ai_model_input');
        if (!menu || !input) return;
        menu.replaceChildren(...models.map(name => {
            const li = document.createElement('li');
            li.className = 'model-combo-option' + (name === input.value ? ' selected' : '');
            li.setAttribute('role', 'option');
            li.textContent = name;
            li.addEventListener('click', () => {
                // _selecting 阻止下方 focus() 重新触发 openModelMenu 导致下拉再次弹出
                modelCombo._selecting = true;
                input.value = name;   // 覆盖而非追加
                input.dispatchEvent(new Event('change'));
                closeModelMenu();
                modelCombo._selecting = false;
            });
            return li;
        }));
    };

    // 菜单相对输入框向上还是向下展开:排序方向与定位共用这一套判据
    const menuOpensUp = (input) => {
        const rect = input.getBoundingClientRect();
        const spaceBelow = window.innerHeight - rect.bottom - 8;
        const spaceAbove = rect.top - 8;
        return spaceBelow < 200 && spaceAbove > spaceBelow;
    };

    // 向下展开:倒序(新版本在上,离输入框最近);向上展开:正序(新版本在下,同样离输入框最近)
    const renderOrderedMenu = (matched, input) => {
        renderModelMenu(menuOpensUp(input) ? matched : [...matched].reverse());
    };

    const showModelMenu = (menu, input) => {
        // position: fixed 不受父级 overflow 裁剪;打开时按视口剩余空间决定向上/向下,
        // 并把 left/top/maxHeight 全部夹进视口,避免任何方向被裁切
        menu.classList.add('open');
        menu.hidden = false;
        const rect = input.getBoundingClientRect();
        const menuWidth = Math.min(Math.max(rect.width, 160), 320);
        const openUp = menuOpensUp(input);
        const spaceBelow = window.innerHeight - rect.bottom - 8;
        const spaceAbove = rect.top - 8;
        const avail = Math.max(120, openUp ? spaceAbove : spaceBelow);
        const height = Math.min(240, avail);
        let left = rect.right - menuWidth;
        left = Math.max(8, Math.min(left, window.innerWidth - menuWidth - 8));
        menu.style.width = menuWidth + 'px';
        menu.style.maxHeight = height + 'px';
        menu.style.left = left + 'px';
        if (openUp) {
            menu.style.top = 'auto';
            menu.style.bottom = (window.innerHeight - rect.top + 4) + 'px';
        } else {
            menu.style.bottom = 'auto';
            menu.style.top = (rect.bottom + 4) + 'px';
        }
        const inputEl = input || document.getElementById('ai_model_input');
        if (inputEl) inputEl.setAttribute('aria-expanded', 'true');
    };

    // fixed 定位在打开期间不跟随滚动:页面滚动/窗口改变时关闭,避免坐标漂移悬空;
    // 但菜单自身滚动(滚轮/拖滚动条)不能关——滚动源在菜单内时忽略
    const menuViewportHandler = (event) => {
        const menu = document.getElementById('ai_model_menu');
        if (!menu || !menu.classList.contains('open')) return;
        if (event.target instanceof Node && menu.contains(event.target)) return;
        closeModelMenu();
    };
    window.addEventListener('scroll', menuViewportHandler, { capture: true, passive: true });
    window.addEventListener('resize', menuViewportHandler, { passive: true });

    const closeModelMenu = () => {
        const menu = document.getElementById('ai_model_menu');
        const input = document.getElementById('ai_model_input');
        if (!menu) return;
        menu.classList.remove('open');
        menu.hidden = true;
        if (input) input.setAttribute('aria-expanded', 'false');
    };

    // 候选框搬到 body 下:fixed 定位只要祖先带 transform/filter,包含块就会从视口
    // 变成那个祖先,视口坐标按错坐标系解释、菜单飞到页面别处;body 无 transform 最稳
    const modelMenuHost = document.getElementById('ai_model_menu');
    if (modelMenuHost && modelMenuHost.parentElement !== document.body) {
        document.body.appendChild(modelMenuHost);
    }

    const scanModels = async () => {
        const api = window.pywebview?.api;
        if (!api || modelCombo.scanning) return;
        modelCombo.scanning = true;
        const hint = document.getElementById('ai_models_hint');
        if (hint) hint.textContent = '…';
        try {
            const res = await api.scan_local_ai_models();
            // 升序存储为规范序;展示方向由菜单相对输入框的位置决定(renderOrderedMenu)
            modelCombo.models = res?.ok && res.models?.length ? [...res.models].sort() : [];
            if (hint) {
                if (modelCombo.models.length) {
                    // 提示行固定倒序,新版本排最前
                    hint.textContent = [...modelCombo.models].reverse().join(', ');
                } else {
                    hint.textContent = getMsg('ollama_none');
                }
            }
        } catch (error) {
            console.error('Model scan failed', error);
            modelCombo.models = [];
            if (hint) hint.textContent = getMsg('ollama_none');
        } finally {
            modelCombo.scanning = false;
        }
    };

    const openModelMenu = async () => {
        const menu = document.getElementById('ai_model_menu');
        const input = document.getElementById('ai_model_input');
        if (!menu || !input) return;
        if (!modelCombo.models) {
            await scanModels();
        }
        if (!modelCombo.models?.length) return;
        renderOrderedMenu(filterModels(input.value), input);
        showModelMenu(menu, input);
    };

    // 输入内容 → 下拉列表同步筛选(子串匹配,大小写不敏感)
    const filterModels = (query) => {
        if (!modelCombo.models) return [];
        const q = String(query || '').trim().toLowerCase();
        if (!q) return modelCombo.models;
        return modelCombo.models.filter(m => m.toLowerCase().includes(q));
    };

    const input = document.getElementById('ai_model_input');
    const clear = document.getElementById('ai_model_clear');
    if (input) {
        input.addEventListener('focus', () => { if (!modelCombo._selecting) openModelMenu(); });
        input.addEventListener('click', () => { if (!modelCombo._selecting) openModelMenu(); });
        // 输入时同步筛选:无匹配则收起,避免空盒子悬着
        input.addEventListener('input', () => {
            if (!modelCombo.models) return;
            const matched = filterModels(input.value);
            const menu = document.getElementById('ai_model_menu');
            if (!menu) return;
            if (!matched.length) { closeModelMenu(); return; }
            renderOrderedMenu(matched, input);
            if (!menu.classList.contains('open')) showModelMenu(menu, input);
        });
    }
    if (clear) {
        const syncClear = () => { clear.hidden = !(input && input.value.length > 0); };
        input?.addEventListener('input', syncClear);
        input?.addEventListener('change', syncClear);
        clear.addEventListener('click', () => {
            if (!input) return;
            input.value = '';
            input.dispatchEvent(new Event('change'));
            input.focus();
            syncClear();
        });
    }
    // 点击菜单外或按 Esc 关闭下拉(菜单本体已挂 body,要一并豁免)
    document.addEventListener('click', (e) => {
        const combo = e.target.closest('.model-combo, .model-combo-menu');
        if (!combo) closeModelMenu();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModelMenu();
    });


    const applyAiModeUI = (mode) => {
        const isLocal = mode !== 'cloud';
        const keyRow = document.getElementById('ai_api_key_row');
        if (keyRow) keyRow.classList.toggle('hidden', isLocal);
        const urlInput = document.getElementById('ai_base_url_input');
        const modelInput = document.getElementById('ai_model_input');
        if (urlInput) urlInput.placeholder = (AI_PLACEHOLDERS[isLocal ? 'local' : 'cloud']).url;
        if (modelInput) modelInput.placeholder = (AI_PLACEHOLDERS[isLocal ? 'local' : 'cloud']).model;
        const hint = document.getElementById('ai_save_status');
        if (hint) hint.textContent = '';
    };
    window.applyAiModeUI = applyAiModeUI;

    document.getElementById('ai_mode_select')?.addEventListener('change', (e) => {
        applyAiModeUI(e.target.value);
    });

    // 实时保存:字段失焦即提交(与全应用一致);URL 格式校验失败不落盘并提示
    const commitAiConfig = async (validateUrl = false) => {
        const status = document.getElementById('ai_test_status');
        try {
            const mode = document.getElementById('ai_mode_select')?.value || 'local';
            const baseUrl = document.getElementById('ai_base_url_input')?.value.trim() || '';
            const model = document.getElementById('ai_model_input')?.value.trim() || '';
            const apiKey = mode === 'cloud'
                ? (document.getElementById('ai_api_key_input')?.value.trim() || '')
                : null;

            if (validateUrl && baseUrl && !/^https?:\/\//i.test(baseUrl)) {
                if (status) {
                    status.textContent = getMsg('msg_ai_invalid_url');
                    status.style.color = '#ff3b30';
                }
                return;
            }

            if (status) status.style.color = '';
            const res = await window.pywebview.api.save_ai_config(baseUrl, model, mode, apiKey);
            if (res && !res.ok && status) {
                status.textContent = `${getMsg('msg_ai_save_fail')} (${res.error || '?'})`;
                status.style.color = '#ff3b30';
            }
            // 模型/地址已变:累计计数按新模型分账重新展示
            refreshAiTokenUsage();
        } catch (error) {
            console.error('AI config commit failed', error);
        }
    };

    document.getElementById('ai_mode_select')?.addEventListener('change', (e) => {
        applyAiModeUI(e.target.value);
        commitAiConfig();
    });
    document.getElementById('ai_base_url_input')?.addEventListener('change', () => commitAiConfig(true));
    document.getElementById('ai_model_input')?.addEventListener('change', () => commitAiConfig());
    document.getElementById('ai_api_key_input')?.addEventListener('change', () => commitAiConfig());
    document.getElementById('ai_test_button')?.addEventListener('click', async () => {
        const status = document.getElementById('ai_test_status');
        const button = document.getElementById('ai_test_button');
        if (!window.pywebview || !button) return;
        button.disabled = true;
        if (status) status.textContent = '…';
        try {
            const res = await window.pywebview.api.test_ai_connection();
            if (status) status.textContent = res?.ok ? getMsg('ai_test_ok')
                : `${getMsg('ai_test_fail')} (${res?.error || 'unknown'})`;
        } catch (error) {
            if (status) status.textContent = `${getMsg('ai_test_fail')} (${error})`;
        } finally {
            button.disabled = false;
        }
        // 连接测试同样计费:刷新累计展示
        refreshAiTokenUsage();
    });

    // ---- 模型接入引导:开启 AI 辅助决策后模型尚未就绪时,把注意力聚到「模型接入」 ----
    const AI_GUIDE_ID = 'ai_model_guide';
    let aiGuideReposition = null;

    const isAiModelConfigured = () => {
        const mode = document.getElementById('ai_mode_select')?.value || 'local';
        const url = (document.getElementById('ai_base_url_input')?.value || '').trim();
        const model = (document.getElementById('ai_model_input')?.value || '').trim();
        const apiKey = (document.getElementById('ai_api_key_input')?.value || '').trim();
        if (!url || !model) return false;
        return mode !== 'cloud' || Boolean(apiKey);
    };

    const closeAiModelGuide = () => {
        document.getElementById(AI_GUIDE_ID)?.remove();
        if (aiGuideReposition) {
            window.removeEventListener('resize', aiGuideReposition);
            document.removeEventListener('scroll', aiGuideReposition, true);
            aiGuideReposition = null;
        }
    };

    // 整窗只留「模型接入」一块透明:四块 dim 围出洞口,目标区块不被任何遮罩覆盖
    const openAiModelGuide = () => {
        const target = document.getElementById('ai_model_group');
        if (!target) return;
        closeAiModelGuide();

        const layer = document.createElement('div');
        layer.id = AI_GUIDE_ID;
        layer.className = 'ai-guide-layer';
        layer.setAttribute('role', 'dialog');
        layer.setAttribute('aria-modal', 'true');
        layer.setAttribute('aria-labelledby', 'ai_guide_title');
        layer.innerHTML = [
            '<div class="ai-guide-dim" data-part="top"></div>',
            '<div class="ai-guide-dim" data-part="bottom"></div>',
            '<div class="ai-guide-dim" data-part="left"></div>',
            '<div class="ai-guide-dim" data-part="right"></div>',
            '<div class="ai-guide-ring"></div>',
            '<div class="ai-guide-tip"><h3 id="ai_guide_title"></h3><p id="ai_guide_desc"></p></div>',
            `<button type="button" class="ai-guide-close" aria-label="${getMsg('btn_close')}">`,
            '<svg aria-hidden="true" focusable="false"><use href="#i-close"/></svg>',
            '</button>',
        ].join('');
        document.body.appendChild(layer);
        layer.querySelector('#ai_guide_title').textContent = getMsg('ai_guide_title');
        layer.querySelector('#ai_guide_desc').textContent = getMsg('ai_guide_desc');
        layer.querySelector('.ai-guide-close').addEventListener('click', closeAiModelGuide);

        const PAD = 8;
        const dims = ['top', 'bottom', 'left', 'right'].reduce((acc, part) => {
            acc[part] = layer.querySelector(`[data-part="${part}"]`);
            return acc;
        }, {});
        const ring = layer.querySelector('.ai-guide-ring');
        const tip = layer.querySelector('.ai-guide-tip');

        aiGuideReposition = () => {
            const rect = target.getBoundingClientRect();
            const vw = window.innerWidth;
            const vh = window.innerHeight;
            const x1 = Math.max(0, rect.left - PAD);
            const y1 = Math.max(0, rect.top - PAD);
            const x2 = Math.min(vw, rect.right + PAD);
            const y2 = Math.min(vh, rect.bottom + PAD);
            const place = (el, left, top, width, height) => {
                el.style.left = `${left}px`;
                el.style.top = `${top}px`;
                el.style.width = `${Math.max(0, width)}px`;
                el.style.height = `${Math.max(0, height)}px`;
            };
            place(dims.top, 0, 0, vw, y1);
            place(dims.bottom, 0, y2, vw, vh - y2);
            place(dims.left, 0, y1, x1, y2 - y1);
            place(dims.right, x2, y1, vw - x2, y2 - y1);
            place(ring, x1, y1, x2 - x1, y2 - y1);

            // 引导文字贴在洞口上方;上方空间不够就落到下方,始终不出窗口
            const tipWidth = Math.min(380, vw - 40);
            const tipLeft = Math.min(Math.max(16, x1), Math.max(16, vw - tipWidth - 16));
            const above = y1 > 170;
            tip.style.width = `${tipWidth}px`;
            tip.style.left = `${tipLeft}px`;
            tip.style.top = `${above ? y1 - 12 : y2 + 12}px`;
            tip.style.transform = above ? 'translateY(-100%)' : 'none';
        };
        aiGuideReposition();
        window.addEventListener('resize', aiGuideReposition);
        document.addEventListener('scroll', aiGuideReposition, true);

        // 焦点真正落到模型接入:滚动到可见 + 定位到首处待填字段
        target.scrollIntoView({ block: 'center', behavior: 'smooth' });
        const firstEmpty = ['ai_base_url_input', 'ai_model_input', 'ai_api_key_input']
            .map((id) => document.getElementById(id))
            .find((el) => el && !el.value.trim() && !el.closest('.hidden'));
        (firstEmpty || document.getElementById('ai_mode_select'))?.focus({ preventScroll: true });
        setTimeout(aiGuideReposition, 340); // 等平滑滚动结束再重算洞口
    };
    window.openAiModelGuide = openAiModelGuide;
    window.closeAiModelGuide = closeAiModelGuide;

    // ---- token 累计消耗:按模型分账,切换模型各计各的 ----
    const renderAiTokenUsage = (data) => {
        const summary = document.getElementById('ai_token_summary');
        if (!summary) return;
        const model = String(data?.model || '').trim();
        const usage = (data && data.usage) || {};
        const entry = model ? usage[model] : null;
        const hasEntry = !!entry && (Number(entry.tokens) > 0 || Number(entry.requests) > 0);

        if (!model) summary.textContent = getMsg('ai_token_no_model');
        else if (!hasEntry) summary.textContent = getMsg('ai_token_empty');
        else {
            let text = formatMsg('ai_token_summary',
                Number(entry.tokens || 0).toLocaleString(), Number(entry.requests || 0));
            // 用过多个模型时附一行总计,便于估算整体开销
            if (Object.keys(usage).length > 1 && Number(data.total?.tokens) > 0) {
                text += ' · ' + formatMsg('ai_token_total', Number(data.total.tokens).toLocaleString());
            }
            summary.textContent = text;
        }

        summary.dataset.model = model;
        summary.title = Object.keys(usage).length
            ? Object.entries(usage).map(([name, item]) =>
                `${name}: ${Number(item.tokens || 0).toLocaleString()} tokens / ${item.requests || 0}`).join('\n')
            : '';
        const resetBtn = document.getElementById('ai_token_reset');
        if (resetBtn) resetBtn.disabled = !hasEntry;
    };

    const refreshAiTokenUsage = async () => {
        if (!window.pywebview?.api?.get_ai_token_usage) return;
        try {
            renderAiTokenUsage(await window.pywebview.api.get_ai_token_usage());
        } catch (error) { console.error('AI token usage refresh failed', error); }
    };
    window.refreshAiTokenUsage = refreshAiTokenUsage;

    document.getElementById('ai_token_reset')?.addEventListener('click', async () => {
        if (!window.pywebview?.api?.reset_ai_token_usage) return;
        const model = (document.getElementById('ai_token_summary')?.dataset.model || '').trim();
        const scope = model || getMsg('ai_token_no_model');
        const ok = await window.pywebview.api.show_confirm(getMsg('title_prompt'),
            formatMsg('ai_token_reset_confirm', scope));
        if (!ok) return;
        try {
            const result = await window.pywebview.api.reset_ai_token_usage(model);
            if (result && result.ok === false) return;
            renderAiTokenUsage(result);
            window.pywebview.api.show_alert(getMsg('title_prompt'), getMsg('ai_token_reset_done'), 'info');
        } catch (error) { console.error('AI token reset failed', error); }
    });

    // AI 页可见时每 5s 轻量轮询:拦截弹窗在后台分析也会产生消耗
    let aiTokenTimer = null;
    const scheduleAiTokenRefresh = () => {
        clearTimeout(aiTokenTimer);
        aiTokenTimer = setTimeout(async () => {
            if (document.getElementById('ai_window')?.classList.contains('active') && !document.hidden) {
                await refreshAiTokenUsage();
            }
            scheduleAiTokenRefresh();
        }, 5000);
    };
    scheduleAiTokenRefresh();
    
    document.getElementById('scan_method_select')?.addEventListener('change', (e) => {
        const val = e.target.value;
        if (val === 'none' || appState.scanning) return;
        if (['smart', 'file', 'path', 'full'].includes(val)) triggerScan(val);
        else if (['delete', 'ignore', 'quarantine', 'whitelist'].includes(val)) handleVirusActions(val);
    });

    const applyToggle = async (key, checked, toggle) => {
        let failed = false;
        toggle.dataset.pending = '1';
        toggle.disabled = true;
        syncInteractiveTimeoutState();
        try {
            const result = await window.pywebview.api.update_config(key, checked);
            if (result !== undefined && result !== null) toggle.checked = result;
            failed = toggle.checked !== checked;
            if (appState.configCache) {
                appState.configCache[key] = toggle.checked;
                updateProtectionLights(appState.configCache);
            }
        } catch { toggle.checked = !checked; failed = true; }
        finally {
            delete toggle.dataset.pending;
            toggle.disabled = false;
            syncInteractiveTimeoutState();
        }
        if (key === 'context_switch' || key === 'classic_menu_switch') await window.refreshContextMenuStatus();
        if (key === 'context_switch' && failed) {
            try { await window.pywebview.api.show_alert(getMsg('title_error'), getMsg('msg_context_menu_failed'), 'error'); } catch {}
        }
        if (key === 'driver_switch' && failed) {
            try { await window.pywebview.api.show_alert(getMsg('title_error'), getMsg('msg_driver_switch_failed'), 'error'); } catch {}
        }
    };

    document.querySelectorAll('.toggle-switch input').forEach((toggle, index) => {
        toggle.addEventListener('change', async (e) => {

            const key = toggle.dataset.configKey;
            if (!window.pywebview || !key) return;

            if (key === 'ai_assist_switch') {
                if (!e.target.checked) { applyToggle(key, false, toggle); return; }
                window.pywebview.api.show_confirm(getMsg("title_prompt"), getMsg("msg_ai_assist_risk")).then(ok => {
                    if (!ok) { toggle.checked = false; return; }
                    applyToggle(key, true, toggle);
                    // 已确认开启,但模型还没接上:把注意力导到「模型接入」,否则开了也分析不了
                    if (!isAiModelConfigured()) openAiModelGuide();
                });
                return;
            }

            if (key === 'classic_menu_switch') {
                if (!e.target.checked) { applyToggle(key, false, toggle); return; }
                window.pywebview.api.show_confirm(getMsg("title_prompt"), getMsg("msg_classic_menu_confirm")).then(ok => {
                    if (ok) applyToggle(key, true, toggle);
                    else toggle.checked = false;
                });
                return;
            }

            await applyToggle(key, e.target.checked, toggle);
        });
    });

    document.getElementById('taskmgr_select')?.addEventListener('change', (e) => {
        const val = e.target.value;
        const checkedCbs = document.querySelectorAll('#taskmgr_window .manage-list-item input[type="checkbox"]:checked');
        if (checkedCbs.length === 0 || !window.pywebview) return updateCustomSelectUI('taskmgr_select', 'none');

        if (val === 'view') {
            checkedCbs.forEach(cb => {
                if (cb.dataset.path && cb.dataset.path !== "path_unknown") window.pywebview.api.open_file_location(cb.dataset.path);
            });
        } else if (val === 'end') {
            window.pywebview.api.show_confirm(getMsg("msg_end_proc_title"), getMsg("msg_end_proc_confirm")).then(res => {
                if (res) Promise.all(Array.from(checkedCbs).map(cb => window.pywebview.api.kill_process(parseInt(cb.value)))).then(() => fetchProcs());
            });
        } else if (val === 'quarantine' || val === 'whitelist') {
            const paths = Array.from(checkedCbs).map(cb => cb.dataset.path).filter(p => p && p !== "path_unknown");
            if (paths.length > 0) {
                const listKey = val === 'quarantine' ? 'quarantine' : 'white_list';
                window.pywebview.api.manage_named_list(listKey, paths, 'add').then(() => {
                    Promise.all(Array.from(checkedCbs).map(cb => window.pywebview.api.kill_process(parseInt(cb.value)))).then(() => fetchProcs());
                });
            }
        }
        updateCustomSelectUI('taskmgr_select', 'none');
    });
    
    document.getElementById('netmon_select')?.addEventListener('change', (e) => {
        const val = e.target.value;
        const checkedCbs = document.querySelectorAll('#netmon_window .manage-list-item input[type="checkbox"]:checked');
        if (checkedCbs.length === 0 || !window.pywebview) return updateCustomSelectUI('netmon_select', 'none');

        if (val === 'view') {
            checkedCbs.forEach(cb => {
                if (cb.dataset.path && cb.dataset.path !== "path_unknown") window.pywebview.api.open_file_location(cb.dataset.path);
            });
        } else if (val === 'end') {
            window.pywebview.api.show_confirm(getMsg("msg_end_proc_title"), getMsg("msg_end_proc_confirm")).then(res => {
                if (res) Promise.all(Array.from(checkedCbs).map(cb => window.pywebview.api.kill_process(parseInt(cb.value)))).then(() => fetchNetmon());
            });
        }
        updateCustomSelectUI('netmon_select', 'none');
    });

    document.getElementById('startup_select')?.addEventListener('change', (e) => {
        const val = e.target.value;
        const checked = getCheckedValues('#startup_window');
        if (checked.length > 0 && window.pywebview) {
            if (val === 'enable' || val === 'disable') {
                const widget = document.querySelector('#startup_window .manage-widget');
                if (widget && widget.gridState && widget.gridState.lastDisplayData) {
                    widget.gridState.lastDisplayData.forEach(item => {
                        if (checked.includes(item.id)) item.status = val === 'enable' ? 'status_enabled' : 'status_disabled';
                    });
                    widget.renderData();
                }
            }
            window.pywebview.api.manage_startup(checked, val).then(fetchStartup);
        }
        updateCustomSelectUI('startup_select', 'none');
    });

    document.getElementById('junk_select')?.addEventListener('change', (e) => {
        const val = e.target.value;
        const checked = getCheckedValues('#junk_window');
        if (!window.pywebview) return;
        
        if (val === 'view') {
            checked.forEach(path => window.pywebview.api.open_file_location(path));
        } else if (val === 'delete') {
            if (checked.length > 0) {
                window.pywebview.api.clean_system_junk(checked).then(size => {
                    window.pywebview.api.show_alert(getMsg("title_prompt"), `${getMsg("msg_cleaned")}${formatSize(size)}`, "info");
                    appState.junkList = appState.junkList.filter(item => !checked.includes(item.path));
                    renderDataGrid('#junk_window', appState.junkList, cols.junk, 'path', true);
                });
            }
        }
        updateCustomSelectUI('junk_select', 'none');
    });

    document.getElementById('repair_select')?.addEventListener('change', (e) => {
        const val = e.target.value;
        if (val === 'repair') {
            const checked = getCheckedValues('#repair_window');
            if (checked.length > 0 && window.pywebview) {
                window.pywebview.api.execute_system_repair(checked).then(() => {
                    window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_repaired"), "info");
                    renderDataGrid('#repair_window', [], cols.repair, 'id', true);
                });
            }
        }
        updateCustomSelectUI('repair_select', 'none');
    });

    ['whitelist_window', 'quarantine_window', 'popup_window', 'custom_protect_window'].forEach(id => {
        const listKeyMap = {
            'popup_window': 'block_list',
            'custom_protect_window': 'custom_rule',
            'whitelist_window': 'white_list',
            'quarantine_window': 'quarantine'
        };
        const listKey = listKeyMap[id];
        const selectId = id.replace('_window', '_select');

        document.getElementById(selectId)?.addEventListener('change', (e) => {
            const val = e.target.value;
            if (!window.pywebview) return;

            if (val === 'add') {
                if (id === 'popup_window') {
                    const select = document.getElementById(selectId);
                    if (select.dataset.capturing === 'true') return;
                    select.dataset.capturing = 'true';
                    const triggerText = select.nextElementSibling?.querySelector('.custom-select-text');
                    const originalI18n = triggerText?.getAttribute('data-i18n');
                    const originalText = triggerText?.textContent;
                    if (triggerText) {
                        triggerText.setAttribute('data-i18n', 'msg_click_target');
                        triggerText.textContent = getMsg('msg_click_target');
                    }
                    let failureMessage = 'popup_capture_failed';
                    Promise.resolve().then(() => window.pywebview.api.capture_popup_window()).then(async rule => {
                        if (rule?.error) throw new Error(rule.error);
                        if (!rule) return;
                        failureMessage = 'popup_add_failed';
                        const ok = await window.pywebview.api.add_popup_rule(rule);
                        if (!ok) throw new Error('Popup rule was not saved');
                        await refreshConfigLists();
                    }).catch(error => {
                        console.error('Popup capture/add failed', error);
                        return window.pywebview.api.show_alert(getMsg('title_prompt'), getMsg(failureMessage), 'warning');
                    }).catch(error => console.error('Popup error notification failed', error)).finally(() => {
                        select.dataset.capturing = 'false';
                        if (triggerText) {
                            triggerText.setAttribute('data-i18n', originalI18n || 'btn_select');
                            triggerText.textContent = originalText;
                        }
                        updateCustomSelectUI(selectId, 'none');
                    });
                    return;
                } else {
                    const fTypes = id === 'custom_protect_window' ? ['JSON Files (*.json)'] : null;
                    const currentListKey = id === 'custom_protect_window' ? 'custom_rule' : listKey;
                    window.pywebview.api.select_files(fTypes).then(files => {
                        if (files?.length > 0) window.pywebview.api.manage_named_list(currentListKey, files, 'add').then(refreshConfigLists);
                    });
                }
            } else if (val === 'add_file') {
                const fTypes = id === 'custom_protect_window' ? ['JSON Files (*.json)'] : null;
                const currentListKey = id === 'custom_protect_window' ? 'custom_rule' : listKey;
                window.pywebview.api.select_files(fTypes).then(files => {
                    if (files?.length > 0) window.pywebview.api.manage_named_list(currentListKey, files, 'add').then(refreshConfigLists);
                });
            } else if (val === 'add_path') {
                window.pywebview.api.select_folder().then(folder => {
                    if (folder?.length > 0) window.pywebview.api.manage_named_list(listKey, folder, 'add').then(refreshConfigLists);
                });
            } else if (val === 'extract') {
                const checked = getCheckedValues(`#${id}`);
                if (checked.length > 0) {
                    window.pywebview.api.select_folder().then(folder => {
                        if (folder?.length > 0) {
                            window.pywebview.api.extract_list_items(checked, folder[0]).then(success => {
                                if (success) window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_extract_success"), "info");
                            });
                        }
                    });
                }
            } else if (val === 'remove') {
                const checked = getCheckedValues(`#${id}`);
                if (checked.length > 0) {
                    const remove = id === 'popup_window' ? window.pywebview.api.remove_popup_rules(checked) : window.pywebview.api.remove_list_items(listKey, checked);
                    remove.then(refreshConfigLists);
                }
            } else if (val === 'quarantine' || val === 'whitelist') {
                const checked = getCheckedValues(`#${id}`);
                if (checked.length > 0) {
                    const targetKey = val === 'quarantine' ? 'quarantine' : 'white_list';
                    window.pywebview.api.manage_named_list(targetKey, checked, 'add').then(() => refreshConfigLists());
                }
            }
            updateCustomSelectUI(selectId, 'none');
        });
    });

    document.getElementById('release_select')?.addEventListener('change', (e) => {
        const val = e.target.value;
        if (!window.pywebview) return updateCustomSelectUI('release_select', 'none');

        const refresh = () => window.pywebview.api.list_release_records().then(data => {
            renderDataGrid('#release_window', buildReleaseRows(data), cols.release, 'value', false);
        });

        if (val === 'remove') {
            const checked = getCheckedValues('#release_window');
            if (checked.length === 0) return updateCustomSelectUI('release_select', 'none');
            // 行 value 用单字母前缀(p:/s:)保持紧凑;后端 API 契约是 permanent/suppress
            const kindOf = { p: 'permanent', s: 'suppress' };
            Promise.all(checked.map(v => {
                const sep = v.indexOf(':');
                return window.pywebview.api.delete_release_record(kindOf[v.slice(0, sep)], v.slice(sep + 1));
            })).then(refresh).then(() => updateCustomSelectUI('release_select', 'none'));
        } else if (val === 'clear') {
            window.pywebview.api.show_confirm(getMsg('title_prompt'), getMsg('msg_clear_release_confirm')).then(ok => {
                if (ok) window.pywebview.api.clear_release_records().then(refresh);
            }).finally(() => updateCustomSelectUI('release_select', 'none'));
        } else {
            updateCustomSelectUI('release_select', 'none');
        }
    });

    document.getElementById('log_export_select')?.addEventListener('change', (e) => {
        const val = e.target.value;
        const checked = getCheckedValues('#log_export_window');
        if (val === 'export') {
            if (checked.length === 0) {
                window.pywebview?.api.show_alert(getMsg("title_prompt"), getMsg("msg_sel_log_export"), "warning");
            } else {
                window.pywebview?.api.export_logs(checked).then(res => res && window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_export_success"), "info"));
            }
        } else if (val === 'delete') {
            if (checked.length > 0 && window.pywebview) {
                window.pywebview.api.show_confirm(getMsg("title_prompt"), getMsg("msg_del_log_confirm")).then(res => {
                    if (res) window.pywebview.api.clear_logs(checked).then(() => {
                        window.pywebview.api.get_logs().then(logs => renderDataGrid('#log_export_window', logs.reverse().map(log => ({ time_str: `[${log.time_str}]`, level: log.level, action: log.action, source: log.source || '-', id: log.id })), cols.log, 'id', true));
                        window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_log_deleted"), "info");
                    });
                });
            }
        }
        updateCustomSelectUI('log_export_select', 'none');
    });

    document.getElementById('minimize_button')?.addEventListener('click', () => window.pywebview?.api.minimize());

    const syncMaximizeIcon = (maximized) => {
        document.getElementById('icon_maximize')?.classList.toggle('hidden', !!maximized);
        document.getElementById('icon_restore')?.classList.toggle('hidden', !maximized);
        refreshIconButtonLabels();
    };
    window.syncMaximizeIcon = syncMaximizeIcon;

    document.getElementById('maximize_button')?.addEventListener('click', () => {
        window.pywebview?.api.toggle_maximize().then(state => syncMaximizeIcon(!!state)).catch(() => {});
    });
    document.getElementById('close_button')?.addEventListener('click', () => window.pywebview?.api.hide_window());

    // 字母徽标(图标加载失败或本身没有方形图标时使用)
    const agentBadge = (letter, color) =>
        `<svg class="ai-chip-logo ai-chip-badge" viewBox="0 0 16 16" aria-hidden="true">` +
        `<rect width="16" height="16" rx="4" fill="${color || '#888'}"/>` +
        `<text x="8" y="11.5" text-anchor="middle" font-size="9" font-weight="700" fill="#fff" font-family="inherit">${letter || '?'}</text></svg>`;

    const bindChipLogoFallbacks = () => {
        document.querySelectorAll('.ai-chip-logo[data-letter]').forEach(img => {
            if (img.dataset.bound) return;   // 动态渲染会重复调用:避免重复绑定
            img.dataset.bound = '1';
            const fallback = () => {
                if (img.dataset.failed) return;
                img.dataset.failed = '1';
                const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                svg.setAttribute('class', 'ai-chip-logo ai-chip-badge');
                svg.setAttribute('viewBox', '0 0 16 16');
                svg.innerHTML = `<rect width="16" height="16" rx="4" fill="${img.dataset.color || '#888'}"/><text x="8" y="11.5" text-anchor="middle" font-size="9" font-weight="700" fill="#fff" font-family="inherit">${img.dataset.letter || '?'}</text>`;
                img.replaceWith(svg);
            };
            img.addEventListener('error', fallback);
            if (img.complete && img.naturalWidth === 0) fallback();
        });
    };
    bindChipLogoFallbacks();

    // 首页五个防护灯 = 五个实时防护模块的开关(config 里对应的 *_switch,后端按实际线程状态写回)。
    // 总述文案必须跟着灯走:全开才是「已受到防护」,否则说「未完全开启 / 未开启」。
    // 原来文案写死在模板的 data-i18n 上,新装默认五个模块全关时会出现
    // 「一边写『此装置已受到防护』、一边五个灰点」的自相矛盾。
    // driver_alert_exempt(默认开,设置页可关)把驱动防护从总述判断里摘出去:
    // 灯仍如实显示驱动状态,只是内核驱动装不上的机器不该永远挂着「未完全开启」。
    const PROTECT_LIGHT_KEYS = ['process', 'document', 'system', 'network', 'driver'];
    const updateProtectionLights = (cfg) => {
        PROTECT_LIGHT_KEYS.forEach((key) => {
            const enabled = !!(cfg && cfg[key + '_switch']);
            document.getElementById('light_' + key)?.classList.toggle('on', enabled);
        });
        const brand = document.querySelector('.status-brand');
        if (!brand) return;
        const judged = (cfg && cfg.driver_alert_exempt)
            ? PROTECT_LIGHT_KEYS.filter((key) => key !== 'driver')
            : PROTECT_LIGHT_KEYS;
        const judgedOn = judged.filter((key) => !!(cfg && cfg[key + '_switch'])).length;
        const full = judgedOn === judged.length;
        brand.classList.toggle('state-warn', !full);
        const title = brand.querySelector('.state-title');
        if (title) {
            // 全开时与模板初始文案一致;否则换文案,由本函数独占维护(translateText 之后会再调一次)
            title.textContent = getMsg(full ? 'status_protected' : (judgedOn ? 'status_partial' : 'status_off'));
        }
        // 带对勾的盾 + 「防护未完全开启」同样自相矛盾,未全开时换素盾
        brand.querySelector('.state-icon use')?.setAttribute('href', full ? '#i-shield-check' : '#i-shield');
    };

    // 待处理告警 chip 现在是筛选器(同其他日志筛选):点击展示当前弹窗队列;
    // 打开告警窗改由队列条目点击触发(见 home_log_list 点击处理)
    const pendingThreatButton = document.getElementById('pending_threats_btn');
    const refreshPendingThreats = async () => {
        if (window.pywebview?.api && !document.hidden) {
            try {
                const count = await window.pywebview.api.get_pending_threat_count();
                pendingThreatButton?.classList.toggle('hidden', count === 0);
                const label = document.getElementById('pending_threats_count');
                if (label && label.textContent !== String(count)) label.textContent = String(count);
                if (homeLogFilter === 'pending') {
                    if (count > 0) {
                        await fetchPendingThreatQueue();
                    } else {
                        // 队列已清空:回退到「全部」,不把用户停在空筛选上
                        pendingThreatEvents = [];
                        homeLogFilter = 'all';
                        document.querySelectorAll('.log-filter').forEach(b => b.classList.toggle('active', b.dataset.filter === 'all'));
                        renderHomeLogs();
                    }
                }
            } catch (error) { console.error('Pending threats refresh failed', error); }
        }
        window.setTimeout(refreshPendingThreats, 1500);
    };
    refreshPendingThreats();

    document.querySelectorAll('.log-filter').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.log-filter').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            homeLogFilter = btn.dataset.filter;
            renderHomeLogs();
            if (homeLogFilter === 'pending') fetchPendingThreatQueue();
        });
    });

    document.getElementById('home_log_export')?.addEventListener('click', () => {
        window.pywebview?.api.export_logs().then(res => {
            if (res) window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_export_success"), "info");
        });
    });

    document.getElementById('home_log_list')?.addEventListener('click', (e) => {
        // 待处理队列条目:点击打开告警窗进行处理
        if (e.target.closest('.home-log-item.lv-PENDING')) {
            window.pywebview?.api.show_pending_threats?.().catch(error => reportStartupError('pending-threats', error));
            return;
        }
        const li = e.target.closest('.home-log-item');
        if (!li || !li.classList.contains('lv-BLOCK')) return;

        const action = li.dataset.action || '';
        const pid = li.dataset.pid || '';
        const path = li.dataset.path || '';
        let target = null, search = '';

        if (action === 'File Block' || action === 'Deferred Scan Block') {
            target = 'quarantine_window';
            search = path;
        } else if (action === 'Process Block' || action === 'Process DLL Block') {
            target = 'taskmgr_window';
            search = pid;
        } else if (action === 'Network Block') {
            target = 'netmon_window';
            search = pid;
        }

        if (!target) return;
        switchPage(target);
        const searchInput = document.querySelector(`#${target} .search-box input`);
        if (searchInput && search) {
            searchInput.value = search;
            searchInput.dispatchEvent(new Event('input'));
        }
    });

    const contextMenu = document.createElement('div');
    contextMenu.className = 'custom-context-menu';
    contextMenu.innerHTML = `
        <div class="custom-context-menu-item" id="ctx_open_location"><svg aria-hidden="true" focusable="false"><use href="#i-folder"/></svg><span data-i18n="ctx_open_loc"></span></div>
        <div class="custom-context-menu-item" id="ctx_copy_cell"><svg aria-hidden="true" focusable="false"><use href="#i-copy"/></svg><span data-i18n="ctx_copy_cell"></span></div>`;
    const copyRowItem = contextMenu.querySelector('#ctx_copy_cell').cloneNode(true);
    copyRowItem.id = 'ctx_copy_row';
    copyRowItem.querySelector('span').setAttribute('data-i18n', 'ctx_copy_row');
    contextMenu.appendChild(copyRowItem);
    document.body.appendChild(contextMenu);
    let ctxTarget = null;
    let ctxCellText = null;
    let ctxRowText = null;

    const showContextMenu = (e) => {
        e.preventDefault();
        contextMenu.querySelector('#ctx_open_location').classList.toggle('hidden', !ctxTarget);
        contextMenu.querySelector('#ctx_copy_cell').classList.toggle('hidden', ctxCellText === null);
        contextMenu.querySelector('#ctx_copy_row').classList.toggle('hidden', ctxRowText === null);
        for (const key of ['ctx_open_loc', 'ctx_copy_cell', 'ctx_copy_row']) {
            contextMenu.querySelector(`[data-i18n="${key}"]`).textContent = getMsg(key);
        }
        contextMenu.style.left = `${e.clientX}px`;
        contextMenu.style.top = `${e.clientY}px`;
        contextMenu.classList.add('show');
        const rect = contextMenu.getBoundingClientRect();
        contextMenu.style.left = `${Math.max(0, Math.min(e.clientX, window.innerWidth - rect.width - 5))}px`;
        contextMenu.style.top = `${Math.max(0, Math.min(e.clientY, window.innerHeight - rect.height - 5))}px`;
    };

    const copyTextToClipboard = async (text) => {
        if (navigator.clipboard?.writeText) {
            try {
                await navigator.clipboard.writeText(text);
                return;
            } catch (e) {}
        }

        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        textarea.style.pointerEvents = 'none';
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        document.execCommand('copy');
        textarea.remove();
    };

    document.addEventListener('contextmenu', (e) => {
        ctxTarget = null;
        ctxCellText = null;
        ctxRowText = null;
        const logRow = e.target.closest('#home_log_list .home-log-item');
        if (logRow) {
            ctxRowText = logRow.dataset.copyText;
            const cell = e.target.closest('span');
            ctxCellText = cell ? cell.textContent : null;
            showContextMenu(e);
            return;
        }
        const li = e.target.closest('.manage-list-item');
        const rowCol = e.target.closest('.row-col');
        if (li && rowCol) {
            const cb = li.querySelector('input[type="checkbox"]');
            if (cb && cb.dataset.path && cb.dataset.path !== "path_unknown") {
                ctxTarget = cb.dataset.path;
                ctxCellText = rowCol.textContent;
                showContextMenu(e);
                return;
            }
        }
        contextMenu.classList.remove('show');
    });
    document.addEventListener('click', (e) => { if (!e.target.closest('.custom-context-menu')) contextMenu.classList.remove('show'); });
    document.addEventListener('scroll', () => contextMenu.classList.remove('show'), true);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') contextMenu.classList.remove('show'); });
    document.getElementById('ctx_open_location').addEventListener('click', () => {
        if (window.pywebview && ctxTarget) window.pywebview.api.open_file_location(ctxTarget);
        contextMenu.classList.remove('show');
    });
    document.getElementById('ctx_copy_cell').addEventListener('click', async () => {
        const text = ctxCellText;
        contextMenu.classList.remove('show');
        if (text !== null) await copyTextToClipboard(text);
    });

    document.getElementById('ctx_copy_row').addEventListener('click', async () => {
        const text = ctxRowText;
        contextMenu.classList.remove('show');
        if (text !== null) await copyTextToClipboard(text);
    });

    initI18nKeys();

    const bindSettingAction = (key, action) => {
        const item = Array.from(document.querySelectorAll('#about_window .list-item, #setting_window .list-item')).find(el => {
            const h2 = el.querySelector('h2');
            return h2 && h2.getAttribute('data-i18n') === key;
        });
        
        if (item) {
            const btn = item.querySelector('button');
            const isAboutItem = item.closest('#about_window') !== null;

            if (isAboutItem) {
                item.style.cursor = 'pointer';
                item.dataset.action = key;
                item.addEventListener('click', action);
                return;
            }
            
            if (btn) {
                btn.addEventListener('click', action);
            } else {
                item.style.cursor = 'pointer';
                item.dataset.action = key;
                item.addEventListener('click', action);
            }
        }
    };

    bindSettingAction('key_product', async () => {
        if (!window.pywebview) return;
        try {
            const cfg = await window.pywebview.api.get_config();
            if (cfg && cfg.api_key && cfg.api_key.trim() !== "") {
                window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_key_activated"), "info");
            }
        } catch (e) {}
    });

    bindSettingAction('web_official', () => window.pywebview?.api.open_website());

    const updateModalState = { result: null, downloading: false, pageUrl: '', downloadId: null,
        revision: -1, view: 0, phase: 'idle', percent: 0, installerPath: null, installIntent: null };
    let updateCheck = 0;
    let updateChecking = false;
    let updateDisposed = false;
    const updateWaits = new Set();
    const updateText = key => {
        const text = {
            simplified_switch: { checking: '正在检查更新…', timeout: '请求响应超时，未自动重试。请确认当前状态。',
                unavailable: '暂时无法确认下载状态，请稍后重新打开。', verifying: '正在校验安装包…',
                installing: '安装程序正在运行，请勿重复发起。', unknown: '无法确认安装是否启动，未重复发起。请检查安装程序后重新启动应用。',
                exited: '安装程序已退出，请重新检查版本。', unknownTotal: '总大小未知', failed: '操作失败，请重试。' },
            traditional_switch: { checking: '正在檢查更新…', timeout: '請求回應逾時，未自動重試。請確認目前狀態。',
                unavailable: '暫時無法確認下載狀態，請稍後重新開啟。', verifying: '正在驗證安裝包…',
                installing: '安裝程式正在執行，請勿重複發起。', unknown: '無法確認安裝是否啟動，未重複發起。請檢查安裝程式後重新啟動應用。',
                exited: '安裝程式已退出，請重新檢查版本。', unknownTotal: '總大小未知', failed: '操作失敗，請重試。' },
            english_switch: { checking: 'Checking for updates…', timeout: 'The response timed out. No automatic retry was sent; check the current state.',
                unavailable: 'Download state is unavailable. Reopen this window to check again.', verifying: 'Verifying the installer…',
                installing: 'The installer is running. Do not start it again.', unknown: 'The launch result is unknown. No retry was sent; check the installer and restart the application.',
                exited: 'The installer has exited. Check the version again.', unknownTotal: 'Total size unknown', failed: 'The operation failed. Please try again.' },
        };
        return (text[appState.lang] || text.english_switch)[key];
    };
    const updateRpc = (operation, timeout = 5000) => new Promise((resolve, reject) => {
        let settled = false;
        let timer;
        const finish = (callback, value) => {
            if (settled) return;
            settled = true; clearTimeout(timer); updateWaits.delete(cancel); callback(value);
        };
        const cancel = () => finish(reject, Object.assign(new Error('Update view closed'), { cancelled: true }));
        timer = setTimeout(() => finish(reject, Object.assign(new Error(updateText('timeout')), { timedOut: true })), timeout);
        updateWaits.add(cancel);
        Promise.resolve().then(operation).then(value => finish(resolve, value), error => finish(reject, error));
    });
    const setModalElement = (id, show) => document.getElementById(id)?.classList.toggle('hidden', !show);
    const showUpdateStatus = text => {
        const element = document.getElementById('update_modal_status');
        if (element) { element.textContent = String(text || ''); element.classList.remove('hidden'); }
    };
    const showUpdateError = async text => {
        showUpdateStatus(text);
        try {
            await updateRpc(() => window.pywebview.api.show_alert(getMsg('title_error'), String(text), 'error'));
        } catch (error) {
            if (!error.cancelled) { try { window.alert(String(text)); } catch (_) {} }
        }
    };
    const currentUpdateAsset = () => updateModalState.result?.asset;
    const matchesUpdateAsset = state => {
        const asset = currentUpdateAsset();
        return !!asset && typeof asset.asset_id === 'string' && asset.asset_id.length === 64
            && state?.asset_id === asset.asset_id && state.asset_url === asset.url
            && state.file_name === asset.name;
    };
    const syncUpdateSweep = () => {
        const track = document.getElementById('update_progress_track');
        const visible = !updateDisposed && !document.hidden && !document.getElementById('update_modal')?.classList.contains('hidden');
        const running = visible && updateModalState.phase === 'downloading' && updateModalState.percent < 100;
        track?.classList.toggle('is-downloading', !!running);
    };
    const setUpdateProgress = state => {
        const track = document.getElementById('update_progress_track');
        const fill = document.getElementById('update_progress_fill');
        const text = document.getElementById('update_progress_text');
        const known = typeof state.percent === 'number' && Number.isFinite(state.percent) && state.percent >= 0;
        const percent = known ? Math.min(100, Math.max(0, state.percent)) : -1;
        const received = typeof state.received === 'number' && Number.isFinite(state.received) ? Math.max(0, state.received) : 0;
        updateModalState.percent = percent;
        if (fill) fill.style.width = String(known ? percent : 0) + '%';
        if (track) {
            track.style.setProperty('--update-progress', String(known ? percent : 0) + '%');
            track.classList.toggle('is-complete', known && percent >= 100);
            track.classList.toggle('is-indeterminate', !known);
            if (known) track.setAttribute('aria-valuenow', String(percent)); else track.removeAttribute('aria-valuenow');
            track.setAttribute('aria-label', getMsg('btn_download'));
            track.setAttribute('aria-valuetext', known ? String(percent) + '%' : formatSize(received) + ' · ' + updateText('unknownTotal'));
        }
        if (text) text.textContent = known ? String(percent) + '%' : formatSize(received);
        syncUpdateSweep();
    };
    const applyDownloadState = (state, restore = false) => {
        if (!matchesUpdateAsset(state) || !/^[0-9a-f]{32}$/.test(String(state.download_id || ''))
                || !Number.isInteger(state.revision) || state.revision < 0) return false;
        if (restore && !updateModalState.downloadId) updateModalState.downloadId = state.download_id;
        if (state.download_id !== updateModalState.downloadId || state.revision < updateModalState.revision) return false;
        const phases = ['downloading', 'verifying', 'ready', 'failed', 'installing', 'install_unknown', 'installer_finished'];
        if (!phases.includes(state.phase)) return false;
        const result = state.result || {};
        if (state.phase === 'ready' && (result.success !== true || typeof result.path !== 'string')) return false;
        updateModalState.revision = state.revision;
        updateModalState.phase = state.phase;
        updateModalState.downloading = state.phase === 'downloading' || state.phase === 'verifying';
        const installing = state.phase === 'installing' || state.phase === 'install_unknown';
        const intent = updateModalState.installIntent;
        if (intent && (state.phase === 'installer_finished' || state.phase === 'failed'
                || (state.phase === 'ready' && state.revision > intent.revision && state.error))) updateModalState.installIntent = null;
        const unresolved = installing || !!updateModalState.installIntent;
        updateModalState.installerPath = state.phase === 'ready' && !unresolved ? result.path : null;
        setUpdateProgress(state);
        setModalElement('update_modal_progress', state.phase !== 'failed');
        const ready = state.phase === 'ready';
        setModalElement('update_install_btn', ready || installing || !!updateModalState.installIntent);
        const install = document.getElementById('update_install_btn');
        if (install) install.disabled = !ready || unresolved;
        setModalElement('update_download_btn', !ready && !installing && !updateModalState.installIntent);
        const download = document.getElementById('update_download_btn');
        if (download) download.disabled = updateModalState.downloading || unresolved || updateChecking;
        if (state.phase === 'downloading') setModalElement('update_modal_status', false);
        else if (state.phase === 'verifying') showUpdateStatus(updateText('verifying'));
        else if (unresolved) showUpdateStatus(updateText(state.phase === 'install_unknown' ? 'unknown' : 'installing'));
        else if (ready) showUpdateStatus(state.error || getMsg('msg_update_downloaded') + ' ' + result.path);
        else if (state.phase === 'failed') showUpdateStatus(getMsg('msg_update_download_fail') + '\n' + String(result.error || state.error || ''));
        else showUpdateStatus(updateText('exited'));
        return true;
    };
    const updateErrorMessage = res => {
        const messages = {
            repository_unavailable: '更新仓库不可访问（HTTP 404），请确认仓库已公开且地址正确。',
            rate_limited: 'GitHub 暂时限制了请求，请稍后重试。',
            network_error: '连接更新服务器失败，请检查网络和系统代理。',
            invalid_response: '更新服务器返回的数据格式异常。',
        };
        const english = {
            repository_unavailable: 'Update repository unavailable (HTTP 404). Check its visibility and address.',
            rate_limited: 'GitHub temporarily limited requests. Please try again later.',
            network_error: 'Could not connect to the update server. Check your network and system proxy.',
            invalid_response: 'The update server returned an unexpected response.',
        };
        const reason = (/^zh/.test(document.documentElement.lang) ? messages : english)[res?.error_code];
        return `${getMsg('msg_update_fail')}${reason ? `\n${reason}` : ''}${res?.detail ? `\n${res.detail}` : ''}`;
    };


    const openUpdateModal = async (res) => {
        const view = ++updateModalState.view;
        updateModalState.result = res;
        Object.assign(updateModalState, { downloadId: null, revision: -1, installerPath: null,
            phase: 'idle', percent: 0, installIntent: null });
        updateModalState.downloading = false;
        // 本仓库发布页/下载按钮只在自身有更新时出现;上游单独提示时只给上游发布页,
        // 免得两个「发布页」按钮指向不同项目,也免得给出无从下载的按钮
        const selfUpdate = !!res.has_update;
        // 上游跟进提示(开发者模式专有):没带 upstream 字段就是普通模式,整块不出现
        const upstream = res.upstream && res.upstream.has_update ? res.upstream : null;
        updateModalState.pageUrl = selfUpdate ? (res.url || '') : '';
        const upstreamBox = document.getElementById('update_modal_upstream');
        if (upstreamBox) {
            if (upstream) {
                upstreamBox.textContent = `${getMsg('msg_upstream_new').replace('{0}', upstream.latest).replace('{1}', upstream.tracked)}\n${getMsg('msg_upstream_follow')}`;
                upstreamBox.classList.remove('hidden');
            } else {
                upstreamBox.textContent = '';
                upstreamBox.classList.add('hidden');
            }
        }
        const upstreamBtn = document.getElementById('update_upstream_btn');
        if (upstreamBtn) {
            upstreamBtn.classList.toggle('hidden', !upstream);
            upstreamBtn.dataset.url = upstream ? upstream.url : '';
        }
        const title = document.getElementById('update_modal_title');
        if (title) {
            const titleKey = res.has_update ? 'msg_new_version' : 'msg_new_version_upstream';
            title.textContent = getMsg(titleKey);
            title.dataset.i18n = titleKey;
        }
        setModalElement('update_page_btn', !!updateModalState.pageUrl);
        const version = document.getElementById('update_modal_version');
        if (version) {
            if (res.has_update) {
                version.textContent = `${res.current} -> ${res.latest}`;
                version.classList.remove('hidden');
            } else {
                version.textContent = '';
                version.classList.add('hidden');
            }
        }
        const asset = document.getElementById('update_modal_asset');
        if (asset) {
            if (selfUpdate && res.asset && res.asset.name) {
                const sizeText = res.asset.size > 0 ? ` (${formatSize(res.asset.size)})` : '';
                asset.textContent = `${res.asset.name}${sizeText}`;
                asset.classList.remove('hidden');
            } else {
                asset.textContent = '';
                asset.classList.add('hidden');
            }
        }
        setModalElement('update_modal_progress', false);
        setModalElement('update_modal_status', false);
        // 能下载的只有本仓库安装包:上游提示没有对应安装包,不给下载按钮
        setModalElement('update_download_btn', selfUpdate && !!(res.asset && res.asset.url));
        setModalElement('update_install_btn', false);
        const downloadBtn = document.getElementById('update_download_btn');
        if (downloadBtn) downloadBtn.disabled = false;
        const fill = document.getElementById('update_progress_fill');
        if (fill) fill.style.width = '0%';
        setUpdateProgress({ percent: 0, received: 0 });
        const progressText = document.getElementById('update_progress_text');
        if (progressText) progressText.textContent = '0%';

        const changelog = document.getElementById('update_modal_changelog');
        if (changelog) {
            // 自身有新版展示自身日志;自身已是最新、上游有新版时改展示上游日志
            const notes = selfUpdate
                ? { body: res.body, latest: res.latest, at: res.published_at }
                : (upstream ? { body: upstream.body, latest: upstream.latest, at: upstream.published_at } : null);
            const body = String((notes && notes.body) || '').trim();
            if (body) {
                const meta = notes.at
                    ? `<span class="changelog-meta">${escapeHtml(String(notes.latest))} · ${escapeHtml(String(notes.at))}</span>`
                    : `<span class="changelog-meta">${escapeHtml(String(notes.latest))}</span>`;
                changelog.innerHTML = meta + escapeHtml(body);
                changelog.classList.remove('hidden');
            } else {
                changelog.innerHTML = '';
                changelog.classList.add('hidden');
            }
        }

        document.getElementById('update_modal')?.classList.remove('hidden');

        // 之前已开始的下载:直接恢复进度,不再提示重复下载
        if (!selfUpdate || !res.asset?.asset_id) return;
        try {
            const state = await updateRpc(() => window.pywebview.api.get_update_download_state());
            if (view === updateModalState.view) applyDownloadState(state, true);
        } catch (error) {
            if (view === updateModalState.view) showUpdateStatus(updateText('unavailable'));
        }
    };

    const closeUpdateModal = () => {
        updateModalState.view += 1;
        document.getElementById('update_modal')?.classList.add('hidden');
        syncUpdateSweep();
    };
    window.updateDownloadState = state => applyDownloadState(state);
    window.updateDownloadProgress = payload => applyDownloadState({ ...payload, phase: payload?.phase || 'downloading' });
    window.updateDownloadFinished = result => applyDownloadState({ ...result,
        phase: result?.phase || (result?.success ? 'ready' : 'failed'), result });
    const restoreUpdateState = async view => {
        const state = await updateRpc(() => window.pywebview.api.get_update_download_state());
        if (view !== updateModalState.view) return false;
        return applyDownloadState(state, !updateModalState.downloadId);
    };
    const downloadIdentity = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), value => value.toString(16).padStart(2, '0')).join('');
    document.getElementById('update_download_btn')?.addEventListener('click', async () => {
        const asset = currentUpdateAsset();
        if (!asset?.asset_id || !window.pywebview || updateModalState.downloading || updateChecking) return;
        const view = updateModalState.view;
        const id = downloadIdentity();
        Object.assign(updateModalState, { downloadId: id, revision: -1, installerPath: null, installIntent: null });
        applyDownloadState({ download_id: id, asset_id: asset.asset_id, asset_url: asset.url, file_name: asset.name,
            revision: 0, phase: 'downloading', received: 0, total: asset.size || 0, percent: asset.size ? 0 : -1 });
        try {
            const response = await updateRpc(() => window.pywebview.api.download_update(asset.url, asset.name, id));
            if (view !== updateModalState.view || id !== updateModalState.downloadId
                    || currentUpdateAsset()?.asset_id !== asset.asset_id) return;
            if (response?.already && matchesUpdateAsset(response.state)) {
                updateModalState.downloadId = response.state.download_id;
                updateModalState.revision = -1;
            }
            if (response?.state) applyDownloadState(response.state);
            if (!response?.success) {
                updateModalState.downloading = false;
                updateModalState.phase = 'failed'; syncUpdateSweep();
                const button = document.getElementById('update_download_btn'); if (button) button.disabled = false;
                await showUpdateError(response?.error || updateText('failed'));
            }
        } catch (error) {
            if (view !== updateModalState.view || id !== updateModalState.downloadId || error.cancelled) return;
            try { if (await restoreUpdateState(view)) return; } catch (_) {}
            updateModalState.phase = 'unknown'; updateModalState.downloading = false; syncUpdateSweep();
            showUpdateStatus(error.timedOut ? updateText('timeout') : updateText('unavailable'));
            const button = document.getElementById('update_download_btn'); if (button) button.disabled = false;
        }
    });
    document.getElementById('update_install_btn')?.addEventListener('click', async () => {
        if (updateModalState.phase !== 'ready' || !updateModalState.installerPath || updateModalState.installIntent || !window.pywebview) return;
        const view = updateModalState.view;
        const id = updateModalState.downloadId;
        const path = updateModalState.installerPath;
        updateModalState.installIntent = { id, revision: updateModalState.revision };
        document.getElementById('update_install_btn').disabled = true;
        showUpdateStatus(updateText('installing'));
        try {
            const accepted = await updateRpc(() => window.pywebview.api.run_update_installer(path, id));
            if (view !== updateModalState.view || id !== updateModalState.downloadId) return;
            if (accepted === true) closeUpdateModal();
            else {
                await restoreUpdateState(view);
                if (updateModalState.phase !== 'install_unknown') await showUpdateError(getMsg('msg_update_install_fail'));
            }
        } catch (error) {
            if (view !== updateModalState.view || id !== updateModalState.downloadId || error.cancelled) return;
            try { await restoreUpdateState(view); } catch (_) {}
            showUpdateStatus(updateText('unknown'));
        }
    });
    document.getElementById('update_upstream_btn')?.addEventListener('click', event => {
        const url = event.currentTarget?.dataset?.url;
        if (url) Promise.resolve(window.pywebview?.api.open_url(url)).catch(error => showUpdateError(String(error)));
    });
    document.getElementById('update_page_btn')?.addEventListener('click', () => {
        const url = updateModalState.pageUrl || updateModalState.result?.url;
        if (url) Promise.resolve(window.pywebview?.api.open_url(url)).catch(error => showUpdateError(String(error)));
    });
    document.getElementById('update_close_btn')?.addEventListener('click', closeUpdateModal);
    const checkForUpdates = async () => {
        if (updateChecking || !window.pywebview) return;
        updateChecking = true;
        const token = ++updateCheck;
        const view = updateModalState.view;
        const quick = document.getElementById('quick_update_btn');
        if (quick) { quick.disabled = true; quick.setAttribute('aria-busy', 'true'); }
        try {
            const response = await updateRpc(() => window.pywebview.api.check_update(), 45000);
            if (token !== updateCheck || view !== updateModalState.view) return;
            if (!response || response.error) await showUpdateError(updateErrorMessage(response || { error_code: 'invalid_response' }));
            else if (response.has_update || response.upstream?.has_update) await openUpdateModal(response);
            else await updateRpc(() => window.pywebview.api.show_alert(getMsg('title_prompt'), getMsg('msg_latest_version') + ' ' + response.current, 'info'));
        } catch (error) {
            if (token === updateCheck && view === updateModalState.view && !error.cancelled) await showUpdateError(error.timedOut ? updateText('timeout') : String(error.message || error));
        } finally {
            if (token === updateCheck) {
                updateChecking = false;
                if (quick) { quick.disabled = false; quick.removeAttribute('aria-busy'); }
                const download = document.getElementById('update_download_btn');
                if (download && !updateModalState.downloading && !updateModalState.installIntent) download.disabled = false;
            }
        }
    };
    bindSettingAction('update_check', checkForUpdates);
    document.addEventListener('visibilitychange', syncUpdateSweep);
    window.addEventListener('pagehide', () => {
        updateDisposed = true; updateCheck += 1; updateModalState.view += 1; updateChecking = false;
        for (const cancel of [...updateWaits]) cancel();
        syncUpdateSweep();
    });
    window.addEventListener('pageshow', () => {
        updateDisposed = false;
        const quick = document.getElementById('quick_update_btn');
        if (quick) { quick.disabled = false; quick.removeAttribute('aria-busy'); }
        syncUpdateSweep();
    });

    const checkSystemNotifyPermission = () => {
        window.pywebview.api.check_notification_permission().then(res => {
            if (!res || !res.supported) {
                window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_notify_unsupported"), "info");
            } else if (!res.enabled) {
                /* 权限正常保持静默,仅异常才提示并引导 */
                window.pywebview.api.show_confirm(getMsg("title_prompt"), getMsg("msg_notify_disabled")).then(ok => {
                    if (ok) window.pywebview.api.open_notification_settings();
                });
            }
        });
    };

    document.getElementById('notify_channel_select')?.addEventListener('change', (e) => {
        if (!window.pywebview) return;
        const channel = e.target.value;
        window.pywebview.api.update_config('notify_channel', channel).then(saved => {
            // 选择系统渠道时立即检查通知权限
            if ((saved ?? channel) === 'system') checkSystemNotifyPermission();
        });
    });

    const changelogState = { loaded: false, data: null, tab: 'cyanmod' };

    const versionDigits = (s) => (String(s).match(/\d+/g) || []).map(Number);

    const versionAtMost = (a, b) => {
        const da = versionDigits(a), db = versionDigits(b);
        const len = Math.max(da.length, db.length);
        for (let i = 0; i < len; i++) {
            const x = da[i] || 0, y = db[i] || 0;
            if (x !== y) return x < y;
        }
        return true;
    };

    const fetchReleases = async (repo, maxVersion) => {
        const res = await fetch(`https://api.github.com/repos/${repo}/releases?per_page=20`, {
            headers: { 'Accept': 'application/vnd.github+json' }
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const list = await res.json();
        return (list || []).filter(rel => rel && rel.tag_name).map(rel => ({
            tag: String(rel.tag_name).trim(),
            name: String(rel.name || rel.tag_name || ''),
            date: String(rel.published_at || '').slice(0, 10),
            body: String(rel.body || '').slice(0, 2000)
        })).filter(e => !maxVersion || (versionDigits(e.tag).length && versionAtMost(e.tag, maxVersion)));
    };

    const renderChangelog = () => {
        const body = document.getElementById('changelog_body');
        const note = document.getElementById('changelog_note');
        if (!body) return;

        if (note) {
            if (changelogState.tab === 'upstream' && changelogState.data && !changelogState.data.error && changelogState.data.tracked) {
                note.textContent = getMsg('changelog_tracked').replace('{0}', 'v' + changelogState.data.tracked);
                note.classList.remove('hidden');
            } else {
                note.classList.add('hidden');
            }
        }

        if (!changelogState.data) {
            body.innerHTML = `<div class="changelog-placeholder">${escapeHtml(getMsg('changelog_loading'))}</div>`;
            return;
        }

        if (changelogState.data.error) {
            body.innerHTML = `<div class="changelog-placeholder">${escapeHtml(getMsg('changelog_failed'))}</div>`;
            return;
        }

        const entries = changelogState.data[changelogState.tab] || [];

        if (!entries.length) {
            body.innerHTML = `<div class="changelog-placeholder">${escapeHtml(getMsg('changelog_empty'))}</div>`;
            return;
        }

        body.innerHTML = entries.map(e => `
            <div class="changelog-entry">
                <div class="changelog-entry-head">
                    <span class="changelog-tag">${escapeHtml(e.tag)}</span>
                    <span class="changelog-name">${escapeHtml(e.name || '')}</span>
                    <span class="changelog-date">${escapeHtml(e.date || '')}</span>
                </div>
                ${e.body ? `<div class="changelog-text">${escapeHtml(e.body)}</div>` : ''}
            </div>`).join('');
    };

    const loadChangelogs = () => {
        if (changelogState.loaded) {
            renderChangelog();
            return;
        }

        renderChangelog();
        const tracked = appState.upstreamTracked || '3.7.1';

        Promise.all([
            fetchReleases('upcyan/PYAS_cyanmod', null).catch(() => null),
            fetchReleases('87owo/PYAS', tracked).catch(() => null)
        ]).then(([cyanmod, upstream]) => {
            const failed = cyanmod === null && upstream === null;
            changelogState.data = { cyanmod: cyanmod || [], upstream: upstream || [], tracked, error: failed };
            changelogState.loaded = true;
            renderChangelog();
        });
    };

    document.querySelectorAll('.changelog-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.changelog-tab').forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            changelogState.tab = tab.dataset.tab;
            renderChangelog();
            if (!changelogState.loaded) loadChangelogs();
        });
    });
    
    bindSettingAction('opt_reset', () => {
        window.pywebview?.api.show_confirm(getMsg("title_prompt"), getMsg("opt_reset_desc")).then(res => {
            if (res) window.pywebview.api.reset_config().then(() => window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_reset_success"), "info"));
        });
    });
    document.getElementById('clear_alert_rules')?.addEventListener('click', async () => {
        const api = window.pywebview?.api;
        if (!api) return;
        const chinese = /^zh/.test(document.documentElement.lang);
        if (!await api.show_confirm(getMsg('title_prompt'), chinese ? '清除全部已记住的告警决定？以后重新询问。' : 'Clear all remembered alert decisions? Future alerts will prompt again.')) return;
        const success = await api.clear_alert_decisions();
        await api.show_alert(getMsg('title_prompt'), success ? (chinese ? '已清除。' : 'Cleared.') : (chinese ? '保存失败，未清除。' : 'Could not save. Rules were preserved.'), success ? 'info' : 'error');
    });

    document.querySelectorAll('select.modern-select').forEach(buildCustomSelectElement);
    renderDataGrid('#home_window', [], cols.log, 'id', false);
    renderDataGrid('#scan_window', appState.virusResults, cols.virus, 'path', true);
    renderDataGrid('#taskmgr_window', [], cols.process, 'pid', false);
    renderDataGrid('#startup_window', [], cols.startup, 'id', false);
    renderDataGrid('#junk_window', [], cols.junk, 'path', true);
    renderDataGrid('#repair_window', [], cols.repair, 'id', true);
    renderDataGrid('#whitelist_window', [], cols.fileList, 'path', false);
    renderDataGrid('#quarantine_window', [], cols.fileList, 'path', false);
    renderDataGrid('#custom_protect_window', [], cols.fileList, 'path', false);
    renderDataGrid('#popup_window', [], cols.popup, 'value', false);
    renderDataGrid('#log_export_window', [], cols.log, 'id', true);
    renderDataGrid('#release_window', [], cols.release, 'value', false);
    renderDataGrid('#netmon_window', [], cols.netmon, 'pid', false);

    let gridResizeTimer = null;
    const rescaleAllGrids = () => {
        document.querySelectorAll('.manage-widget, .virus-widget').forEach(widget => {
            if (!widget.getClientRects().length) return;
            const state = widget.gridState;
            if (!state || !Array.isArray(state.colWidths) || !state.colWidths.length) return;
            const containerWidth = widget.clientWidth || 800;
            const availableWidth = Math.max(containerWidth - 60 - (state.colWidths.length * 16), 400);
            const total = state.colWidths.reduce((sum, w) => sum + w, 0);
            if (total <= 0) return;
            state.colWidths = state.colWidths.map(w => Math.max((w / total) * availableWidth, 40));
            state.colWidths.forEach((w, idx) => widget.style.setProperty(`--col-${idx}`, `${w}px`));
        });
    };
    window.addEventListener('resize', () => {
        clearTimeout(gridResizeTimer);
        gridResizeTimer = setTimeout(rescaleAllGrids, 120);
    });

    const updateQuickScale = () => {
        const row = document.querySelector('.quick-actions-row');
        if (!row) return;
        const scale = Math.max(0.68, Math.min(1, row.clientWidth / 640));
        row.style.setProperty('--quick-scale', scale.toFixed(3));
        row.classList.toggle('quick-compact', row.clientWidth < 470);
    };
    updateQuickScale();
    let quickScaleFrame = null;
    window.addEventListener('resize', () => {
        if (quickScaleFrame !== null) return;
        quickScaleFrame = requestAnimationFrame(() => {
            quickScaleFrame = null;
            updateQuickScale();
        });
    });

    let pywebviewInitStarted = false;
    let pywebviewInitReady = false;
    let pywebviewInitAttempts = 0;
    let pywebviewInitTimer = null;
    const pywebviewInitDeadline = Date.now() + 30000;

    const reportStartupError = (stage, message) => {
        const text = String(message);
        console.error(`PYAS startup ${stage}:`, text);
        if (window.pywebview?.api?.report_ui_error) {
            window.pywebview.api.report_ui_error(stage, text).catch(() => {});
        }
    };

    const schedulePywebviewInit = (delay) => {
        clearTimeout(pywebviewInitTimer);
        pywebviewInitTimer = setTimeout(initializePywebview, delay);
    };

    const initializePywebview = async () => {
        if (pywebviewInitStarted || pywebviewInitReady || pywebviewInitAttempts >= 3) return;
        if (!window.pywebview?.api) {
            if (Date.now() < pywebviewInitDeadline) schedulePywebviewInit(250);
            else showStartupError("The Python interface bridge is unavailable. PYAS will attempt recovery.");
            return;
        }
        pywebviewInitStarted = true;
        pywebviewInitAttempts += 1;
        clearTimeout(pywebviewInitTimer);
        let timeoutId;
        let timedOut = false;
        let stage = 'get_config';
        const timeout = new Promise((_, reject) => {
            timeoutId = setTimeout(() => {
                timedOut = true;
                reject(new Error("Python interface initialization timed out"));
            }, 8000);
        });
        try {
            for (const error of (window.pyasStartupErrors || []).splice(0)) {
                reportStartupError(error.stage, error.message);
            }
            await Promise.race([(async () => {
                const cfg = await window.pywebview.api.get_config();
                if (timedOut) return;
                if (!cfg || typeof cfg !== 'object') throw new Error("Invalid configuration response");
                stage = 'ui_apply';
                const theme = cfg.theme || "white_switch";
                const lang = cfg.language || "english_switch";
                appState.firstLaunch = cfg.first_launch;
                applyTheme(theme);
                translateText(lang);
                updateCustomSelectUI('theme_select', theme);
                updateCustomSelectUI('lang_select', lang);
                const versionChip = document.getElementById('about_version');
                if (versionChip) versionChip.textContent = 'v' + (cfg.version || '');
                const titleVersion = document.getElementById('title_version');
                if (titleVersion) titleVersion.textContent = 'v' + (cfg.version || '');
                // 开发者模式(本地构建)在版本号后挂标识,与发布包区分
                document.getElementById('title_dev_badge')?.classList.toggle('hidden', !cfg.dev_channel);
                const notifySelect = document.getElementById('notify_channel_select');
                if (notifySelect) {
                    const channel = cfg.notify_channel === 'custom' ? 'custom' : 'system';
                    notifySelect.value = channel;
                    updateCustomSelectUI('notify_channel_select', channel);
                }
                appState.upstreamTracked = cfg.upstream_tracked || '3.7.0';
                appState.configCache = cfg;
                await window.refreshContextMenuStatus();
                updateProtectionLights(cfg);
                const timeoutInput = document.getElementById('interactive_timeout_input');
                if (timeoutInput) {
                    const parsed = parseInt(cfg.interactive_timeout, 10);
                    timeoutInput.value = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 5), 300) : 30;
                }
                const aiModeSelect = document.getElementById('ai_mode_select');
                if (aiModeSelect) {
                    const aiMode = cfg.ai_provider_mode === 'cloud' ? 'cloud' : 'local';
                    aiModeSelect.value = aiMode;
                    updateCustomSelectUI('ai_mode_select', aiMode);
                    const baseUrl = document.getElementById('ai_base_url_input');
                    const apiKey = document.getElementById('ai_api_key_input');
                    const aiModel = document.getElementById('ai_model_input');
                    if (baseUrl) baseUrl.value = cfg.ai_base_url || '';
                    if (apiKey) apiKey.value = cfg.ai_api_key || '';
                    if (aiModel) aiModel.value = cfg.ai_model || '';
                    applyAiModeUI(aiMode);
                    refreshAiTokenUsage();
                }

                document.querySelectorAll('.toggle-switch input').forEach((toggle, index) => {
                    if (appState.firstLaunch) {
                        // 首启时防护开关一律置灰等引擎就绪;「驱动防护不纳入警报」是纯界面偏好(默认开),
                        // 不依赖引擎,置灰成关会让界面与新装默认值对不上
                        toggle.checked = toggle.dataset.configKey === 'driver_alert_exempt'
                            ? !!cfg.driver_alert_exempt
                            : false;
                        toggle.disabled = true;
                    } else if (toggle.dataset.configKey) {
                        toggle.checked = !!cfg[toggle.dataset.configKey];
                    }
                });
                const fillTimeout = (id, key, fallback, min, max) => {
                    const input = document.getElementById(id);
                    if (!input) return;
                    let value = parseInt(cfg[key], 10);
                    if (!Number.isFinite(value)) value = fallback;
                    input.value = Math.min(Math.max(value, min), max);
                };
                fillTimeout('interactive_timeout_input', 'interactive_timeout', 30, 5, 300);
                fillTimeout('ai_auto_timeout_input', 'ai_auto_execute_timeout', 60, 5, 600);
                fillTimeout('ai_delay_seconds_input', 'ai_delay_seconds', 3, 1, 30);
                syncInteractiveTimeoutState();
                // 回填完成后再按实际值刷新清空按钮(赋值不发事件,按钮默认隐藏)
                syncClearButtons();
                stage = 'init_ui_ready';
                await window.pywebview.api.init_ui_ready();
                backfillHomeLogs();
            })(), timeout]);
            pywebviewInitReady = true;
            closeStartupOverlay();
        } catch (err) {
            reportStartupError(stage, err?.message || err);
            showStartupError(`Interface initialization failed (${stage}): ${err?.message || err}`);
            if (pywebviewInitAttempts < 3) schedulePywebviewInit(500 * pywebviewInitAttempts);
        } finally {
            clearTimeout(timeoutId);
            pywebviewInitStarted = false;
        }
    };

    window.addEventListener('pywebviewready', initializePywebview);
    initializePywebview();


    window.onEngineReady = async () => {
        if (!appState.firstLaunch) return;
        if (appState.configCache?.policy_status) {
            // A per-user first-run flag must never override administrator policy.
            await window.pywebview.api.update_config('first_launch', false);
            appState.firstLaunch = false;
            if (appState.configCache.policy_status.initialized) {
                document.querySelectorAll('.toggle-switch input').forEach(toggle => { if (!toggle.dataset.pending) toggle.disabled = false; });
            }
            window.dispatchEvent(new Event('pyas-policy-refresh'));
            return;
        }
        await window.pywebview.api.update_config("first_launch", false);

        const seq = ["autostart_switch", "suffix_switch", "process_switch", "suspend_switch", "load_switch", "document_switch", "system_switch", "network_switch", "driver_switch", "context_switch"];
        
        for (const key of seq) {
            {
                const toggle = document.querySelector(`.toggle-switch input[data-config-key="${key}"]`);
                if (toggle) {
                    toggle.checked = true;
                    try {
                        const res = await window.pywebview.api.update_config(key, true);
                        if (res !== undefined && res !== null) toggle.checked = res;
                    } catch { toggle.checked = false; } 
                    finally { toggle.disabled = false; }
                    if (appState.configCache) appState.configCache[key] = toggle.checked;
                    await new Promise(r => setTimeout(r, 100));
                }
            }
        }
        document.querySelectorAll('.toggle-switch input').forEach(t => { t.disabled = false; });
        appState.firstLaunch = false;
        await window.refreshContextMenuStatus();
        syncInteractiveTimeoutState();
        if (appState.configCache) {
            updateProtectionLights(appState.configCache);
        }
    };
});
