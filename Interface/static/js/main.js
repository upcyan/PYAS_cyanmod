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

    const closeCustomSelect = () => {
        if (!openCustomSelect) return;
        const { wrapper, menu } = openCustomSelect;
        wrapper.classList.remove('open');
        menu.classList.remove('open');
        menu.removeAttribute('style');
        if (wrapper.isConnected) wrapper.appendChild(menu);
        else menu.remove();
        openCustomSelect = null;
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

    document.addEventListener('click', closeCustomSelect);
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

    const themes = window.PyasTheme.themes;

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
        netmon: [{key: 'name', label: 'col_name', flex: 1.5}, {key: 'pid', label: 'col_pid', flex: 0.5}, {key: 'downStr', label: 'col_down_speed', flex: 1}, {key: 'upStr', label: 'col_up_speed', flex: 1}, {key: 'connCount', label: 'col_conn_count', flex: 0.8}]
    };

    const buildCustomSelectElement = (select) => {
        select.style.display = 'none';
        const wrapper = document.createElement('div');
        wrapper.className = 'custom-select-wrapper';
        
        const selectedOpt = select.options[select.selectedIndex];
        const triggerKey = selectedOpt ? selectedOpt.getAttribute('data-i18n') : '';
        const triggerTextContent = selectedOpt ? getMsg(triggerKey || selectedOpt.textContent) : '';

        const triggerHTML = `
            <div class="custom-select-trigger">
                <span class="custom-select-text" ${triggerKey ? `data-i18n="${triggerKey}"` : ''}>${triggerTextContent}</span>
                <div class="custom-select-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg></div>
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
            if (optKey) li.setAttribute('data-i18n', optKey);
            
            li.addEventListener('click', (e) => {
                e.stopPropagation();
                select.value = option.value;
                const triggerText = wrapper.querySelector('.custom-select-text');
                triggerText.textContent = li.textContent;
                if (optKey) triggerText.setAttribute('data-i18n', optKey);
                
                closeCustomSelect();
                optionsContainer.querySelectorAll('.custom-select-option').forEach(el => el.classList.remove('selected'));
                li.classList.add('selected');
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
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = wrapper.classList.contains('open');
            closeCustomSelect();
            if (!isOpen && !select.disabled) {
                wrapper.classList.add('open');
                document.body.appendChild(optionsContainer);
                optionsContainer.classList.add('open');
                openCustomSelect = { wrapper, trigger, menu: optionsContainer };
                positionCustomSelect();
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
        if (decisionDescription) decisionDescription.textContent = /^zh/.test(document.documentElement.lang) ? '撤销永久允许及 30 秒重复操作规则；保留普通白名单' : 'Revoke permanent and short-lived alert rules; keep the regular whitelist';

        const progressText = document.getElementById('progress_text');
        if (progressText && progressText.dataset.dynamicMsg) {
            try {
                const msgs = JSON.parse(progressText.dataset.dynamicMsg);
                if (msgs[lang]) progressText.textContent = msgs[lang];
            } catch (e) {}
        }
        renderMenuStatus();
    };

    const applyTheme = (theme) => {
        appState.theme = theme;
        const actualTheme = theme === "system_switch" 
            ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? "black_switch" : "white_switch") 
            : theme;

        const themeVars = themes[actualTheme];
        if (themeVars) {
            for (const [key, value] of Object.entries(themeVars)) {
                document.documentElement.style.setProperty(key, value.startsWith("rgba") ? value : `rgb(${value})`);
            }
        }
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
                
                const rawKeyMap = { 'sizeStr': 'size', 'downStr': 'down', 'upStr': 'up' };
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

        if (targetId === 'about_window') loadChangelogs();
        if (targetId === 'home_window' && homeLogDirty) renderHomeLogs();

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

    const backfillHomeLogs = () => {
        if (!window.pywebview || homeLogBackfillInFlight) return;
        homeLogBackfillInFlight = true;
        window.pywebview.api.get_logs().then(logs => {
            homeLogBackfillInFlight = false;
            window.pywebview.api.report_ui_error('home-log-backfill', 'received ' + (logs ? logs.length : 'null') + ' entries');
            if (!logs || !logs.length) { renderHomeLogs(); return; }
            const merged = [...logs];
            homeLogs.forEach(l => { if (!merged.some(m => m.id === l.id)) merged.push(l); });
            homeLogs.length = 0;
            merged.slice(-200).forEach(l => homeLogs.push(l));
            renderHomeLogs();
        }).catch(err => {
            homeLogBackfillInFlight = false;
            window.pywebview.api.report_ui_error('home-log-backfill', 'failed: ' + String(err && err.message || err));
            renderHomeLogs();
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

        const data = (homeLogFilter === 'all' ? homeLogs : homeLogs.filter(l => l.level === homeLogFilter))
            .slice(-200)
            .sort((a, b) => (homeLogSortDesc ? -1 : 1) * String(a.time_str || '').localeCompare(String(b.time_str || '')));

        if (!data.length) {
            listUl.innerHTML = homeLogs.length
                ? '<li class="home-log-empty">' + escapeHtml(getMsg('changelog_empty')) + '</li>'
                : '';
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
    document.getElementById('quick_scan_btn')?.addEventListener('click', () => { if (!appState.scanning) { switchPage('scan_window'); triggerScan('smart'); }});
    document.getElementById('quick_update_btn')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        window.pywebview.api.check_update().then(res => {
            if (res.error) window.pywebview.api.show_alert(getMsg("title_error"), updateErrorMessage(res), "error");
            else if (res.has_update) openUpdateModal(res);
            else window.pywebview.api.show_alert(getMsg("title_prompt"), `${getMsg("msg_latest_version")} ${res.current}`, "info");
        });
    });
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
            const visible = !appState.firstLaunch && !!parent?.checked;
            row.classList.toggle('hidden', !visible);
            row.querySelectorAll('input, button').forEach(control => {
                control.disabled = !visible || parent.disabled || control.dataset.pending === '1';
            });
        });
        const interactive = document.querySelector('[data-config-key="interactive_switch"]');
        const automatic = document.querySelector('[data-config-key="interactive_auto_block"]');
        const timeoutInput = document.getElementById('interactive_timeout_input');
        if (automatic) automatic.disabled = appState.firstLaunch || !interactive?.checked || interactive.disabled || automatic.dataset.pending === '1';
        if (timeoutInput) {
            timeoutInput.disabled = appState.firstLaunch || !interactive?.checked || interactive.disabled || !automatic?.checked || automatic.disabled;
            timeoutInput.closest('.list-item')?.classList.toggle('hidden', appState.firstLaunch || !interactive?.checked || !automatic?.checked);
        }
    };

    document.getElementById('interactive_timeout_input')?.addEventListener('change', (e) => {
        if (!window.pywebview) return;
        let value = parseInt(e.target.value, 10);
        if (!Number.isFinite(value)) value = 30;
        value = Math.min(Math.max(value, 5), 300);
        e.target.value = value;
        window.pywebview.api.update_config('interactive_timeout', value);
    });
    
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
    };

    document.querySelectorAll('.toggle-switch input').forEach((toggle, index) => {
        toggle.addEventListener('change', async (e) => {

            const key = toggle.dataset.configKey;
            if (!window.pywebview || !key) return;

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
    };
    window.syncMaximizeIcon = syncMaximizeIcon;

    document.getElementById('maximize_button')?.addEventListener('click', () => {
        window.pywebview?.api.toggle_maximize().then(state => syncMaximizeIcon(!!state)).catch(() => {});
    });
    document.getElementById('close_button')?.addEventListener('click', () => window.pywebview?.api.hide_window());

    const updateProtectionLights = (cfg) => {
        const map = { process: 'light_process', document: 'light_document', system: 'light_system', network: 'light_network', driver: 'light_driver' };
        Object.entries(map).forEach(([key, id]) => {
            const el = document.getElementById(id);
            if (el) el.classList.toggle('on', !!(cfg && cfg[key + '_switch']));
        });
    };

    const pendingThreatButton = document.getElementById('pending_threats_btn');
    pendingThreatButton?.addEventListener('click', () => {
        window.pywebview?.api.show_pending_threats().catch(error => reportStartupError('pending-threats', error));
    });
    const refreshPendingThreats = async () => {
        if (window.pywebview?.api && !document.hidden) {
            try {
                const count = await window.pywebview.api.get_pending_threat_count();
                pendingThreatButton?.classList.toggle('hidden', count === 0);
                const label = document.getElementById('pending_threats_count');
                if (label && label.textContent !== String(count)) label.textContent = String(count);
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
        });
    });

    document.getElementById('home_log_export')?.addEventListener('click', () => {
        window.pywebview?.api.export_logs().then(res => {
            if (res) window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_export_success"), "info");
        });
    });

    document.getElementById('home_log_list')?.addEventListener('click', (e) => {
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
        <div class="custom-context-menu-item" id="ctx_open_location"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg><span data-i18n="ctx_open_loc"></span></div>
        <div class="custom-context-menu-item" id="ctx_copy_cell"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg><span data-i18n="ctx_copy_cell"></span></div>`;
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

    const updateModalState = { result: null, downloading: false };
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

    const setModalElement = (id, show) => document.getElementById(id)?.classList.toggle('hidden', !show);

    const openUpdateModal = (res) => {
        updateModalState.result = res;
        updateModalState.downloading = false;
        const version = document.getElementById('update_modal_version');
        if (version) version.textContent = `${res.current} -> ${res.latest}`;
        const asset = document.getElementById('update_modal_asset');
        if (asset) {
            if (res.asset && res.asset.name) {
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
        setModalElement('update_download_btn', !!(res.asset && res.asset.url));
        setModalElement('update_install_btn', false);
        const downloadBtn = document.getElementById('update_download_btn');
        if (downloadBtn) downloadBtn.disabled = false;
        const fill = document.getElementById('update_progress_fill');
        if (fill) fill.style.width = '0%';
        const progressText = document.getElementById('update_progress_text');
        if (progressText) progressText.textContent = '0%';
        document.getElementById('update_modal')?.classList.remove('hidden');
    };

    const closeUpdateModal = () => document.getElementById('update_modal')?.classList.add('hidden');

    window.updateDownloadProgress = (payload) => {
        if (!payload) return;
        const fill = document.getElementById('update_progress_fill');
        const text = document.getElementById('update_progress_text');
        if (payload.percent >= 0) {
            if (fill) fill.style.width = `${payload.percent}%`;
            if (text) text.textContent = `${payload.percent}%`;
        } else {
            if (fill) fill.style.width = '35%';
            if (text) text.textContent = formatSize(payload.received || 0);
        }
    };

    window.updateDownloadFinished = (result) => {
        updateModalState.downloading = false;
        const downloadBtn = document.getElementById('update_download_btn');
        if (downloadBtn) downloadBtn.disabled = false;
        const status = document.getElementById('update_modal_status');
        if (result && result.success) {
            const fill = document.getElementById('update_progress_fill');
            if (fill) fill.style.width = '100%';
            const progressText = document.getElementById('update_progress_text');
            if (progressText) progressText.textContent = '100%';
            setModalElement('update_modal_progress', false);
            updateModalState.installerPath = result.path;
            if (status) {
                status.textContent = `${getMsg('msg_update_downloaded')} ${result.path}`;
                status.classList.remove('hidden');
            }
            setModalElement('update_install_btn', true);
            setModalElement('update_download_btn', false);
        } else {
            if (status) {
                status.textContent = `${getMsg('msg_update_download_fail')}${result && result.error ? `\n${result.error}` : ''}`;
                status.classList.remove('hidden');
            }
            setModalElement('update_modal_progress', false);
            setModalElement('update_download_btn', !!(updateModalState.result?.asset?.url));
        }
    };

    document.getElementById('update_download_btn')?.addEventListener('click', () => {
        const asset = updateModalState.result?.asset;
        if (!asset || !asset.url || !window.pywebview || updateModalState.downloading) return;
        updateModalState.downloading = true;
        const downloadBtn = document.getElementById('update_download_btn');
        if (downloadBtn) downloadBtn.disabled = true;
        setModalElement('update_modal_status', false);
        setModalElement('update_modal_progress', true);
        window.pywebview.api.download_update(asset.url, asset.name).then(res => {
            if (!res || !res.success) {
                window.updateDownloadFinished(res || { success: false, error: 'failed to start' });
            }
        }).catch(() => window.updateDownloadFinished({ success: false, error: 'bridge error' }));
    });

    document.getElementById('update_install_btn')?.addEventListener('click', () => {
        const path = updateModalState.installerPath;
        if (!path || !window.pywebview) return;
        window.pywebview.api.run_update_installer(path).then(ok => {
            if (ok) closeUpdateModal();
            else window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_update_install_fail"), "error");
        });
    });

    document.getElementById('update_page_btn')?.addEventListener('click', () => {
        const url = updateModalState.result?.url;
        if (url) window.pywebview?.api.open_url(url);
    });

    document.getElementById('update_close_btn')?.addEventListener('click', closeUpdateModal);

    bindSettingAction('update_check', () => {
        window.pywebview?.api.check_update().then(res => {
            if (res.error) window.pywebview.api.show_alert(getMsg("title_error"), updateErrorMessage(res), "error");
            else if (res.has_update) openUpdateModal(res);
            else window.pywebview.api.show_alert(getMsg("title_prompt"), `${getMsg("msg_latest_version")} ${res.current}`, "info");
        });
    });

    bindSettingAction('opt_notify_check', () => {
        if (!window.pywebview) return;
        window.pywebview.api.check_notification_permission().then(res => {
            if (!res || !res.supported) {
                window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_notify_unsupported"), "info");
            } else if (res.enabled) {
                window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_notify_ok"), "info");
            } else {
                window.pywebview.api.show_confirm(getMsg("title_prompt"), getMsg("msg_notify_disabled")).then(ok => {
                    if (ok) window.pywebview.api.open_notification_settings();
                });
            }
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
                appState.upstreamTracked = cfg.upstream_tracked || '3.7.0';
                appState.configCache = cfg;
                await window.refreshContextMenuStatus();
                updateProtectionLights(cfg);
                const timeoutInput = document.getElementById('interactive_timeout_input');
                if (timeoutInput) {
                    const parsed = parseInt(cfg.interactive_timeout, 10);
                    timeoutInput.value = Number.isFinite(parsed) ? Math.min(Math.max(parsed, 5), 300) : 30;
                }

                document.querySelectorAll('.toggle-switch input').forEach((toggle, index) => {
                    if (appState.firstLaunch) {
                        toggle.checked = false;
                        toggle.disabled = true;
                    } else if (toggle.dataset.configKey) {
                        toggle.checked = !!cfg[toggle.dataset.configKey];
                    }
                });
                syncInteractiveTimeoutState();
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
        document.querySelectorAll('.toggle-switch input').forEach(t => t.disabled = false);
        appState.firstLaunch = false;
        await window.refreshContextMenuStatus();
        syncInteractiveTimeoutState();
        if (appState.configCache) {
            updateProtectionLights(appState.configCache);
        }
    };
});
