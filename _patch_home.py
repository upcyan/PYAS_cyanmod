# -*- coding: utf-8 -*-
"""首页日志改独立轻量列表渲染 + 按钮字体自适应。"""
import io

# ============ 1. index.html: 日志容器换成独立列表 ============
path = 'Interface/templates/index.html'
with io.open(path, encoding='utf-8') as f:
    c = f.read()
old = '<div class="manage-widget home-log-widget"><ul class="manage-list"></ul></div>'
new = '<div class="home-log-widget"><ul class="home-log-list" id="home_log_list"></ul></div>'
assert c.count(old) == 1
c = c.replace(old, new)
with io.open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(c)
print('html 完成')

# ============ 2. style.css ============
path = 'Interface/static/css/style.css'
with io.open(path, encoding='utf-8') as f:
    c = f.read()

old = """#home_window .manage-list-item[data-level="BLOCK"] {
    border-left: 3px solid #ff3b30;
    cursor: pointer;
}

#home_window .manage-list-item[data-level="BLOCK"]:hover {
    background-color: var(--accent-alpha);
}

#home_window .manage-list-item[data-level="WARN"] {
    border-left: 3px solid #ff9500;
}

#home_window .manage-list-item[data-level="SCAN"] {
    border-left: 3px solid var(--accent-color);
}"""
new = ""
assert c.count(old) == 1, 'old table rules'
c = c.replace(old, new)

old = """.home-log-widget {
    flex: 1;
    min-height: 0;
}"""
new = """.home-log-widget {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
    border: 1px solid var(--border-color);
    border-radius: 12px;
    background-color: var(--bg-panel);
}

.home-log-list {
    list-style: none;
    margin: 0;
    padding: 0;
}

.home-log-item {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 9px 16px;
    border-bottom: 1px solid var(--border-color);
    font-size: 13px;
    color: var(--text-primary);
}

.home-log-item:last-child {
    border-bottom: none;
}

.home-log-item .hl-time {
    flex: 0 0 165px;
    color: var(--text-secondary);
    white-space: nowrap;
}

.home-log-item .hl-level {
    flex: 0 0 44px;
    font-weight: 600;
}

.home-log-item .hl-action {
    flex: 0 0 120px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

.home-log-item .hl-source {
    flex: 1;
    min-width: 0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    color: var(--text-secondary);
}

.home-log-item.lv-BLOCK {
    border-left: 3px solid #ff3b30;
    cursor: pointer;
}

.home-log-item.lv-BLOCK .hl-level {
    color: #ff3b30;
}

.home-log-item.lv-BLOCK:hover {
    background-color: var(--accent-alpha);
}

.home-log-item.lv-WARN {
    border-left: 3px solid #ff9500;
}

.home-log-item.lv-WARN .hl-level {
    color: #ff9500;
}

.home-log-item.lv-SCAN {
    border-left: 3px solid var(--accent-color);
}

.home-log-empty {
    display: flex;
    align-items: center;
    justify-content: center;
    height: 120px;
    color: var(--text-secondary);
    font-size: 13px;
}

.quick-actions-row {
    container-type: inline-size;
}

@container (max-width: 560px) {
    .quick-item {
        padding: 10px 12px;
        gap: 10px;
    }

    .quick-item .item-icon {
        width: 26px;
        height: 26px;
        flex: 0 0 26px;
    }

    .quick-item .item-info h2 {
        font-size: 13px;
    }

    .quick-item .icon-action-btn {
        width: 20px;
        height: 20px;
    }

    .quick-item .icon-action-btn svg {
        width: 14px;
        height: 14px;
    }
}

@container (max-width: 430px) {
    .quick-item .item-info h2 {
        font-size: 11px;
    }

    .quick-item .icon-action-btn {
        display: none;
    }
}

.home-log-widget::-webkit-scrollbar { width: 6px; height: 6px; }
.home-log-widget::-webkit-scrollbar-track { background: transparent; }
.home-log-widget::-webkit-scrollbar-thumb { background-color: transparent; border-radius: 10px; }
.home-log-widget:hover::-webkit-scrollbar-thumb { background-color: rgba(134, 134, 139, 0.4); }
.home-log-widget::-webkit-scrollbar-thumb:hover { background-color: rgba(134, 134, 139, 0.75); }"""
assert c.count(old) == 1, 'css'
c = c.replace(old, new)
with io.open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(c)
print('style.css 完成')

# ============ 3. main.js: 独立渲染替换共享表格 ============
path = 'Interface/static/js/main.js'
with io.open(path, encoding='utf-8') as f:
    c = f.read()

old = """    let homeLogDirty = false;

    const renderHomeLogs = () => {
        homeLogDirty = false;
        const widget = document.querySelector('#home_window .manage-widget');
        if (!widget || !widget.gridState) return;
        if (!document.getElementById('home_window')?.classList.contains('active')) {
            homeLogDirty = true;
            return;
        }
        const data = (homeLogFilter === 'all' ? homeLogs : homeLogs.filter(l => l.level === homeLogFilter)).slice(-200);
        const dir = widget.gridState.sortAsc ? 1 : -1;
        data.sort((a, b) => dir * String(a.time_str || '').localeCompare(String(b.time_str || '')));
        renderDataGrid('#home_window', data, cols.log, 'id', false);
    };"""
new = """    let homeLogDirty = false;
    let homeLogSortDesc = true;

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
            listUl.innerHTML = '<li class="home-log-empty">' + escapeHtml(getMsg('changelog_empty')) + '</li>';
            return;
        }

        listUl.innerHTML = data.map(e => {
            const lv = String(e.level || '');
            const actionRaw = String(e.action || '');
            const actionText = getMsg(actionRaw) !== actionRaw ? getMsg(actionRaw) : actionRaw;
            const attrs = lv === 'BLOCK'
                ? ' data-action="' + escapeHtml(actionRaw) + '" data-pid="' + escapeHtml(String(e.pid ?? '')) + '" data-path="' + escapeHtml(String(e.source || '')) + '"'
                : '';
            return '<li class="home-log-item lv-' + escapeHtml(lv) + '"' + attrs + '>'
                + '<span class="hl-time">' + escapeHtml(e.time_str || '') + '</span>'
                + '<span class="hl-level">' + escapeHtml(getMsg(lv) || lv) + '</span>'
                + '<span class="hl-action">' + escapeHtml(actionText) + '</span>'
                + '<span class="hl-source" title="' + escapeHtml(String(e.source || '')) + '">' + escapeHtml(String(e.source || '')) + '</span>'
                + '</li>';
        }).join('');
    };"""
assert c.count(old) == 1, 'renderHomeLogs'
c = c.replace(old, new)

old = """    document.getElementById('home_log_sort')?.addEventListener('click', () => {
        const widget = document.querySelector('#home_window .manage-widget');
        if (!widget?.gridState) return;
        widget.gridState.sortKey = 'time_str';
        widget.gridState.sortAsc = !widget.gridState.sortAsc;
        const arrow = widget.gridState.sortAsc ? '↑' : '↓';
        const btn = document.getElementById('home_log_sort');
        if (btn) btn.innerHTML = `${arrow}&nbsp;<span data-i18n="col_date">${getMsg('col_date')}</span>`;
        widget.buildHeader();
        widget.renderData(widget.gridState.filterText, false);
    });"""
new = """    document.getElementById('home_log_sort')?.addEventListener('click', () => {
        homeLogSortDesc = !homeLogSortDesc;
        const btn = document.getElementById('home_log_sort');
        if (btn) {
            const arrow = homeLogSortDesc ? '↓' : '↑';
            btn.innerHTML = arrow + '&nbsp;<span data-i18n="col_date">' + getMsg('col_date') + '</span>';
        }
        renderHomeLogs();
    });"""
assert c.count(old) == 1, 'sort-btn'
c = c.replace(old, new)

old = """    document.querySelector('#home_window .manage-list')?.addEventListener('click', (e) => {
        const li = e.target.closest('.manage-list-item');
        if (!li || li.dataset.level !== 'BLOCK') return;
        if (e.target.tagName === 'INPUT') return;

        const action = li.dataset.action || '';
        const pid = li.dataset.pid || '';
        const path = li.querySelector('input')?.dataset.path || '';"""
new = """    document.getElementById('home_log_list')?.addEventListener('click', (e) => {
        const li = e.target.closest('.home-log-item');
        if (!li || !li.classList.contains('lv-BLOCK')) return;

        const action = li.dataset.action || '';
        const pid = li.dataset.pid || '';
        const path = li.dataset.path || '';"""
assert c.count(old) == 1, 'row-click'
c = c.replace(old, new)

with io.open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(c)
print('main.js 完成')
