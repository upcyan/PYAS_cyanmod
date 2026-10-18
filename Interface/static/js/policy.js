/* Administrator policy setup is explicit; status reads never replay a write. */
document.addEventListener('DOMContentLoaded', () => {
    const copy = {
        en: { title: 'Administrator security policy', missing: 'No trusted policy is initialized. Review defaults or the old settings before authorizing them.',
            pending: 'Waiting for administrator authorization or policy commit…', restart: 'Policy saved. Restart PYAS to apply it; protections are not shown as active before they start.',
            failed: 'Policy authorization or saving failed. No automatic retry was sent.', unknown: 'The commit result is unknown. Restart and check the policy before making more changes.',
            defaults: 'Review default policy', legacy: 'Review old settings', review: 'Review all security settings before saving.',
            warning: 'Old settings were user-writable and are not automatically trusted.', confirm: 'I have reviewed these settings', approve: 'Authorize and save', cancel: 'Cancel',
            unavailable: 'No valid settings are available to import.', cancelled: 'Authorization was cancelled or could not be confirmed.' },
        zh: { title: '管理员安全策略', missing: '尚未初始化可信策略。请审核默认设置或旧配置，再由管理员授权保存。',
            pending: '正在等待管理员授权或确认保存结果…', restart: '策略已保存，请重新启动 PYAS 后应用；尚未启动的防护不会显示为已开启。',
            failed: '策略授权或保存失败，未自动重试。', unknown: '保存结果尚无法确认，请重新启动并核对策略后再操作。',
            defaults: '审核默认策略', legacy: '审核旧配置', review: '请逐项核对安全设置后再授权保存。',
            warning: '旧配置曾允许普通用户修改，不会被自动信任。', confirm: '我已审核以上设置', approve: '授权并保存', cancel: '取消',
            unavailable: '没有可导入的有效配置。', cancelled: '授权已取消，或无法确认保存结果。' },
        tw: { title: '管理員安全策略', missing: '尚未初始化可信策略。請審核預設設定或舊配置，再由管理員授權儲存。',
            pending: '正在等待管理員授權或確認儲存結果…', restart: '策略已儲存，請重新啟動 PYAS 後套用；尚未啟動的防護不會顯示為已開啟。',
            failed: '策略授權或儲存失敗，未自動重試。', unknown: '儲存結果尚無法確認，請重新啟動並核對策略後再操作。',
            defaults: '審核預設策略', legacy: '審核舊配置', review: '請逐項核對安全設定後再授權儲存。',
            warning: '舊配置曾允許普通使用者修改，不會被自動信任。', confirm: '我已審核以上設定', approve: '授權並儲存', cancel: '取消',
            unavailable: '沒有可匯入的有效配置。', cancelled: '授權已取消，或無法確認儲存結果。' },
    };
    const texts = () => /^zh/i.test(document.documentElement.lang)
        ? (/TW|HK|Hant/i.test(document.documentElement.lang) ? copy.tw : copy.zh) : copy.en;
    const panel = document.createElement('aside');
    panel.id = 'policy_status_panel'; panel.className = 'policy-status-panel hidden'; panel.setAttribute('role', 'status');
    const heading = document.createElement('strong'), message = document.createElement('p');
    message.id = 'policy_status_text';
    const actions = document.createElement('div'); actions.className = 'policy-status-actions';
    const defaults = document.createElement('button'), legacy = document.createElement('button');
    defaults.id = 'policy_initialize_btn'; legacy.id = 'policy_migrate_btn';
    for (const button of [defaults, legacy]) { button.type = 'button'; button.className = 'action-btn modern-btn'; actions.appendChild(button); }
    panel.append(heading, message, actions); document.body.appendChild(panel);
    let active = true, epoch = 0, flight = null, status = null, busy = false, notice = '';
    const disabled = new Map();
    const userKeys = new Set(['driver_alert_exempt', 'dnd_switch']);
    const api = () => window.pywebview?.api;
    const updateControls = blocked => {
        for (const element of document.querySelectorAll('[data-config-key]')) {
            if (userKeys.has(element.dataset.configKey)) continue;
            if (blocked) { if (!disabled.has(element)) disabled.set(element, element.disabled); element.disabled = true; }
        }
        if (!blocked) {
            for (const [element, previous] of disabled) {
                if (!element.dataset.pending) element.disabled = previous;
            }
            disabled.clear();
        }
    };
    const render = value => {
        if (!value || typeof value.state !== 'string') return;
        status = value;
        const t = texts();
        const waiting = busy || ['authorizing', 'applying'].includes(value.state);
        const blocked = waiting || !value.initialized || ['restart_required', 'commit_unknown', 'unavailable'].includes(value.state);
        updateControls(blocked);
        const visible = waiting || value.state !== 'ready' || !!value.error;
        panel.classList.toggle('hidden', !visible);
        heading.textContent = t.title;
        let text = !value.initialized ? t.missing : t.failed;
        if (waiting) text = t.pending;
        else if (value.state === 'restart_required') text = t.restart;
        else if (value.state === 'commit_unknown') text = t.unknown;
        else if (value.error) text = t.failed + ' ' + String(value.error);
        if (notice && !waiting && value.state !== 'restart_required') text = notice;
        if (message.textContent !== text) message.textContent = text;
        defaults.textContent = t.defaults; legacy.textContent = t.legacy;
        actions.classList.toggle('hidden', value.initialized || waiting);
        defaults.disabled = legacy.disabled = waiting;
    };
    const refresh = () => {
        const bridge = api();
        if (!active || typeof bridge?.get_policy_status !== 'function') return;
        if (flight && flight.bridge === bridge) return;
        const ticket = { bridge, epoch }; flight = ticket;
        Promise.resolve().then(() => bridge.get_policy_status()).then(value => {
            if (active && ticket.epoch === epoch && flight === ticket) render(value);
        }).catch(() => {}).finally(() => { if (flight === ticket) flight = null; });
    };
    const review = (values, old) => new Promise(resolve => {
        const t = texts(), dialog = document.createElement('dialog');
        dialog.className = 'policy-review-dialog'; dialog.id = 'policy_review_dialog';
        const title = document.createElement('h2'); title.textContent = t.title;
        const notice = document.createElement('p'); notice.textContent = old ? t.warning + ' ' + t.review : t.review;
        const pre = document.createElement('pre'); pre.id = 'policy_review_values'; pre.textContent = JSON.stringify(values, null, 2);
        const label = document.createElement('label'), confirm = document.createElement('input');
        confirm.type = 'checkbox'; confirm.id = 'policy_review_confirm'; label.append(confirm, document.createTextNode(t.confirm));
        const approve = document.createElement('button'), cancel = document.createElement('button');
        approve.id = 'policy_review_approve'; approve.textContent = t.approve; approve.disabled = true;
        cancel.id = 'policy_review_cancel'; cancel.textContent = t.cancel;
        for (const button of [approve, cancel]) { button.type = 'button'; button.className = 'action-btn modern-btn'; }
        confirm.addEventListener('change', () => { approve.disabled = !confirm.checked; });
        let accepted = false;
        approve.addEventListener('click', () => { accepted = true; dialog.close(); });
        cancel.addEventListener('click', () => dialog.close());
        dialog.addEventListener('close', () => { dialog.remove(); resolve(accepted); }, { once: true });
        const row = document.createElement('div'); row.className = 'policy-status-actions'; row.append(cancel, approve);
        dialog.append(title, notice, pre, label, row); document.body.appendChild(dialog); dialog.showModal();
    });
    const setup = async old => {
        if (busy || status?.initialized || !active) return;
        const bridge = api(), view = epoch;
        if (!bridge) return;
        notice = ''; busy = true; render(status || { state: 'not_initialized', initialized: false });
        try {
            const preview = await (old ? bridge.get_policy_migration_preview() : bridge.get_policy_defaults_preview());
            if (view !== epoch || !active) return;
            if (!preview?.available) { notice = texts().unavailable; return; }
            busy = false; render(status);
            if (!await review(preview.values, old) || view !== epoch || !active) return;
            busy = true; render(status);
            const result = await bridge.initialize_security_policy(old, preview.digest || null);
            if (view !== epoch || !active) return;
            epoch++; // invalidate status reads captured before this write completed
            if (result?.ok) render({ state: 'restart_required', initialized: true });
            else notice = texts().cancelled;
        } catch (error) {
            if (view === epoch && active) notice = texts().failed;
        } finally { busy = false; if (status) render(status); refresh(); }
    };
    defaults.addEventListener('click', () => setup(false));
    legacy.addEventListener('click', () => setup(true));
    window.addEventListener('pywebviewready', refresh);
    window.addEventListener('pyas-policy-refresh', refresh);
    let timer = setInterval(refresh, 1000);
    window.addEventListener('pagehide', () => {
        active = false; epoch++; clearInterval(timer);
        document.getElementById('policy_review_dialog')?.close();
    });
    window.addEventListener('pageshow', () => { active = true; epoch++; clearInterval(timer); timer = setInterval(refresh, 1000); refresh(); });
    refresh();
});
