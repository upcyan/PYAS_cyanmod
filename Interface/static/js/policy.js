/* Administrator policy setup is explicit; status reads never replay a write. */
document.addEventListener('DOMContentLoaded', () => {
    const copy = {
        en: { title: 'Administrator security policy', missing: 'No trusted policy is initialized. Review defaults or the old settings before authorizing them.',
            pending: 'Waiting for administrator authorization or policy commit…', restart: 'Policy saved. PYAS must restart before it applies.',
            restartNow: 'Restart now', restarting: 'Restarting…',
            restartFailed: 'Restart failed. Close and reopen PYAS manually.',
            failed: 'Policy authorization or saving failed. No automatic retry was sent.', unknown: 'The commit result is unknown. Restart and check the policy before making more changes.',
            defaults: 'Review default policy', legacy: 'Review old settings', review: 'Review all security settings before saving.',
            warning: 'Old settings were user-writable and are not automatically trusted.', confirm: 'I have reviewed these settings', approve: 'Authorize and save', cancel: 'Cancel',
            unavailable: 'No valid settings are available to import.', cancelled: 'Administrator authorization was cancelled.' },
        zh: { title: '管理员安全策略', missing: '尚未初始化可信策略。请审核默认设置或旧配置，再由管理员授权保存。',
            pending: '正在等待管理员授权或确认保存结果…', restart: '策略已保存，需要重新启动 PYAS 后生效。',
            restartNow: '立即重新启动', restarting: '正在重新启动…',
            restartFailed: '重新启动失败，请手动关闭并重新打开 PYAS。',
            failed: '策略授权或保存失败，未自动重试。', unknown: '保存结果尚无法确认，请重新启动并核对策略后再操作。',
            defaults: '审核默认策略', legacy: '审核旧配置', review: '请逐项核对安全设置后再授权保存。',
            warning: '旧配置曾允许普通用户修改，不会被自动信任。', confirm: '我已审核以上设置', approve: '授权并保存', cancel: '取消',
            unavailable: '没有可导入的有效配置。', cancelled: '已取消管理员授权，未提交策略。' },
        tw: { title: '管理員安全策略', missing: '尚未初始化可信策略。請審核預設設定或舊配置，再由管理員授權儲存。',
            pending: '正在等待管理員授權或確認儲存結果…', restart: '策略已儲存，需要重新啟動 PYAS 後生效。',
            restartNow: '立即重新啟動', restarting: '正在重新啟動…',
            restartFailed: '重新啟動失敗，請手動關閉並重新開啟 PYAS。',
            failed: '策略授權或儲存失敗，未自動重試。', unknown: '儲存結果尚無法確認，請重新啟動並核對策略後再操作。',
            defaults: '審核預設策略', legacy: '審核舊配置', review: '請逐項核對安全設定後再授權儲存。',
            warning: '舊配置曾允許普通使用者修改，不會被自動信任。', confirm: '我已審核以上設定', approve: '授權並儲存', cancel: '取消',
            unavailable: '沒有可匯入的有效配置。', cancelled: '已取消管理員授權，未提交策略。' },
    };
    const texts = () => /^zh/i.test(document.documentElement.lang)
        ? (/TW|HK|Hant/i.test(document.documentElement.lang) ? copy.tw : copy.zh) : copy.en;
    const panel = document.createElement('aside');
    panel.id = 'policy_status_panel'; panel.className = 'policy-status-panel hidden'; panel.setAttribute('role', 'status');
    const heading = document.createElement('strong'), message = document.createElement('p');
    message.id = 'policy_status_text';
    const actions = document.createElement('div'); actions.className = 'policy-status-actions';
    const defaults = document.createElement('button'), legacy = document.createElement('button');
    const restart = document.createElement('button');
    defaults.id = 'policy_initialize_btn'; legacy.id = 'policy_migrate_btn';
    restart.id = 'policy_restart_btn';
    for (const button of [defaults, legacy, restart]) { button.type = 'button'; button.className = 'action-btn modern-btn'; }
    restart.classList.add('hidden');
    actions.append(defaults, legacy, restart);
    panel.append(heading, message, actions); document.body.appendChild(panel);
    let active = true, epoch = 0, flight = null, status = null, busy = false, notice = '', restarting = false;
    const disabled = new Map();
    const userKeys = new Set(['driver_alert_exempt', 'driver_home_hidden', 'dnd_switch']);
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
        // A saved policy is only read at startup, so this state offers exactly
        // one action: confirm and restart. Nothing else can move it forward.
        const needsRestart = value.state === 'restart_required';
        let text = !value.initialized ? t.missing : t.failed;
        if (waiting) text = t.pending;
        else if (needsRestart) text = t.restart;
        else if (value.state === 'commit_unknown') text = t.unknown;
        else if (value.error) text = t.failed + ' ' + String(value.error);
        if (restarting) text = t.restarting;
        else if (notice) text = notice;
        if (message.textContent !== text) message.textContent = text;
        defaults.textContent = t.defaults; legacy.textContent = t.legacy;
        defaults.classList.toggle('hidden', needsRestart);
        legacy.classList.toggle('hidden', needsRestart);
        restart.classList.toggle('hidden', !needsRestart);
        restart.textContent = restarting ? t.restarting : t.restartNow;
        restart.disabled = restarting;
        const showActions = needsRestart || (!value.initialized && !waiting && value.state !== 'commit_unknown');
        actions.classList.toggle('hidden', !showActions);
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
        approve.addEventListener('click', () => {
            if (approve.disabled || !confirm.checked) return;
            accepted = true; dialog.close();
        });
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
            else {
                const state = result?.state || status?.state || 'commit_failed';
                const detail = result?.detail || status?.error || result?.error || '';
                notice = result?.cancelled ? texts().cancelled : '';
                render({state, initialized: false, error: String(detail)});
            }
        } catch (error) {
            if (view === epoch && active) notice = texts().failed;
        } finally { busy = false; if (status) render(status); refresh(); }
    };
    // Reached two ways: the backend reports that shutdown was refused, or the
    // guard below expires because this page is still alive long after a restart
    // should have destroyed it. Either way the button must not stay stuck off.
    const restartFailed = () => {
        restarting = false; notice = texts().restartFailed;
        render({ state: 'restart_required', initialized: true });
    };
    window.pyasPolicyRestartFailed = restartFailed;
    defaults.addEventListener('click', () => setup(false));
    legacy.addEventListener('click', () => setup(true));
    restart.addEventListener('click', () => {
        if (restarting) return;
        // The only action this state offers: confirm and restart. It stays
        // disabled while the process tears down, so it cannot be pressed twice.
        restarting = true; notice = '';
        render({ state: 'restart_required', initialized: true });
        setTimeout(() => { if (restarting) restartFailed(); }, 25000);
        // 新策略里的防护开关(进程溯源/行为防护)需要管理员令牌,重启必须提权;
        // 旧后端没有该方法时退回同级重启
        Promise.resolve()
            .then(() => api()?.restart_to_apply_policy?.() ?? api()?.restart_application?.())
            .then(result => {
                if (result === true) return;   // the launcher takes over after this process exits
                restartFailed();
            }).catch(restartFailed);
    });
    // 首次安装只主动弹一次:策略未初始化时自动打开审核对话框,把需要提权的
    // 默认防护(进程溯源/行为防护)一次性交给用户授权;取消后本次安装不再打扰
    if (!localStorage.getItem('pyas_policy_offer_shown')) {
        localStorage.setItem('pyas_policy_offer_shown', '1');
        const offerOnce = () => {
            if (status && !status.initialized && status.state === 'not_initialized') setup(false);
        };
        setTimeout(offerOnce, 1200);
    }
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
