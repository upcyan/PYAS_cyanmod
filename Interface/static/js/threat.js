'use strict';
document.addEventListener('DOMContentLoaded', () => {
    const byId = id => document.getElementById(id);
    const allow = byId('threat_allow');
    const block = byId('threat_block');
    const permanent = byId('threat_permanent');
    const repeat = byId('threat_repeat');
    const allButtons = [allow, block, permanent];
    const disable = () => allButtons.forEach(button => { button.disabled = true; });
    let confirmationId = null;
    const texts = {
        simplified_switch: ['永久允许', '30 秒内对完全相同的告警重复此决定（最多 20 次，默认关闭）', '仅记住此防护、此完整路径、此 SHA-256 文件内容、此检测结果和此目标。文件变化后重新询问；不会放行目录或关闭扫描。可在设置中清除。确认永久允许？', '确认永久允许', '取消', '文件身份无法验证、已经变化或保存失败；未新增允许规则，请重新处理。', '无法确认文件身份或属于内存告警，不能记住决定。'],
        traditional_switch: ['永久允許', '30 秒內對完全相同的告警重複此決定（最多 20 次，預設關閉）', '僅記住此防護、此完整路徑、此 SHA-256 檔案內容、此偵測結果與此目標。檔案變更後重新詢問；不放行目錄或關閉掃描。可在設定中清除。確認永久允許？', '確認永久允許', '取消', '無法驗證檔案身分、檔案已變更或儲存失敗；未新增允許規則。', '無法確認檔案身分或屬於記憶體告警，不能記住決定。'],
        english_switch: ['Always allow', 'Repeat this decision for identical alerts for 30 seconds (up to 20 uses, off by default)', 'Remember only this protection, exact path, SHA-256 content, detection and target. Changed files will prompt again. Scanning stays enabled. Clear rules in Settings. Always allow?', 'Confirm always allow', 'Cancel', 'File identity changed, could not be verified, or saving failed. No allow rule added.', 'File identity cannot be verified or this is a memory alert. Decisions cannot be remembered.'],
    };
    let currentId = null;
    let busy = false;
    let initialized = false;
    let queueKey = '';
    let latestTheme = 'system_switch';
    let nextTimer;
    let revision = 0;

    const setText = (id, text) => {
        const element = byId(id);
        if (element.textContent !== text) element.textContent = text;
    };
    const refresh = async () => {
        clearTimeout(nextTimer);
        const requestRevision = ++revision;
        try {
            const api = window.pywebview?.api;
            if (!api) return;
            const data = await api.snapshot();
            if (requestRevision !== revision) return;
            if (!data) { disable(); byId('threat_confirmation').classList.add('hidden'); return; }
            const changed = currentId !== data.id;
            currentId = data.id;
            latestTheme = data.theme;
            if (document.body.dataset.appliedTheme !== latestTheme) {
                window.PyasTheme.apply(latestTheme);
                document.body.dataset.appliedTheme = latestTheme;
            }
            document.documentElement.lang = window.AppI18n.langMap[data.language] || 'en';
            document.documentElement.dir = data.language === 'arabic_switch' ? 'rtl' : 'ltr';
            const messages = window.AppI18n.dict[data.language] || window.AppI18n.dict.english_switch;
            const pendingLabel = messages.pending_threats || 'Pending alerts';
            setText('queue_heading', pendingLabel);
            setText('queue_count', String(data.count ?? data.events.length));
            setText('threat_title', data.title);
            setText('threat_message', data.message);
            const localized = texts[data.language] || texts.english_switch;
            let status = data.decision_error ? localized[5] : (data.remaining === null ? data.waiting : data.countdown);
            if (data.duplicates > 1) status += /^zh/.test(document.documentElement.lang)
                ? ` 此决定同时处理 ${data.duplicates} 个完全相同的重复告警。`
                : ` This decision covers ${data.duplicates} identical duplicate alerts.`;
            setText('threat_status', status);
            setText('threat_permanent', localized[0]);
            setText('threat_repeat_text', localized[1]);
            setText('threat_confirmation_text', `${localized[2]}\n${data.identity_summary || ''}`);
            setText('threat_confirm', localized[3]);
            setText('threat_cancel', localized[4]);
            allow.textContent = data.allow;
            block.textContent = data.block;
            allow.disabled = block.disabled = busy || !!data.resolving;
            permanent.disabled = repeat.disabled = busy || !!data.resolving || !data.can_remember;
            permanent.title = data.can_remember ? localized[2] : localized[6];
            if (!data.can_remember) repeat.checked = false;
            const key = JSON.stringify(data.events);
            if (key !== queueKey) {
                queueKey = key;
                byId('threat_queue_list').replaceChildren(...data.events.map((event, index) => {
                    const item = document.createElement('li');
                    item.textContent = `${event.title} · ${event.count ?? 1}`;
                    item.classList.toggle('active', event.active ?? (event.id === data.id));
                    if (event.active ?? (event.id === data.id)) item.setAttribute('aria-current', 'true');
                    return item;
                }));
            }
            if (changed) {
                repeat.checked = false;
                confirmationId = null;
                byId('threat_confirmation').classList.add('hidden');
                byId('threat_message').scrollTop = 0;
                block.focus({ preventScroll: true });
            }
            if (!initialized) { await api.ready(); initialized = true; }
        } catch (error) {
            console.error('Threat UI refresh failed', error);
            disable();
        } finally {
            if (requestRevision === revision) nextTimer = setTimeout(refresh, 400);
        }
    };
    const decide = async choice => {
        if (busy || !currentId) return;
        busy = true;
        revision += 1;
        clearTimeout(nextTimer);
        disable();
        byId('threat_confirmation').classList.add('hidden');
        try { await window.pywebview.api.decide(currentId, choice, choice !== 'permanent' && repeat.checked); }
        catch (error) { console.error('Threat decision failed', error); }
        finally { busy = false; await refresh(); }
    };
    allow.addEventListener('click', () => decide('allow'));
    block.addEventListener('click', () => decide('block'));
    permanent.addEventListener('click', () => {
        confirmationId = currentId;
        byId('threat_confirmation').classList.remove('hidden');
        byId('threat_cancel').focus();
    });
    byId('threat_cancel').addEventListener('click', () => {
        confirmationId = null;
        byId('threat_confirmation').classList.add('hidden');
        permanent.focus();
    });
    byId('threat_confirm').addEventListener('click', () => {
        if (confirmationId === currentId) decide('permanent');
    });
    const minimize = () => window.pywebview?.api.minimize().catch(console.error);
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape') { event.preventDefault(); minimize(); }
    });
    matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => window.PyasTheme.apply(latestTheme));
    refresh();
});
