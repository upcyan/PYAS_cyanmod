'use strict';
document.addEventListener('DOMContentLoaded', () => {
    const byId = id => document.getElementById(id);
    const allow = byId('threat_allow');
    const block = byId('threat_block');
    const permanent = byId('threat_permanent');
    const aiButton = byId('threat_ai');
    const fpButton = byId('threat_fp');
    const fpPanel = byId('threat_fp_panel');
    const repeat = byId('threat_repeat');
    const allButtons = [allow, block, permanent, aiButton, fpButton];
    const disable = () => allButtons.forEach(button => { button.disabled = true; });
    let confirmationId = null;
    let aiVerdict = '';
    let fpTexts = null;
    const hideFpPanel = () => fpPanel.classList.add('hidden');
    // AI 分析结果面板:仅分析结束后(就绪/失败)展示结论与建议动作;
    // 分析中由按钮流光承担,延迟启动期间也只显示按钮上的倒计时
    const renderAiResult = (ai, lang) => {
        const panel = byId('ai_result');
        if (!panel) return;
        if (!ai || !ai.label || ai.state === 'analyzing' || ai.state === 'delay') { panel.classList.add('hidden'); return; }
        const messages = window.AppI18n.dict[lang] || window.AppI18n.dict.english_switch;
        const ready = ai.state === 'ready';
        byId('ai_result_title').textContent = ready
            ? (messages.ai_result_title || 'AI 分析结果')
            : (messages.ai_result_failed || 'AI 分析不可用');
        const verdict = byId('ai_result_verdict');
        verdict.textContent = ai.label;
        verdict.className = 'ai-result-verdict ' + (ready ? (ai.verdict === 'block' ? 'verdict-block' : 'verdict-allow') : 'verdict-failed');
        const reason = byId('ai_result_reason');
        reason.textContent = ai.hint || '';
        reason.classList.toggle('hidden', !ai.hint);
        panel.classList.remove('hidden');
    };
    const openFpPanel = () => {
        if (!fpTexts || !currentId) return;
        byId('threat_fp_title').textContent = fpTexts.button;
        byId('threat_fp_identity').textContent = latestIdentity;
        byId('threat_fp_scope_this_text').textContent = fpTexts.scope_this;
        byId('threat_fp_scope_file_text').textContent = fpTexts.scope_file;
        byId('threat_fp_reason_label').textContent = fpTexts.reason;
        byId('threat_fp_reason').replaceChildren(...fpTexts.reasons.map(([value, label]) => {
            const option = document.createElement('option');
            option.value = value;
            option.textContent = label;
            return option;
        }));
        byId('threat_fp_note').value = '';
        byId('threat_fp_note').placeholder = fpTexts.note;
        byId('threat_fp_submit').textContent = fpTexts.submit;
        byId('threat_fp_cancel').textContent = fpTexts.cancel;
        fpPanel.classList.remove('hidden');
        byId('threat_fp_cancel').focus({ preventScroll: true });
    };
    const texts = {
        simplified_switch: ['永久允许', '重复确认越多，自动延长有效时间（60 秒起，最长 1 小时，累计最多 100 次，默认关闭）', '仅记住此防护、此完整路径、此 SHA-256 文件内容、此检测结果和此目标。文件变化后重新询问；不会放行目录或关闭扫描。可在设置中清除。确认永久允许？', '确认永久允许', '取消', '文件身份无法验证、已经变化或保存失败；未新增允许规则，请重新处理。', '无法确认文件身份或属于内存告警，不能记住决定。'],
        traditional_switch: ['永久允許', '重複確認越多，自動延長有效時間（60 秒起，最長 1 小時，累計最多 100 次，預設關閉）', '僅記住此防護、此完整路徑、此 SHA-256 檔案內容、此偵測結果與此目標。檔案變更後重新詢問；不放行目錄或關閉掃描。可在設定中清除。確認永久允許？', '確認永久允許', '取消', '無法驗證檔案身分、檔案已變更或儲存失敗；未新增允許規則。', '無法確認檔案身分或屬於記憶體告警，不能記住決定。'],
        english_switch: ['Always allow', 'Repeat this decision for identical alerts — the window grows with each confirmation (from 60s up to 1 hour, 100 uses max, off by default)', 'Remember only this protection, exact path, SHA-256 content, detection and target. Changed files will prompt again. Scanning stays enabled. Clear rules in Settings. Always allow?', 'Confirm always allow', 'Cancel', 'File identity changed, could not be verified, or saving failed. No allow rule added.', 'File identity cannot be verified or this is a memory alert. Decisions cannot be remembered.'],
    };
    let currentId = null;
    let busy = false;
    let initialized = false;
    let queueKey = '';
    let latestTheme = 'system_switch';
    let nextTimer;
    let revision = 0;
    let latestIdentity = '';

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
            if (!data) {
                // 告警已消失/被接管:立即停掉流光动效,避免残留「分析中」假象
                disable();
                aiButton.classList.remove('is-analyzing');
                aiButton.hidden = true;
                aiVerdict = '';
                byId('ai_result')?.classList.add('hidden');
                byId('threat_confirmation').classList.add('hidden');
                return;
            }
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
            const repeatHint = byId('threat_repeat_hint');
            if (repeatHint) {
                if (data.repeat_hint) {
                    repeatHint.textContent = data.repeat_hint;
                    repeatHint.classList.remove('hidden');
                } else {
                    repeatHint.classList.add('hidden');
                }
            }
            const procLine = byId('threat_process');
            if (procLine) {
                const proc = data.process;
                if (proc && proc.name) {
                    const label = data.process_label || 'Process';
                    procLine.textContent = `${label}: ${proc.name}`;
                    procLine.title = proc.path || '';
                    procLine.classList.remove('hidden');
                } else {
                    procLine.classList.add('hidden');
                }
            }
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
            // AI 建议第四按钮:分析中/失败置灰,仅就绪建议可点击;未启用则隐藏
            const ai = data.ai;
            const aiAnalyzing = !!ai && ai.state === 'analyzing';
            aiButton.classList.toggle('is-analyzing', aiAnalyzing);
            if (ai && ai.label) {
                aiButton.hidden = false;
                setText('threat_ai_label', ai.label);
                aiButton.title = ai.hint || '';
                aiVerdict = ai.state === 'ready' ? ai.verdict : '';
                aiButton.disabled = busy || !!data.resolving || !aiVerdict;
            } else {
                aiButton.hidden = true;
                aiButton.classList.remove('is-analyzing');
                aiVerdict = '';
                aiButton.disabled = true;
            }
            renderAiResult(ai, data.language);
            // 误报入口:仅文件类告警(有内容身份)显示
            const fp = data.fp;
            if (fp && fp.button) {
                fpButton.hidden = false;
                fpButton.textContent = fp.button;
                fpButton.disabled = busy || !!data.resolving;
                fpTexts = fp;
            } else {
                fpButton.hidden = true;
                fpTexts = null;
                hideFpPanel();
            }
            latestIdentity = data.identity_summary || '';
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
                hideFpPanel();
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
    aiButton.addEventListener('click', () => {
        // 只执行就绪的 AI 建议;失败/分析中点击无效,绝不隐式放行
        if (aiVerdict) decide(aiVerdict);
    });
    fpButton.addEventListener('click', openFpPanel);
    byId('threat_fp_cancel').addEventListener('click', hideFpPanel);
    byId('threat_fp_submit').addEventListener('click', async () => {
        if (busy || !currentId || fpPanel.classList.contains('hidden')) return;
        const scope = document.querySelector('input[name="fp_scope"]:checked')?.value || 'file_rule';
        const reason = byId('threat_fp_reason').value || 'other';
        const note = byId('threat_fp_note').value || '';
        busy = true;
        revision += 1;
        clearTimeout(nextTimer);
        disable();
        hideFpPanel();
        try { await window.pywebview.api.report_false_positive(currentId, reason, note, scope); }
        catch (error) { console.error('False positive report failed', error); }
        finally { busy = false; await refresh(); }
    });
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
