'use strict';
document.addEventListener('DOMContentLoaded', () => {
    const byId = id => document.getElementById(id);
    const allow = byId('threat_allow');
    const block = byId('threat_block');
    const permanent = byId('threat_permanent');
    const glow = byId('ai_window_glow');
    const fpButton = byId('threat_fp');
    const fpPanel = byId('threat_fp_panel');
    const repeat = byId('threat_repeat');
    const allButtons = [allow, block, permanent, fpButton];
    const disable = () => {
        allButtons.forEach(button => { button.disabled = true; });
        repeat.disabled = true;
        glow.classList.remove('is-analyzing');
    };
    const BRIDGE_TIMEOUT_MS = 5000;
    const bridgeWaits = new Set();
    const bridgeError = code => Object.assign(new Error(code), { code });
    const waitForBridge = promise => new Promise((resolve, reject) => {
        let settled = false;
        let timer;
        const finish = (callback, value) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            bridgeWaits.delete(cancel);
            callback(value);
        };
        const cancel = () => finish(reject, bridgeError('BRIDGE_CANCELLED'));
        timer = setTimeout(() => finish(reject, bridgeError('BRIDGE_TIMEOUT')), BRIDGE_TIMEOUT_MS);
        bridgeWaits.add(cancel);
        Promise.resolve(promise).then(value => finish(resolve, value), error => finish(reject, error));
    });
    let snapshotFlight = null;
    const readSnapshot = async api => {
        // Reuse one stalled call rather than creating another native thread every poll.
        if (snapshotFlight?.api === api && snapshotFlight.expired) {
            if (!snapshotFlight.settled) throw Object.assign(bridgeError('BRIDGE_TIMEOUT'), { deferred: true });
            snapshotFlight = null;  // Discard a late snapshot; obtain current server state.
        }
        if (!snapshotFlight || snapshotFlight.api !== api) {
            const flight = { api, settled: false, expired: false };
            flight.promise = Promise.resolve().then(() => api.snapshot());
            flight.promise.then(() => { flight.settled = true; }, () => { flight.settled = true; });
            snapshotFlight = flight;
        }
        const flight = snapshotFlight;
        try {
            const data = await waitForBridge(flight.promise);
            if (snapshotFlight === flight) snapshotFlight = null;
            if (flight.expired) throw bridgeError('BRIDGE_EXPIRED');
            return data;
        } catch (error) {
            if (error.code === 'BRIDGE_TIMEOUT') flight.expired = true;
            else if (snapshotFlight === flight) snapshotFlight = null;
            throw error;
        }
    };
    const decisionText = kind => {
        const labels = {
            simplified_switch: { timeout: '操作响应超时，未自动重试；请核对当前告警后再选择。', pending: '正在处理此决定，请勿重复提交。' },
            traditional_switch: { timeout: '操作回應逾時，未自動重試；請核對目前告警後再選擇。', pending: '正在處理此決定，請勿重複提交。' },
            english_switch: { timeout: 'The response timed out. No automatic retry was sent; check the current alert before deciding again.', pending: 'Processing this decision. Do not submit it again.' },
        };
        return (labels[latestLanguage] || labels.english_switch)[kind];
    };
    let actionRevision = 0;
    let decisionTimeoutId = null;
    let confirmationId = null;
    let fpTexts = null;
    const hideFpPanel = () => fpPanel.classList.add('hidden');
    const message = (lang, key) => window.AppI18n.dict[lang]?.[key]
        || window.AppI18n.dict.english_switch[key] || key;
    // AI is advice, not a second detector. Only actual in-flight analysis lights the window.
    const renderAiResult = (ai, lang, resolving = false) => {
        const panel = byId('ai_result');
        const visible = !!ai?.label;
        glow.classList.toggle('is-analyzing', visible && ai.state === 'analyzing' && !busy && !resolving);
        panel.classList.toggle('hidden', !visible);
        if (!visible) {
            setText('ai_result_verdict', '');
            setText('ai_result_reason', '');
            return;
        }
        const ready = ai.state === 'ready' && ['allow', 'block'].includes(ai.verdict);
        setText('ai_result_title', message(lang, 'evidence_ai_title'));
        setText('ai_result_verdict', ai.label);
        byId('ai_result_verdict').className = 'ai-result-verdict ' + (ready
            ? (ai.verdict === 'block' ? 'verdict-block' : 'verdict-allow') : 'verdict-failed');
        setText('ai_result_reason', ai.hint || '');
        byId('ai_result_reason').classList.toggle('hidden', !ai.hint);
        setText('ai_result_note', message(lang, 'evidence_ai_note'));
    };
    const renderEvidence = (data, lang) => {
        const e = data?.evidence || {};
        const unknown = message(lang, 'evidence_unknown');
        const labels = { evidence_heading: 'evidence_title', evidence_score_label: 'evidence_score',
            evidence_category_label: 'evidence_category', evidence_engine_label: 'evidence_engine',
            evidence_platform_label: 'evidence_platform', evidence_family_label: 'evidence_family',
            evidence_raw_label: 'evidence_raw', evidence_rules_label: 'evidence_rules',
            evidence_file_label: 'evidence_file', evidence_hash_label: 'evidence_hash',
            evidence_event_label: 'evidence_event' };
        for (const [id, key] of Object.entries(labels)) setText(id, message(lang, key));
        const scored = typeof e.score === 'number' && Number.isFinite(e.score) && e.score >= 0 && e.score <= 100
            && ((e.engine === 'ml' && e.score_kind === 'model_probability')
                || (e.engine === 'cl' && e.score_kind === 'cloud_score'));
        const ruleMatch = ['yr', 'ym'].includes(e.engine) && e.score_kind === 'rule_match';
        setText('threat_score', scored ? String(e.score) : message(lang, ruleMatch ? 'evidence_rule_match' : 'evidence_not_scored'));
        byId('threat_score_scale').hidden = !scored;
        byId('threat_score').parentElement.classList.toggle('is-unscored', !scored);
        const track = byId('threat_score_track');
        track.hidden = !scored;
        track.setAttribute('aria-label', message(lang, 'evidence_score'));
        if (scored) track.setAttribute('aria-valuenow', String(e.score));
        else track.removeAttribute('aria-valuenow');
        byId('threat_score_fill').style.width = scored ? String(e.score) + '%' : '0%';
        const engineKeys = { ml: 'evidence_ml', yr: 'evidence_yara', ym: 'evidence_yara_memory',
            cl: 'evidence_cloud', network: 'evidence_network' };
        setText('threat_engine', engineKeys[e.engine] ? message(lang, engineKeys[e.engine]) : unknown);
        const categoryKey = e.category ? 'evidence_category_' + e.category : '';
        const category = window.AppI18n.dict[lang]?.[categoryKey] || window.AppI18n.dict.english_switch[categoryKey];
        setText('threat_category', category || e.category || unknown);
        setText('threat_platform', e.platform || unknown);
        setText('threat_family', e.generic ? message(lang, 'evidence_generic') : (e.family || unknown));
        setText('threat_raw_label', e.raw_label || unknown);
        // 空态时把 dd 折成一行(label 用 ::before 内联),有真实值时恢复上下堆叠
        for (const id of ['threat_category', 'threat_engine', 'threat_platform', 'threat_family']) {
            const dd = byId(id);
            const label = document.getElementById(id.replace('threat_', 'evidence_') + '_label');
            const raw = (dd.textContent || '').trim();
            const empty = !raw || raw === unknown || raw === '—';
            dd.classList.toggle('is-empty', empty);
            if (empty && label) dd.setAttribute('data-label', label.textContent);
            else dd.removeAttribute('data-label');
        }
        const rules = Array.isArray(e.rules) ? e.rules : [];
        byId('threat_rules_row').hidden = !rules.length;
        setText('threat_rules', rules.join(' · '));
        byId('threat_rule_description').hidden = !e.description;
        setText('threat_rule_description', e.description || '');
        setText('threat_score_note', message(lang, ruleMatch ? 'evidence_rule_note'
            : scored ? (e.engine === 'ml' ? 'evidence_ml_note' : 'evidence_cloud_note') : 'evidence_unknown_note'));
        const file = data?.file || {};
        byId('threat_file').classList.toggle('hidden', !file.path);
        setText('threat_file_name', file.name || '');
        setText('threat_file_path', file.path || '');
        setText('threat_file_hash', file.sha256 || unknown);
        setText('threat_context', data?.summary || '');
    };
    const openFpPanel = () => {
        if (!fpTexts || !currentId) return;
        byId('threat_fp_title').textContent = fpTexts.button;
        byId('threat_fp_identity').textContent = latestIdentity;
        byId('threat_fp_scope_this_text').textContent = fpTexts.scope_this;
        byId('threat_fp_scope_file_text').textContent = fpTexts.scope_file;
        const signerWrap = byId('threat_fp_scope_signer_wrap');
        if (fpTexts.scope_signer) {
            byId('threat_fp_scope_signer_text').textContent = fpTexts.scope_signer;
            signerWrap.hidden = false;
        } else {
            signerWrap.hidden = true;
        }
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
        english_switch: ['Always allow', 'Repeat this decision for identical alerts — window grows with each confirmation (60s base, up to 1 hour, 100 uses max, off by default)', 'Remember only this protection, exact path, SHA-256 content, detection and target. Changed files will prompt again. Scanning stays enabled. Clear rules in Settings. Always allow?', 'Confirm always allow', 'Cancel', 'File identity changed, could not be verified, or saving failed. No allow rule added.', 'File identity cannot be verified or this is a memory alert. Decisions cannot be remembered.'],
        japanese_switch: ['常に許可', '同一アラートに対し決定を繰り返します（60秒〜最長1時間、最大100回、既定はオフ）。確認回数が増えるほど有効時間が延びます', 'この保護・完全なパス・SHA-256内容・検出・対象のみ記憶します。ファイルが変われば再確認します。ディレクトリの許可やスキャン停止はしません。設定で削除できます。常に許可しますか？', '常に許可を確認', 'キャンセル', 'ファイルの身元を検証できないか、変更または保存に失敗しました。許可ルールは追加されていません。', 'ファイルの身元を確認できないかメモリ警告のため、決定を記憶できません。'],
        korean_switch: ['항상 허용', '동일한 경고에 대해 이 결정을 반복합니다(60초~최대 1시간, 최대 100회, 기본값 꺼짐). 반복할수록 유효 시간이 늘어납니다', '이 보호, 전체 경로, SHA-256 내용, 탐지, 대상만 기억합니다. 파일이 변경되면 다시 묻습니다. 디렉터리 허용이나 검사 중지는 하지 않습니다. 설정에서 삭제할 수 있습니다. 항상 허용할까요?', '항상 허용 확인', '취소', '파일 신원을 확인할 수 없거나 변경·저장에 실패했습니다. 허용 규칙이 추가되지 않았습니다.', '파일 신원을 확인할 수 없거나 메모리 경고이므로 결정을 기억할 수 없습니다.'],
        french_switch: ['Toujours autoriser', 'Répéter cette décision pour des alertes identiques — la fenêtre s’allonge à chaque confirmation (60 s de base, jusqu’à 1 h, 100 fois max, désactivé par défaut)', 'Seuls cette protection, ce chemin exact, ce contenu SHA-256, cette détection et cette cible sont mémorisés. Les fichiers modifiés redemanderont. Aucun dossier autorisé, scan jamais désactivé. Supprimable dans les réglages. Toujours autoriser ?', 'Confirmer l’autorisation', 'Annuler', 'Identité du fichier invérifiable, modifiée ou échec d’enregistrement ; aucune règle ajoutée.', 'Identité invérifiable ou alerte mémoire : la décision ne peut pas être mémorisée.'],
        spanish_switch: ['Permitir siempre', 'Repetir esta decisión ante alertas idénticas: la ventana crece con cada confirmación (60 s de base, hasta 1 h, máx. 100 usos, desactivado por defecto)', 'Solo se recuerdan esta protección, esta ruta exacta, este contenido SHA-256, esta detección y este destino. Los archivos modificados volverán a preguntar. No se permiten directorios ni se desactiva el análisis. Se puede borrar en Ajustes. ¿Permitir siempre?', 'Confirmar permiso', 'Cancelar', 'No se pudo verificar la identidad del archivo, cambió o falló el guardado; no se añadió regla.', 'No se puede verificar la identidad o es una alerta de memoria; no se puede recordar la decisión.'],
        hindi_switch: ['सदा अनुमति दें', 'समान चेतावनियों के लिए यह निर्णय दोहराएँ — हर पुष्टि के साथ वैधता बढ़ती है (60 सेकंड से अधिकतम 1 घंटे तक, अधिकतम 100 बार, डिफ़ॉल्ट रूप से बंद)', 'केवल यह सुरक्षा, पूर्ण पथ, SHA-256 सामग्री, पहचान और लक्ष्य याद रखा जाता है। फ़ाइल बदलने पर फिर पूछा जाएगा; निर्देशिका अनुमति या स्कैन बंद करना नहीं। सेटिंग में साफ़ किया जा सकता है। सदा अनुमति दें?', 'सदा अनुमति की पुष्टि करें', 'रद्द करें', 'फ़ाइल पहचान सत्यापित नहीं हो सकी, बदल गई या सहेजने में विफल; कोई अनुमति नियम नहीं जोड़ा गया।', 'फ़ाइल पहचान सत्यापित नहीं या मेमोरी चेतावनी है; निर्णय याद नहीं रखा जा सकता।'],
        arabic_switch: ['السماح دائماً', 'تكرار هذا القرار للتنبيهات المتطابقة — تطول المدة مع كل تأكيد (من 60 ثانية حتى ساعة، بحد أقصى 100 مرة، معطّل افتراضياً)', 'يُحفظ فقط هذه الحماية والمسار الكامل ومحتوى SHA-256 والكشف والهدف. الملفات المتغيرة ستُسأل من جديد؛ لن يُسمح بمجلد ولن يتوقف الفحص. يمكن حذفه من الإعدادات. السماح دائماً؟', 'تأكيد السماح الدائم', 'إلغاء', 'تعذّر التحقق من هوية الملف أو تغيّر أو فشل الحفظ؛ لم تُضَف قاعدة سماح.', 'لا يمكن التحقق من هوية الملف أو أنها تنبيه ذاكرة؛ لا يمكن حفظ القرار.'],
        russian_switch: ['Всегда разрешать', 'Повторять это решение для одинаковых предупреждений — срок растёт с каждым подтверждением (от 60 с до 1 часа, до 100 раз, по умолчанию выключено)', 'Запоминаются только эта защита, точный путь, содержимое SHA-256, детект и цель. Изменённый файл спросит снова; каталоги не разрешаются, сканирование не отключается. Можно удалить в настройках. Всегда разрешать?', 'Подтвердить разрешение', 'Отмена', 'Не удалось проверить подлинность файла, он изменён или сохранение не удалось; правило не добавлено.', 'Подлинность не подтверждается или это предупреждение памяти; решение не может быть запомнено.'],
        slovenian_switch: ['Vedno dovoli', 'Ponovi to odločitev za enaka opozorila — okno se z vsako potrditvijo podaljša (od 60 s do 1 ure, do 100-krat, privzeto izklopljeno)', 'Zapomni se samo ta zaščita, celotna pot, vsebina SHA-256, zaznanje in cilj. Spremenjena datoteka bo vprašala znova; mape niso dovoljene, pregled ostaja vklopljen. Lze izbrisati v nastavitvah. Vedno dovoli?', 'Potrdi vedno dovoli', 'Prekliči', 'Identitete datoteke ni bilo mogoče preveriti, je spremenjena ali shranjevanje ni uspelo; pravilo ni dodano.', 'Identitete ni mogoče preveriti ali je opozorilo iz pomnilnika; odločitve ni mogoče zapomniti.'],
    };
    let currentId = null;
    let busy = false;
    let initialized = false;
    let queueKey = '';
    let latestTheme = 'system_switch';
    let nextTimer;
    let revision = 0;
    let disposed = false;
    let latestLanguage = 'english_switch';
    let latestIdentity = '';

    const setText = (id, text) => {
        const element = byId(id);
        const value = String(text ?? '');
        if (element.textContent !== value) element.textContent = value;
    };
    const clearActive = (failed = false) => {
        currentId = null; latestIdentity = ''; confirmationId = null; fpTexts = null; queueKey = '';
        disable(); hideFpPanel(); renderAiResult(null, latestLanguage); renderEvidence(null, latestLanguage);
        repeat.checked = false;
        byId('threat_confirmation').classList.add('hidden');
        fpButton.hidden = true;
        byId('threat_process').classList.add('hidden');
        byId('threat_repeat_hint').classList.add('hidden');
        byId('threat_event_details').open = false;
        // 空态把「事件与文件身份」整块收起:没有告警时它展开是空的,
        // 折叠标题却还挂在那里,读起来像坏了。重复确认那行同理(CSS 按空文案隐藏)
        byId('threat_event_details').hidden = true;
        setText('threat_repeat_text', '');
        byId('threat_queue_list').replaceChildren();
        setText('queue_count', '0'); setText('threat_title', message(latestLanguage, failed ? 'evidence_unavailable' : 'evidence_idle'));
        setText('threat_status', message(latestLanguage, failed ? 'evidence_unavailable' : 'evidence_idle'));
        setText('threat_message', ''); setText('threat_process', '');
    };
    const refresh = async () => {
        if (disposed) return;
        clearTimeout(nextTimer);
        const requestRevision = ++revision;
        try {
            const api = window.pywebview?.api;
            if (!api) { snapshotFlight = null; clearActive(true); return; }
            const data = await readSnapshot(api);
            if (requestRevision !== revision) return;
            if (!data) { clearActive(); return; }
            const changed = currentId !== data.id;
            currentId = data.id;
            if (decisionTimeoutId !== currentId) decisionTimeoutId = null;
            latestTheme = data.theme;
            latestLanguage = data.language;
            if (document.body.dataset.appliedTheme !== latestTheme) {
                window.PyasTheme.apply(latestTheme);
                document.body.dataset.appliedTheme = latestTheme;
            }
            document.documentElement.lang = window.AppI18n.langMap[data.language] || 'en';
            document.documentElement.dir = data.language === 'arabic_switch' ? 'rtl' : 'ltr';
            const messages = window.AppI18n.dict[data.language] || window.AppI18n.dict.english_switch;
            const closeButton = byId('threat_close');
            if (closeButton) {
                const closeLabel = messages.btn_close || 'Close';
                closeButton.setAttribute('aria-label', closeLabel);
                closeButton.title = closeLabel;
            }
            const pendingLabel = messages.pending_threats || 'Pending alerts';
            setText('queue_heading', pendingLabel);
            setText('queue_count', String(data.count ?? data.events.length));
            setText('threat_title', data.title);
            setText('threat_message', data.message);
            byId('threat_event_details').hidden = false;
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
                    // agent 是产品名(专有名词,不做翻译);✓=二进制签名已验证,无标记=仅名字匹配
                    procLine.textContent = data.agent
                        ? `${label}: ${proc.name} · ${data.agent}${data.agent_verified ? ' ✓' : ''}`
                        : `${label}: ${proc.name}`;
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
            if (data.resolving) status = decisionText('pending');
            else if (decisionTimeoutId === data.id) status = decisionText('timeout');
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
            renderEvidence(data, data.language);
            renderAiResult(data.ai, data.language, !!data.resolving);
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
                byId('threat_event_details').open = false;
                document.querySelector('.threat-detail').scrollTop = 0;
                byId('threat_message').scrollTop = 0;
                block.focus({ preventScroll: true });
            }
            if (!initialized) { await waitForBridge(api.ready()); initialized = true; }
        } catch (error) {
            if (disposed || requestRevision !== revision) return;
            if (!error.deferred) console.error('Threat UI refresh failed', error);
            clearActive(true);
        } finally {
            if (!disposed && requestRevision === revision) nextTimer = setTimeout(refresh, 400);
        }
    };
    const runAction = async operation => {
        if (busy || !currentId) return;
        const id = currentId;
        const action = ++actionRevision;
        decisionTimeoutId = null;
        if (snapshotFlight) snapshotFlight.expired = true;
        busy = true;
        revision += 1;
        clearTimeout(nextTimer);
        disable();
        byId('threat_confirmation').classList.add('hidden');
        try { await waitForBridge(operation(id)); }
        catch (error) {
            if (disposed || action !== actionRevision) return;
            if (error.code === 'BRIDGE_TIMEOUT') decisionTimeoutId = id;
            else if (error.code !== 'BRIDGE_CANCELLED') console.error('Threat decision failed', error);
        } finally {
            if (!disposed && action === actionRevision) { busy = false; await refresh(); }
        }
    };
    const decide = choice => {
        const remember = choice !== 'permanent' && repeat.checked;
        return runAction(id => window.pywebview.api.decide(id, choice, remember));
    };
    allow.addEventListener('click', () => decide('allow'));
    block.addEventListener('click', () => decide('block'));
    // 误报备注框右侧清空按钮:threat.html 不加载 main.js,需在此单独注入
    (() => {
        const note = byId('threat_fp_note');
        if (!note || note.closest('.input-clearable')) return;
        const wrapper = document.createElement('div');
        wrapper.className = 'input-clearable';
        note.parentNode.insertBefore(wrapper, note);
        wrapper.appendChild(note);
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'search-clear';
        button.setAttribute('aria-label', message(latestLanguage, 'btn_clear_input'));
        button.title = message(latestLanguage, 'btn_clear_input');
        button.innerHTML = '<svg aria-hidden="true" focusable="false"><use href="#i-close"/></svg>';
        button.addEventListener('click', () => {
            note.value = '';
            note.dispatchEvent(new Event('input', { bubbles: true }));
            note.focus();
        });
        wrapper.appendChild(button);
        const sync = () => wrapper.classList.toggle('has-value', note.value.length > 0);
        note.addEventListener('input', sync);
        sync();
    })();
    fpButton.addEventListener('click', openFpPanel);
    byId('threat_fp_cancel').addEventListener('click', hideFpPanel);
    byId('threat_fp_submit').addEventListener('click', async () => {
        if (busy || !currentId || fpPanel.classList.contains('hidden')) return;
        const scope = document.querySelector('input[name="fp_scope"]:checked')?.value || 'file_rule';
        const reason = byId('threat_fp_reason').value || 'other';
        const note = byId('threat_fp_note').value || '';
        hideFpPanel();
        await runAction(id => window.pywebview.api.report_false_positive(id, reason, note, scope));
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
    // × 按钮与 Escape 走同一条出口:pywebview 桥丢失时静默失败,不能抛错把弹窗锁死
    const minimize = () => {
        try { Promise.resolve(window.pywebview?.api?.minimize?.()).catch(console.error); }
        catch (error) { console.error(error); }
    };
    byId('threat_close')?.addEventListener('click', minimize);
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape') { event.preventDefault(); minimize(); }
    });
    // 前后台上报:AI 结果只在用户没盯着弹窗时才由主程序另行推送,避免重复打扰
    const reportFocus = (state) => {
        const api = window.pywebview?.api;
        if (!api?.set_focus) return;
        try { Promise.resolve(api.set_focus(state)).catch(() => {}); } catch (error) { /* 上报失败不影响弹窗 */ }
    };
    window.addEventListener('focus', () => reportFocus(true));
    window.addEventListener('blur', () => reportFocus(false));
    document.addEventListener('visibilitychange', () => reportFocus(!document.hidden));
    reportFocus(document.hasFocus());

    window.addEventListener('pagehide', () => {
        disposed = true; revision += 1; actionRevision += 1;
        clearTimeout(nextTimer);
        for (const cancel of [...bridgeWaits]) cancel();
        snapshotFlight = null; busy = false; decisionTimeoutId = null;
        clearActive();
    });
    window.addEventListener('pageshow', () => {
        if (disposed) { disposed = false; refresh(); }
    });
    matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => window.PyasTheme.apply(latestTheme));

    // 误报复注框复用主窗口的清空按钮实现(.input-clearable 样式已随 style.css 加载)
    const fpNote = byId('threat_fp_note');
    if (fpNote && !fpNote.closest('.input-clearable')) {
        const wrapper = document.createElement('div');
        wrapper.className = 'input-clearable';
        fpNote.parentNode.insertBefore(wrapper, fpNote);
        wrapper.appendChild(fpNote);
        const clear = document.createElement('button');
        clear.type = 'button';
        clear.className = 'search-clear';
        clear.setAttribute('aria-label', 'clear');
        clear.innerHTML = '<svg aria-hidden="true" focusable="false"><use href="#i-close"/></svg>';
        clear.addEventListener('click', () => {
            fpNote.value = '';
            fpNote.dispatchEvent(new Event('input', { bubbles: true }));
            fpNote.focus();
        });
        wrapper.appendChild(clear);
        const syncNote = () => wrapper.classList.toggle('has-value', fpNote.value.length > 0);
        fpNote.addEventListener('input', syncNote);
        syncNote();
    }

    refresh();
});
