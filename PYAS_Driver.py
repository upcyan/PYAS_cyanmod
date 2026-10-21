from PYAS_Diagnostics import log_exception
import os
import sys
import time
import winreg
import threading
import subprocess
import ctypes
import ctypes.wintypes
from PYAS_WinAPI import (
    LUID,
    PYAS_FULL_MESSAGE,
    PYAS_USER_MESSAGE,
    SERVICE_STATUS_PROCESS,
    TOKEN_PRIVILEGES,
)
from PYAS_WinAPI import (
    ERROR_NOT_FOUND,
    ERROR_OPERATION_ABORTED,
    FLT_PORT_FLAG_SYNC_HANDLE,
    HRESULT_IO_PENDING,
    OVERLAPPED,
    PYAS_CONNECTION_CONTEXT,
    PYAS_CONNECTION_MAGIC,
    PYAS_CONNECTION_VERSION,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
)


class DriverMixin:
    DRIVER_START_ERROR_HINTS = {
        2: "the driver file is missing (system cannot find the file specified)",
        5: "access denied (administrator privileges are required)",
        577: "Windows cannot verify the digital signature of this driver",
        1058: "the driver service is disabled",
        1275: "this driver has been blocked from loading by code integrity policy",
        4551: "an Application Control (WDAC / Smart App Control) policy has blocked this driver because it does not meet the required signing level",
    }

    DRIVER_POLICY_BLOCK_CODES = frozenset({577, 1275, 4551})

    SMART_APP_CONTROL_STATES = {1: "evaluation", 2: "on"}

    @staticmethod
    def _query_smart_app_control_state():
        """返回 SAC 状态:'on'/'evaluation'/None(关闭或不可用)。
        优先读 Defender WMI(与安全中心 UI 一致),注册表兜底。"""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance -Namespace root/Microsoft/Windows/Defender "
                    "-ClassName MSFT_MpComputerStatus).SmartAppControlState",
                ],
                capture_output=True,
                text=True,
                timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
            )
            state = (result.stdout or "").strip()

            if state == "On":
                return "on"

            if state == "Eval":
                return "evaluation"

        except Exception:
            log_exception("PYAS_Driver.DriverMixin._query_smart_app_control_state.wmi")

        # 注册表语义与部分系统的安全中心显示存在出入,仅在明确为开启时报告;
        # 其余情况返回 None,由弹窗使用不含模式断言的中性文案
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\CI\Policy",
                0,
                winreg.KEY_READ,
            ) as key:
                value, _ = winreg.QueryValueEx(key, "VerifiedAndReputablePolicyState")

                if int(value) == 2:
                    return "on"

                return None

        except (FileNotFoundError, OSError, ValueError):
            return None

    @staticmethod
    def open_windows_security(page="appbrowser"):
        """打开 Windows 安全中心;windows-defender:// 是不存在的协议,
        真实协议为 windowsdefender://,失败时逐级回退。"""
        candidates = [f"windowsdefender://{page}", "windowsdefender://", "ms-settings:windowsdefender"]

        for uri in candidates:
            try:
                os.startfile(uri)
                return True

            except Exception:
                continue

        log_exception("PYAS_Driver.DriverMixin.open_windows_security")
        return False

    def _notify_driver_block(self, error):
        code = int(error) & 0xFFFFFFFF

        if code not in self.DRIVER_POLICY_BLOCK_CODES:
            return

        if getattr(self, "_driver_block_notice_shown", False):
            return

        self._driver_block_notice_shown = True

        sac_state = self._query_smart_app_control_state()

        if sac_state:
            self._notify_smart_app_control_block(sac_state)
        else:
            self._notify_wdac_block()

    def _notify_smart_app_control_block(self, sac_state):
        title = self._loc(
            {
                "traditional_switch": "智能應用控制攔截了驅動",
                "simplified_switch": "智能应用控制拦截了驱动",
                "english_switch": "Smart App Control blocked the driver",
                "japanese_switch": "Smart App Control がドライバーをブロックしました",
                "korean_switch": "Smart App Control이 드라이버를 차단했습니다",
                "french_switch": "Smart App Control a bloqué le pilote",
                "spanish_switch": "Smart App Control bloqueó el controlador",
                "hindi_switch": "Smart App Control ने ड्राइवर अवरुद्ध किया",
                "arabic_switch": "حظر Smart App Control برنامج التشغيل",
                "russian_switch": "Smart App Control заблокировал драйвер",
                "slovenian_switch": "Smart App Control je blokiral gonilnik",
            }
        )
        if not sac_state:
            message = self._loc(
                {
                    "traditional_switch": "Windows 智能應用控制（Smart App Control）攔截了 PYAS 驅動——它按雲端信譽判定，即使是微軟簽名的驅動也可能被擋。WDAC 補充策略對 SAC 無效，唯一解法是關閉 SAC。\n\n關閉路徑：Windows 安全中心 → 應用和瀏覽器控制 → 智能應用控制設置 → 關 → 重新啟動系統。",
                    "simplified_switch": "Windows 智能应用控制（Smart App Control）拦截了 PYAS 驱动——它按云端信誉判定，即使是微软签名的驱动也可能被挡。WDAC 补充策略对 SAC 无效，唯一解法是关闭 SAC。\n\n关闭路径：Windows 安全中心 → 应用和浏览器控制 → 智能应用控制设置 → 关 → 重启系统。",
                    "english_switch": "Windows Smart App Control blocked the PYAS driver — it judges by cloud reputation, so even Microsoft-signed drivers can be rejected. WDAC supplemental policies do not apply to SAC; the only fix is to turn SAC off.\n\nPath: Windows Security → App & browser control → Smart App Control settings → Off → reboot.",
                    "japanese_switch": "Windows Smart App Control が PYAS ドライバーをブロックしました。クラウド評価による判定のため、Microsoft 署名済みドライバーも拒否される可能性があります。WDAC 補充ポリシーは SAC に適用されず、唯一の解決策は SAC をオフにすることです。\n\n手順：Windows セキュリティ → アプリとブラウザー コントロール → Smart App Control の設定 → オフ → 再起動。",
                    "korean_switch": "Windows Smart App Control이 PYAS 드라이버를 차단했습니다. 클라우드 평판으로 판단하므로 Microsoft 서명 드라이버도 거부될 수 있습니다. WDAC 보완 정책은 SAC에 적용되지 않으며, 유일한 해결책은 SAC를 끄는 것입니다.\n\n경로: Windows 보안 → 앱 및 브라우저 컨트롤 → Smart App Control 설정 → 끔 → 재부팅.",
                    "french_switch": "Windows Smart App Control a bloqué le pilote PYAS — il juge par réputation cloud, même les pilotes signés par Microsoft peuvent être refusés. Les stratégies WDAC supplémentaires ne s'appliquent pas au SAC ; la seule solution est de désactiver le SAC.\n\nChemin : Sécurité Windows → Contrôle des applications et du navigateur → Paramètres Smart App Control → Désactivé → redémarrer.",
                    "spanish_switch": "Windows Smart App Control bloqueó el controlador PYAS: juzga por reputación en la nube, incluso los controladores firmados por Microsoft pueden rechazarse. Las directivas suplementarias de WDAC no aplican a SAC; la única solución es desactivar SAC.\n\nRuta: Seguridad de Windows → Control de aplicaciones y navegador → Configuración de Smart App Control → Desactivado → reiniciar.",
                    "hindi_switch": "Windows Smart App Control ने PYAS ड्राइवर को अवरुद्ध किया — यह क्लाउड प्रतिष्ठा से निर्णय लेता है, Microsoft-हस्ताक्षरित ड्राइवर भी अस्वीकृत हो सकते हैं। WDAC पूरक नीतियाँ SAC पर लागू नहीं होतीं; एकमात्र समाधान SAC बंद करना है।\n\nपथ: Windows सुरक्षा → ऐप और ब्राउज़र नियंत्रण → Smart App Control सेटिंग → बंद → पुनरारंभ।",
                    "arabic_switch": "حظر Windows Smart App Control برنامج PYAS للتشغيل — يحكم حسب السمعة السحابية، وقد تُرفض حتى برامج التشغيل الموقعة من Microsoft. لا تنطبق سياسات WDAC التكميلية على SAC؛ والحل الوحيد هو إيقاف SAC.\n\nالمسار: أمان Windows → التحكم في التطبيقات والمتصفح → إعدادات Smart App Control → إيقاف → إعادة التشغيل.",
                    "russian_switch": "Windows Smart App Control заблокировал драйвер PYAS — решение по облачной репутации, даже драйверы с подписью Microsoft могут быть отклонены. Дополнительные политики WDAC к SAC не применяются; единственное решение — выключить SAC.\n\nПуть: Безопасность Windows → Управление приложениями и браузером → Параметры Smart App Control → Выкл → перезагрузка.",
                    "slovenian_switch": "Windows Smart App Control je blokiral gonilnik PYAS — odloča se po slovu reputaciji v oblaku, tudi z Microsoftom podpisani gonilniki so lahko zavrnjeni. Dopolnilne politike WDAC ne veljajo za SAC; edina rešitev je izklop SAC.\n\nPot: Varnost sistema Windows → Nadzor aplikacij in brskalnika → Nastavitve Smart App Control → Izklopljeno → ponovni zagon.",
                }
            )

            try:
                self.show_alert(title, message, "warning")
            except Exception:
                log_exception("PYAS_Driver.DriverMixin._notify_smart_app_control_block")

            followup = self._loc(
                {
                    "traditional_switch": "是否立即打開 Windows 安全中心？",
                    "simplified_switch": "是否立即打开 Windows 安全中心？",
                    "english_switch": "Open Windows Security now?",
                    "japanese_switch": "今すぐ Windows セキュリティを開きますか？",
                    "korean_switch": "지금 Windows 보안을 여시겠습니까?",
                    "french_switch": "Ouvrir Sécurité Windows maintenant ?",
                    "spanish_switch": "¿Abrir Seguridad de Windows ahora?",
                    "hindi_switch": "अभी Windows सुरक्षा खोलें?",
                    "arabic_switch": "هل تريد فتح أمان Windows الآن؟",
                    "russian_switch": "Открыть «Безопасность Windows» сейчас?",
                    "slovenian_switch": "Želite zdaj odpreti Windows Varnost?",
                }
            )

            try:
                if self.show_confirm(title, followup):
                    self.open_windows_security("appbrowser")
            except Exception:
                log_exception("PYAS_Driver.DriverMixin._notify_smart_app_control_block.open")

            return

        state_text = (
            self._loc(
                {
                    "traditional_switch": "評估模式（按雲端信譽靜默攔截）",
                    "simplified_switch": "评估模式（按云端信誉静默拦截）",
                    "english_switch": "evaluation mode (silently blocks by cloud reputation)",
                    "japanese_switch": "評価モード（クラウド評価により無音でブロック）",
                    "korean_switch": "평가 모드(클라우드 평판 기준 자동 차단)",
                    "french_switch": "mode évaluation (blocage silencieux par réputation cloud)",
                    "spanish_switch": "modo de evaluación (bloqueo silencioso por reputación)",
                    "hindi_switch": "मूल्यांकन मोड (क्लाउड प्रतिष्ठा से मौन अवरोध)",
                    "arabic_switch": "وضع التقييم (حظر صامت حسب السمعة السحابية)",
                    "russian_switch": "режим оценки (тихая блокировка по облачной репутации)",
                    "slovenian_switch": "način ocenjevanja (tiha blokada po slovu reputaciji)",
                }
            )
            if sac_state == "evaluation"
            else self._loc(
                {
                    "traditional_switch": "開啟狀態",
                    "simplified_switch": "开启状态",
                    "english_switch": "on",
                    "japanese_switch": "オン",
                    "korean_switch": "켜짐",
                    "french_switch": "activé",
                    "spanish_switch": "activado",
                    "hindi_switch": "चालू",
                    "arabic_switch": "مُفعّل",
                    "russian_switch": "включён",
                    "slovenian_switch": "vklopljen",
                }
            )
        )
        message = self._loc(
            {
                "traditional_switch": "Windows 智能應用控制（Smart App Control，目前為{0}）攔截了 PYAS 驅動——它按雲端信譽判定，即使是微軟簽名的驅動也可能被擋。WDAC 補充策略對 SAC 無效，唯一解法是關閉 SAC。\n\n關閉路徑：Windows 安全中心 → 應用和瀏覽器控制 → 智能應用控制設置 → 關 → 重新啟動系統。注意：SAC 一旦手動關閉便無法重新開啟（除非重裝系統）。",
                "simplified_switch": "Windows 智能应用控制（Smart App Control，当前为{0}）拦截了 PYAS 驱动——它按云端信誉判定，即使是微软签名的驱动也可能被挡。WDAC 补充策略对 SAC 无效，唯一解法是关闭 SAC。\n\n关闭路径：Windows 安全中心 → 应用和浏览器控制 → 智能应用控制设置 → 关 → 重启系统。注意：SAC 一旦手动关闭便无法重新开启（除非重装系统）。",
                "english_switch": "Windows Smart App Control (currently {0}) blocked the PYAS driver — it judges by cloud reputation, so even Microsoft-signed drivers can be rejected. WDAC supplemental policies do not apply to SAC; the only fix is to turn SAC off.\n\nPath: Windows Security → App & browser control → Smart App Control settings → Off → reboot. Note: once manually turned off, SAC cannot be re-enabled without reinstalling Windows.",
                "japanese_switch": "Windows Smart App Control（現在{0}）が PYAS ドライバーをブロックしました——クラウド評価による判定のため、Microsoft 署名済みドライバーも拒否される可能性があります。WDAC 補充ポリシーは SAC に適用されず、唯一の解決策は SAC をオフにすることです。\n\n手順：Windows セキュリティ → アプリとブラウザー コントロール → Smart App Control の設定 → オフ → 再起動。注意：一度オフにすると再インストールしない限り再オンできません。",
                "korean_switch": "Windows Smart App Control(현재 {0})이 PYAS 드라이버를 차단했습니다. 클라우드 평판으로 판단하므로 Microsoft 서명 드라이버도 거부될 수 있습니다. WDAC 보완 정책은 SAC에 적용되지 않으며, 유일한 해결책은 SAC를 끄는 것입니다.\n\n경로: Windows 보안 → 앱 및 브라우저 컨트롤 → Smart App Control 설정 → 끔 → 재부팅. 참고: 한번 끄면 Windows를 다시 설치하지 않는 한 다시 켤 수 없습니다.",
                "french_switch": "Windows Smart App Control (actuellement {0}) a bloqué le pilote PYAS — il juge par réputation cloud, même les pilotes signés par Microsoft peuvent être refusés. Les stratégies WDAC supplémentaires ne s'appliquent pas au SAC ; la seule solution est de désactiver le SAC.\n\nChemin : Sécurité Windows → Contrôle des applications et du navigateur → Paramètres Smart App Control → Désactivé → redémarrer. Note : une fois désactivé, le SAC ne peut pas être réactivé sans réinstaller Windows.",
                "spanish_switch": "Windows Smart App Control (actualmente {0}) bloqueó el controlador PYAS: juzga por reputación en la nube, incluso los controladores firmados por Microsoft pueden rechazarse. Las directivas suplementarias de WDAC no aplican a SAC; la única solución es desactivar SAC.\n\nRuta: Seguridad de Windows → Control de aplicaciones y navegador → Configuración de Smart App Control → Desactivado → reiniciar. Nota: una vez desactivado, SAC no puede reactivarse sin reinstalar Windows.",
                "hindi_switch": "Windows Smart App Control (वर्तमान में {0}) ने PYAS ड्राइवर को अवरुद्ध किया — यह क्लाउड प्रतिष्ठा से निर्णय लेता है, Microsoft-हस्ताक्षरित ड्राइवर भी अस्वीकृत हो सकते हैं। WDAC पूरक नीतियाँ SAC पर लागू नहीं होतीं; एकमात्र समाधान SAC बंद करना है।\n\nपथ: Windows सुरक्षा → ऐप और ब्राउज़र नियंत्रण → Smart App Control सेटिंग → बंद → पुनरारंभ। नोट: एक बार बंद करने के बाद Windows पुनः स्थापित किए बिना SAC फिर चालू नहीं हो सकता।",
                "arabic_switch": "حظر Windows Smart App Control (الحالي: {0}) برنامج PYAS للتشغيل — يحكم حسب السمعة السحابية، وقد تُرفض حتى برامج التشغيل الموقعة من Microsoft. لا تنطبق سياسات WDAC التكميلية على SAC؛ والحل الوحيد هو إيقاف SAC.\n\nالمسار: أمان Windows → التحكم في التطبيقات والمتصفح → إعدادات Smart App Control → إيقاف → إعادة التشغيل. ملاحظة: بمجرد إيقافه يدويًا لا يمكن إعادة تفعيله إلا بإعادة تثبيت Windows.",
                "russian_switch": "Windows Smart App Control (сейчас {0}) заблокировал драйвер PYAS — решение по облачной репутации, даже драйверы с подписью Microsoft могут быть отклонены. Дополнительные политики WDAC к SAC не применяются; единственное решение — выключить SAC.\n\nПуть: Безопасность Windows → Управление приложениями и браузером → Параметры Smart App Control → Выкл → перезагрузка. Примечание: после ручного выключения SAC нельзя включить снова без переустановки Windows.",
                "slovenian_switch": "Windows Smart App Control (trenutno {0}) je blokiral gonilnik PYAS — odloča se po slovu reputaciji v oblaku, tudi z Microsoftom podpisani gonilniki so lahko zavrnjeni. Dopolnilne politike WDAC ne veljajo za SAC; edina rešitev je izklop SAC.\n\nPot: Varnost sistema Windows → Nadzor aplikacij in brskalnika → Nastavitve Smart App Control → Izklopljeno → ponovni zagon. Opomba: enkrat ročno izklopljenega SAC ni mogoče znova vklopiti brez ponovne namestitve sistema.",
            }
        ).replace("{0}", state_text)

        try:
            self.show_alert(title, message, "warning")
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._notify_smart_app_control_block")

        followup = self._loc(
            {
                "traditional_switch": "是否立即打開 Windows 安全中心？",
                "simplified_switch": "是否立即打开 Windows 安全中心？",
                "english_switch": "Open Windows Security now?",
                "japanese_switch": "今すぐ Windows セキュリティを開きますか？",
                "korean_switch": "지금 Windows 보안을 여시겠습니까?",
                "french_switch": "Ouvrir Sécurité Windows maintenant ?",
                "spanish_switch": "¿Abrir Seguridad de Windows ahora?",
                "hindi_switch": "अभी Windows सुरक्षा खोलें?",
                "arabic_switch": "هل تريد فتح أمان Windows الآن؟",
                "russian_switch": "Открыть «Безопасность Windows» сейчас?",
                "slovenian_switch": "Želite zdaj odpreti Windows Varnost?",
            }
        )

        try:
            if self.show_confirm(title, followup):
                self.open_windows_security("appbrowser")
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._notify_smart_app_control_block.open")

    def _notify_wdac_block(self):
        title = self._loc(
            {
                "traditional_switch": "無法啟用驅動防護",
                "simplified_switch": "无法启用驱动防护",
                "english_switch": "Driver Protection could not be enabled",
                "japanese_switch": "ドライバー保護を有効にできません",
                "korean_switch": "드라이버 보호를 활성화할 수 없습니다",
                "french_switch": "Impossible d'activer la protection du pilote",
                "spanish_switch": "No se pudo activar la protección del controlador",
                "hindi_switch": "ड्राइवर सुरक्षा सक्रिय नहीं हो सकी",
                "arabic_switch": "تعذر تفعيل حماية برنامج التشغيل",
                "russian_switch": "Не удалось включить защиту драйвера",
                "slovenian_switch": "Zaščite gonilnika ni bilo mogoče omogočiti",
            }
        )
        message = self._loc(
            {
                "traditional_switch": "Windows 應用控制策略（WDAC／Smart App Control）按簽名級別攔截了 PYAS 驅動，驅動防護無法啟用。\n\n處理建議：\n1. 以管理員執行 citool -lp 查看系統活動的代碼完整性策略；\n2. 開發環境可執行 bcdedit /set testsigning on 並重新啟動（允許測試簽名級別，桌面會顯示測試模式水印）；\n3. 正式部署需為驅動取得 Microsoft WHQL／attestation 簽名，或在本機 WDAC 策略中放行該驅動。",
                "simplified_switch": "Windows 应用控制策略（WDAC／Smart App Control）按签名级别拦截了 PYAS 驱动，驱动防护无法启用。\n\n处理建议：\n1. 以管理员运行 citool -lp 查看系统活动的代码完整性策略；\n2. 开发环境可运行 bcdedit /set testsigning on 并重启（允许测试签名级别，桌面会显示测试模式水印）；\n3. 正式部署需为驱动取得 Microsoft WHQL／attestation 签名，或在本机 WDAC 策略中放行该驱动。",
                "english_switch": "A Windows Application Control policy (WDAC / Smart App Control) has blocked the PYAS driver based on its signing level, so Driver Protection cannot be enabled.\n\nSuggested actions:\n1. Run 'citool -lp' as administrator to list active code integrity policies;\n2. On development machines, run 'bcdedit /set testsigning on' and reboot (allows test-signing level; a test-mode watermark will appear);\n3. For production, obtain Microsoft WHQL / attestation signing for the driver, or allowlist it in the local WDAC policy.",
                "japanese_switch": "Windows アプリケーション制御ポリシー（WDAC／Smart App Control）が署名レベルにより PYAS ドライバーをブロックしたため、ドライバー保護を有効にできません。\n\n対処：\n1. 管理者として citool -lp を実行し、有効なコード整合性ポリシーを確認；\n2. 開発環境では bcdedit /set testsigning on を実行して再起動（テスト署名レベルを許可、テストモードの透かし表示）；\n3. 本番では Microsoft WHQL／attestation 署名を取得するか、WDAC ポリシーで許可してください。",
                "korean_switch": "Windows 애플리케이션 제어 정책(WDAC/Smart App Control)이 서명 수준 때문에 PYAS 드라이버를 차단하여 드라이버 보호를 활성화할 수 없습니다.\n\n조치:\n1. 관리자로 citool -lp 실행 후 활성 코드 무결성 정책 확인;\n2. 개발 환경에서는 bcdedit /set testsigning on 실행 후 재부팅(테스트 서명 수준 허용, 테스트 모드 워터마크 표시);\n3. 프로덕션은 Microsoft WHQL/attestation 서명을 받거나 WDAC 정책에서 허용하세요.",
                "french_switch": "Une stratégie de contrôle d'application Windows (WDAC / Smart App Control) a bloqué le pilote PYAS en raison de son niveau de signature.\n\nActions :\n1. Exécutez « citool -lp » en administrateur pour lister les stratégies actives ;\n2. En développement : « bcdedit /set testsigning on » puis redémarrez (autorise le niveau test-signing, filigrane affiché) ;\n3. En production : obtenez une signature Microsoft WHQL / attestation ou autorisez le pilote dans la stratégie WDAC.",
                "spanish_switch": "Una directiva de control de aplicaciones de Windows (WDAC / Smart App Control) bloqueó el controlador PYAS por su nivel de firma.\n\nAcciones:\n1. Ejecute «citool -lp» como administrador para ver las directivas activas;\n2. En desarrollo: «bcdedit /set testsigning on» y reinicie (permite firma de prueba, muestra marca de agua);\n3. En producción: obtenga firma WHQL/attestation de Microsoft o permita el controlador en la directiva WDAC.",
                "hindi_switch": "Windows एप्लिकेशन नियंत्रण नीति (WDAC / Smart App Control) ने हस्ताक्षर स्तर के कारण PYAS ड्राइवर को अवरुद्ध किया।\n\nसुझाव:\n1. सक्रिय नीतियाँ देखने हेतु व्यवस्थापक के रूप में 'citool -lp' चलाएँ;\n2. विकास पर्यावरण में 'bcdedit /set testsigning on' चलाकर पुनरारंभ करें (टेस्ट-साइनिंग स्तर स्वीकृत, वॉटरमार्क दिखेगा);\n3. प्रोडक्शन हेतु Microsoft WHQL/attestation हस्ताक्षर लें या WDAC नीति में ड्राइवर अनुमत दें।",
                "arabic_switch": "حظرت نهج التحكم بالتطبيقات في Windows (WDAC / Smart App Control) برنامج PYAS للتشغيل بسبب مستوى توقيعه، لذا تعذر تفعيل الحماية.\n\nالإجراءات:\n1. شغّل citool -lp كمسؤول لعرض النهج النشطة؛\n2. في بيئة التطوير: bcdedit /set testsigning on ثم أعد التشغيل (يسمح بمستوى التوقيع الاختباري)؛\n3. للإنتاج: احصل على توقيع WHQL/attestation من Microsoft أو اسمح بالبرنامج في نهج WDAC.",
                "russian_switch": "Политика управления приложениями Windows (WDAC / Smart App Control) заблокировала драйвер PYAS из-за уровня подписи.\n\nДействия:\n1. Запустите «citool -lp» от имени администратора, чтобы увидеть активные политики;\n2. Для разработки: «bcdedit /set testsigning on» и перезагрузка (разрешает тестовый уровень подписи, появится водяной знак);\n3. Для продакшена: получите подпись Microsoft WHQL/attestation или разрешите драйвер в политике WDAC.",
                "slovenian_switch": "Pravilnik nadzora aplikacij Windows (WDAC / Smart App Control) je blokiral gonilnik PYAS zaradi ravni podpisa.\n\nDejanja:\n1. Zaženite «citool -lp» kot skrbnik za seznam aktivnih pravilnikov;\n2. V razvoju: «bcdedit /set testsigning on» in ponovni zagon (dovoli testno raven podpisa, prikazan vodni žig);\n3. Za produkcijo: pridobite Microsoft WHQL/attestation podpis ali dovolite gonilnik v pravilniku WDAC.",
            }
        )

        details = ""

        try:
            driver_hash = self.calc_file_hash(self.path_drivers)

            if driver_hash:
                details = f"\n\n{os.path.normpath(self.path_drivers)}\nSHA256: {driver_hash}"

        except Exception:
            log_exception("PYAS_Driver.DriverMixin._notify_driver_block.hash")

        try:
            self.show_alert(title, message + details, "warning")
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._notify_driver_block")

        followup = self._loc(
            {
                "traditional_switch": "是否打開 Microsoft 應用控制官方文檔（瞭解如何建立放行規則）？",
                "simplified_switch": "是否打开 Microsoft 应用控制官方文档（了解如何建立放行规则）？",
                "english_switch": "Open the Microsoft Application Control documentation (how to create allow rules)?",
                "japanese_switch": "Microsoft アプリケーション制御の公式ドキュメント（許可規則の作成方法）を開きますか？",
                "korean_switch": "Microsoft 애플리케이션 제어 공식 문서(허용 규칙 만들기)를 여시겠습니까?",
                "french_switch": "Ouvrir la documentation Microsoft sur le contrôle d'application (créer des règles d'autorisation) ?",
                "spanish_switch": "¿Abrir la documentación de Microsoft sobre control de aplicaciones (cómo crear reglas de permiso)?",
                "hindi_switch": "Microsoft एप्लिकेशन नियंत्रण आधिकारिक दस्तावेज़ (अनुमति नियम बनाना) खोलें?",
                "arabic_switch": "هل تريد فتح وثائق Microsoft للتحكم بالتطبيقات (كيفية إنشاء قواعد سماح)؟",
                "russian_switch": "Открыть документацию Microsoft по управлению приложениями (как создать правила разрешения)?",
                "slovenian_switch": "Ali želite odpreti Microsoftovo dokumentacijo o nadzoru aplikacij (ustvarjanje pravil dovoljenja)?",
            }
        )

        try:
            if self.show_confirm(title, followup):
                self.open_url(
                    "https://learn.microsoft.com/windows/security/"
                    "application-security/application-control/"
                    "app-control-for-business/"
                )
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._notify_driver_block.docs")

    def _describe_driver_start_error(self, error):
        code = int(error) & 0xFFFFFFFF
        hint = self.DRIVER_START_ERROR_HINTS.get(code)

        if hint:
            return f"StartServiceW failed: 0x{code:08X} ({hint})"

        return f"StartServiceW failed: 0x{code:08X}"

    def _query_service_state_handle(self, service):
        status = SERVICE_STATUS_PROCESS()
        needed = ctypes.wintypes.DWORD(0)
        buffer = ctypes.cast(ctypes.byref(status), ctypes.POINTER(ctypes.c_ubyte))

        if not self.advapi32.QueryServiceStatusEx(
            service, 0, buffer, ctypes.sizeof(status), ctypes.byref(needed)
        ):
            return None, ctypes.get_last_error()

        return int(status.dwCurrentState), 0

    def _query_driver_service_state(self):
        scm = self.advapi32.OpenSCManagerW(None, None, 0x0001)

        if not scm:
            return None

        service = None

        try:
            service = self.advapi32.OpenServiceW(scm, "PYAS_Driver", 0x0004)

            if not service:
                return None

            state, _ = self._query_service_state_handle(service)
            return state
        finally:
            if service:
                self.advapi32.CloseServiceHandle(service)

            self.advapi32.CloseServiceHandle(scm)

    def _get_driver_client_image_path(self):
        buffer = ctypes.create_unicode_buffer(32768)
        size = ctypes.wintypes.DWORD(len(buffer))

        if not self.kernel32.QueryFullProcessImageNameW(
            self.kernel32.GetCurrentProcess(), 0, buffer, ctypes.byref(size)
        ):
            return None

        image_path = os.path.abspath(buffer.value)
        drive, tail = os.path.splitdrive(image_path)

        if not drive or not tail:
            return None

        device_buffer = ctypes.create_unicode_buffer(32768)

        if not self.kernel32.QueryDosDeviceW(drive, device_buffer, len(device_buffer)):
            return None

        return device_buffer.value.rstrip("\\") + tail

    def _configure_driver_identity(self):
        image_path = self._get_driver_client_image_path()

        if not image_path:
            return False, ctypes.get_last_error() or 1

        try:
            access = winreg.KEY_SET_VALUE | getattr(winreg, "KEY_WOW64_64KEY", 0)

            with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\PYAS_Driver",
                0,
                access,
            ) as key:
                winreg.SetValueEx(key, "ClientImagePath", 0, winreg.REG_SZ, image_path)

            return True, 0
        except OSError as e:
            log_exception("PYAS_Driver.DriverMixin._configure_driver_identity:74")
            return False, int(getattr(e, "winerror", 0) or 1)

    def _ensure_driver_service(self):
        desired_service_access = 0x0002 | 0x0004 | 0x0010 | 0x00010000
        dependencies = ctypes.create_unicode_buffer("FltMgr\0\0")
        dependencies_ptr = ctypes.cast(dependencies, ctypes.wintypes.LPCWSTR)
        last_error = 0

        for attempt in range(20):
            scm = self.advapi32.OpenSCManagerW(None, None, 0x0001 | 0x0002)

            if not scm:
                return False, ctypes.get_last_error()

            service = None

            try:
                ctypes.set_last_error(0)
                service = self.advapi32.CreateServiceW(
                    scm,
                    "PYAS_Driver",
                    "PYAS_Driver",
                    desired_service_access,
                    0x00000001,
                    0x00000003,
                    0x00000001,
                    self.path_drivers,
                    "FSFilter Activity Monitor",
                    None,
                    dependencies_ptr,
                    None,
                    None,
                )

                if not service:
                    last_error = ctypes.get_last_error()

                    if last_error in (1073, 1078):
                        service = self.advapi32.OpenServiceW(
                            scm, "PYAS_Driver", desired_service_access
                        )

                        if not service:
                            last_error = ctypes.get_last_error()

                    elif last_error == 1072:
                        pass

                if service:
                    ctypes.set_last_error(0)
                    changed = self.advapi32.ChangeServiceConfigW(
                        service,
                        0x00000001,
                        0x00000003,
                        0x00000001,
                        self.path_drivers,
                        "FSFilter Activity Monitor",
                        None,
                        dependencies_ptr,
                        None,
                        None,
                        None,
                    )

                    if not changed:
                        last_error = ctypes.get_last_error()
                        return False, last_error

                    return True, 0
            finally:
                if service:
                    self.advapi32.CloseServiceHandle(service)

                self.advapi32.CloseServiceHandle(scm)

            if last_error != 1072:
                break

            if attempt < 19:
                time.sleep(0.05)

        return False, last_error or 1

    def _start_driver_service(self):
        scm = self.advapi32.OpenSCManagerW(None, None, 0x0001)

        if not scm:
            return False, ctypes.get_last_error()

        service = None

        try:
            service = self.advapi32.OpenServiceW(scm, "PYAS_Driver", 0x0004 | 0x0010)

            if not service:
                return False, ctypes.get_last_error()

            state, error = self._query_service_state_handle(service)

            if state in (2, 4):
                return True, 0

            if error:
                return False, error

            ctypes.set_last_error(0)

            if self.advapi32.StartServiceW(service, 0, None):
                return True, 0

            error = ctypes.get_last_error()

            if error == 1056:
                return True, 0

            return False, error
        finally:
            if service:
                self.advapi32.CloseServiceHandle(service)

            self.advapi32.CloseServiceHandle(scm)

    def uninstall_system_driver(self):
        if not self.stop_system_driver():
            return False, 1051

        return self._delete_driver_service()

    def _delete_driver_service(self, timeout=15.0):
        deadline = time.monotonic() + timeout
        last_error = 0
        delete_requested = False

        while time.monotonic() < deadline:
            scm = self.advapi32.OpenSCManagerW(None, None, 0x0001)

            if not scm:
                return False, ctypes.get_last_error()

            service = None

            try:
                ctypes.set_last_error(0)
                service = self.advapi32.OpenServiceW(scm, "PYAS_Driver", 0x0004 | 0x00010000)

                if not service:
                    last_error = ctypes.get_last_error()

                    if last_error == 1060:
                        return True, 0

                    if last_error != 1072:
                        return False, last_error
                else:
                    state, status_error = self._query_service_state_handle(service)

                    if status_error:
                        return False, status_error

                    if state not in (2, 3, 4) and not delete_requested:
                        ctypes.set_last_error(0)

                        if self.advapi32.DeleteService(service):
                            delete_requested = True
                            last_error = 1072
                        else:
                            last_error = ctypes.get_last_error()

                            if last_error == 1060:
                                return True, 0

                            if last_error == 1072:
                                delete_requested = True
                            else:
                                return False, last_error
                    elif state in (2, 3, 4):
                        last_error = 1051
            finally:
                if service:
                    self.advapi32.CloseServiceHandle(service)

                self.advapi32.CloseServiceHandle(scm)

            time.sleep(0.1)

        return False, last_error or 1072

    def install_system_driver(self):
        try:
            ensured, service_error = self._ensure_driver_service()

            if not ensured:
                self.write_log(
                    "WARN",
                    "Driver Service",
                    detail=f"CreateServiceW/ChangeServiceConfigW failed: 0x{service_error & 0xFFFFFFFF:08X}",
                    success=False,
                )
                return False

            configured, identity_error = self._configure_driver_identity()

            if not configured:
                self.write_log(
                    "WARN",
                    "Driver Identity",
                    detail=f"ClientImagePath configuration failed: 0x{identity_error & 0xFFFFFFFF:08X}",
                    success=False,
                )
                return False

            self._reg_write(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances",
                "DefaultInstance",
                winreg.REG_SZ,
                "PYAS Instance",
            )
            self._reg_write(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances\PYAS Instance",
                "Altitude",
                winreg.REG_SZ,
                "320000",
            )
            self._reg_write(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\PYAS_Driver\Instances\PYAS Instance",
                "Flags",
                winreg.REG_DWORD,
                0,
            )

            started, start_error = self._start_driver_service()

            if not started:
                self.write_log(
                    "WARN",
                    "Driver Service",
                    detail=self._describe_driver_start_error(start_error),
                    success=False,
                )
                self._notify_driver_block(start_error)
                return False

            final_state = None
            last_start_attempt = time.monotonic()
            deadline = time.monotonic() + 3.0

            while time.monotonic() < deadline:
                service_state = self._query_driver_service_state()

                if service_state == 4:
                    final_state = self._query_driver_state()

                    if final_state == 2:
                        return True

                    if final_state in (4, 5):
                        break
                elif service_state == 1:
                    now = time.monotonic()

                    if now - last_start_attempt >= 0.1:
                        started, start_error = self._start_driver_service()
                        last_start_attempt = now

                        if not started:
                            break
                elif service_state is None:
                    break

                time.sleep(0.02)

            if self.check_system_driver():
                self.stop_system_driver()

            detail = (
                "Driver entered unload-retry state during startup"
                if final_state == 4
                else "Driver did not reach running state"
            )
            self.write_log("WARN", "Driver Protection", detail=detail, success=False)
            return False

        except Exception as e:
            log_exception("PYAS_Driver.DriverMixin.install_system_driver:267")
            self.write_log("WARN", "install_system_driver", detail=str(e), success=False)
            return False

    def _driver_handle_value(self, handle):
        if handle is None:
            return None

        value = getattr(handle, "value", handle)

        if value is None:
            return None

        try:
            return int(value)
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._driver_handle_value:281")
            return None

    def _connect_driver_port(self, asynchronous=False):
        context = PYAS_CONNECTION_CONTEXT()
        context.Size = ctypes.sizeof(context)
        context.Version = PYAS_CONNECTION_VERSION
        context.Magic = PYAS_CONNECTION_MAGIC
        context.ProcessId = os.getpid()

        temp_port = ctypes.wintypes.HANDLE()
        status = self.fltlib.FilterConnectCommunicationPort(
            "\\PYAS_Output_Pipe",
            0 if asynchronous else FLT_PORT_FLAG_SYNC_HANDLE,
            ctypes.byref(context),
            ctypes.sizeof(context),
            None,
            ctypes.byref(temp_port),
        )

        if status != 0:
            return None

        return temp_port

    def _detach_driver_port(self, expected_port=None):
        expected_value = self._driver_handle_value(expected_port)

        with self.lock_driver:
            current_port = self.driver_port
            current_value = self._driver_handle_value(current_port)

            if current_value is None:
                return None

            if expected_port is not None and current_value != expected_value:
                return None

            self.driver_port = None
            return current_port

    def _close_driver_port(self, expected_port=None):
        port = self._detach_driver_port(expected_port)

        if not port:
            return False

        try:
            self.kernel32.CloseHandle(port)
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._close_driver_port:326")
            pass

        return True

    def _driver_listener_should_run(self):
        if self.driver_stop_event.is_set():
            return False

        with self.lock_config:
            return bool(self.pyas_config.get("driver_switch", False))

    def start_driver_listener(self, wait_ready=True):
        with self.lock_driver:
            current = self.driver_listener_thread

            if current and current.is_alive():
                return (
                    self.driver_listener_ready_event.is_set()
                    and not self.driver_stop_event.is_set()
                )

            self.driver_stop_event.clear()
            self.driver_listener_ready_event.clear()
            self.driver_listener_failed_event.clear()
            thread = threading.Thread(target=self.pipe_server_thread, daemon=True)
            self.driver_listener_thread = thread
            thread.start()

        if not wait_ready:
            return True

        deadline = time.monotonic() + 5.0

        while time.monotonic() < deadline:
            if self.driver_listener_ready_event.wait(0.02):
                return True

            if self.driver_listener_failed_event.is_set() or not thread.is_alive():
                break

        self._stop_driver_listener()
        return False

    def _stop_driver_listener(self):
        self.driver_stop_event.set()

        with self.lock_driver:
            thread = self.driver_listener_thread
            port = self.driver_port

        if port:
            try:
                self.kernel32.CancelIoEx(port, None)
            except Exception:
                log_exception("PYAS_Driver.DriverMixin._stop_driver_listener:373")
                pass

        if thread and thread is not threading.current_thread():
            thread.join(timeout=2.0)

        alive = bool(thread and thread.is_alive())

        if not alive:
            with self.lock_driver:
                if self.driver_listener_thread is thread:
                    self.driver_listener_thread = None

            self.driver_listener_ready_event.clear()
            self._close_driver_port()

        return not alive

    def _resume_driver_listener(self):
        if not self.check_system_driver():
            return False

        with self.lock_config:
            enabled = bool(self.pyas_config.get("driver_switch", False))

        if not enabled:
            return False

        self._close_driver_port()
        return self.start_driver_listener(wait_ready=True)

    def _send_driver_unload_permit(self, enabled):
        msg = PYAS_USER_MESSAGE()
        msg.Command = 5 if enabled else 6
        msg.Path = ""

        for _ in range(3):
            if not self._ensure_driver_port():
                time.sleep(0.1)
                continue

            with self.lock_driver:
                current_port = self.driver_port

                if not current_port:
                    continue

                bytes_returned = ctypes.wintypes.DWORD(0)

                try:
                    status = self.fltlib.FilterSendMessage(
                        current_port,
                        ctypes.byref(msg),
                        ctypes.sizeof(msg),
                        None,
                        0,
                        ctypes.byref(bytes_returned),
                    )
                except Exception as e:
                    log_exception("PYAS_Driver.DriverMixin._send_driver_unload_permit:427")
                    self.write_log(
                        "WARN", "Driver Unload Authorization", detail=str(e), success=False
                    )
                    status = -1

            if status == 0:
                return True

            self._close_driver_port(current_port)
            time.sleep(0.1)

        return False

    def _ensure_driver_port(self):
        for _ in range(20):
            with self.lock_driver:
                if self.driver_port:
                    return True

            temp_port = self._connect_driver_port()

            if temp_port:
                with self.lock_driver:
                    if not self.driver_port:
                        self.driver_port = temp_port
                        return True

                try:
                    self.kernel32.CloseHandle(temp_port)
                except Exception:
                    log_exception("PYAS_Driver.DriverMixin._ensure_driver_port:454")
                    pass

                return True

            time.sleep(0.05)

        return False

    def _query_driver_state(self):
        for use_existing in (True, False):
            local_port = None
            port = None

            if use_existing:
                with self.lock_driver:
                    if self.driver_port:
                        port = self.driver_port

                if not port:
                    continue
            else:
                local_port = self._connect_driver_port()

                if not local_port:
                    return None

                port = local_port

            msg = PYAS_USER_MESSAGE()
            msg.Command = 7
            msg.Path = ""
            state = ctypes.wintypes.DWORD(0)
            bytes_returned = ctypes.wintypes.DWORD(0)

            try:
                status = self.fltlib.FilterSendMessage(
                    port,
                    ctypes.byref(msg),
                    ctypes.sizeof(msg),
                    ctypes.byref(state),
                    ctypes.sizeof(state),
                    ctypes.byref(bytes_returned),
                )

                if status == 0 and bytes_returned.value == ctypes.sizeof(state):
                    return int(state.value)
            except Exception:
                log_exception("PYAS_Driver.DriverMixin._query_driver_state:496")
                pass
            finally:
                if local_port:
                    try:
                        self.kernel32.CloseHandle(local_port)
                    except Exception:
                        log_exception("PYAS_Driver.DriverMixin._query_driver_state:502")
                        pass

            if use_existing:
                self._close_driver_port(port)

        return None

    def _enable_token_privilege(self, privilege_name):
        token = ctypes.wintypes.HANDLE()
        desired_access = 0x0020 | 0x0008

        if not self.advapi32.OpenProcessToken(
            self.kernel32.GetCurrentProcess(), desired_access, ctypes.byref(token)
        ):
            return None, ctypes.get_last_error()

        luid = LUID()

        if not self.advapi32.LookupPrivilegeValueW(None, privilege_name, ctypes.byref(luid)):
            error = ctypes.get_last_error()
            self.kernel32.CloseHandle(token)
            return None, error

        new_state = TOKEN_PRIVILEGES()
        new_state.PrivilegeCount = 1
        new_state.Privileges[0].Luid = luid
        new_state.Privileges[0].Attributes = 0x00000002

        previous_state = TOKEN_PRIVILEGES()
        return_length = ctypes.wintypes.DWORD(0)
        ctypes.set_last_error(0)

        adjusted = self.advapi32.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(new_state),
            ctypes.sizeof(previous_state),
            ctypes.byref(previous_state),
            ctypes.byref(return_length),
        )
        error = ctypes.get_last_error()

        if not adjusted or error == 1300:
            self.kernel32.CloseHandle(token)
            return None, error or 1

        return (token, previous_state, return_length.value), 0

    def _restore_token_privilege(self, privilege_state):
        if not privilege_state:
            return

        token, previous_state, previous_length = privilege_state

        try:
            if previous_length:
                self.advapi32.AdjustTokenPrivileges(
                    token, False, ctypes.byref(previous_state), 0, None, None
                )
        finally:
            self.kernel32.CloseHandle(token)

    def _filter_unload_with_privilege(self, filter_name):
        result = {
            "status": None,
            "privilege_error": 0,
            "authorization_failed": False,
            "exception": None,
            "attempts": 0,
        }
        privilege_state = None
        unload_authorized = False

        self.driver_unload_worker = None
        self.driver_unload_result = result

        try:
            privilege_state, privilege_error = self._enable_token_privilege("SeLoadDriverPrivilege")

            if not privilege_state:
                result["privilege_error"] = privilege_error
                return result

            retryable_statuses = {0x80070522, 0x80070005, 0x800700AA}

            for delay in (0.0, 0.05, 0.15):
                if delay:
                    time.sleep(delay)

                if not self.check_system_driver():
                    result["status"] = 0
                    unload_authorized = False
                    return result

                if not self._send_driver_unload_permit(True):
                    continue

                unload_authorized = True
                result["attempts"] += 1
                unload_status = self.fltlib.FilterUnload(filter_name)
                result["status"] = unload_status

                if unload_status == 0:
                    unload_authorized = False
                    return result

                revoked = False

                if self.check_system_driver():
                    try:
                        revoked = self._send_driver_unload_permit(False)
                    except Exception:
                        log_exception("PYAS_Driver.DriverMixin._filter_unload_with_privilege:606")
                        revoked = False

                unload_authorized = not revoked

                if (unload_status & 0xFFFFFFFF) not in retryable_statuses:
                    return result

            if result["status"] is None:
                result["authorization_failed"] = True

        except Exception as e:
            log_exception("PYAS_Driver.DriverMixin._filter_unload_with_privilege:616")
            result["exception"] = str(e)
        finally:
            if unload_authorized and self.check_system_driver():
                try:
                    self._send_driver_unload_permit(False)
                except Exception:
                    log_exception("PYAS_Driver.DriverMixin._filter_unload_with_privilege:622")
                    pass

            self._restore_token_privilege(privilege_state)

        return result

    def stop_system_driver(self):
        with self.lock_driver_unload:
            runtime_unloaded = False
            unload_confirmed = False

            try:
                if not self._stop_driver_listener():
                    self.write_log(
                        "WARN",
                        "Driver Protection",
                        detail="Driver listener cancellation did not complete",
                        success=False,
                    )
                    return False

                if not self.check_system_driver():
                    runtime_unloaded = True
                    unload_confirmed = True
                else:
                    if not self._ensure_driver_port():
                        if not self.check_system_driver():
                            runtime_unloaded = True
                            unload_confirmed = True
                        else:
                            self.write_log(
                                "WARN",
                                "Driver Protection",
                                detail="Control port unavailable",
                                success=False,
                            )
                            return False

                    if not runtime_unloaded:
                        unload_result = self._filter_unload_with_privilege("PYAS_Driver")

                        if unload_result["privilege_error"]:
                            error = unload_result["privilege_error"]
                            self.write_log(
                                "WARN",
                                "Driver Protection",
                                detail=f"SeLoadDriverPrivilege unavailable: 0x{error & 0xFFFFFFFF:08X}",
                                success=False,
                            )
                            return False

                        if unload_result["authorization_failed"]:
                            self.write_log(
                                "WARN",
                                "Driver Protection",
                                detail="Unload authorization rejected",
                                success=False,
                            )
                            return False

                        if unload_result["exception"]:
                            self.write_log(
                                "WARN",
                                "stop_system_driver",
                                detail=unload_result["exception"],
                                success=False,
                            )
                            return False

                        unload_status = unload_result["status"]

                        if unload_status == 0:
                            runtime_unloaded = True
                            unload_confirmed = True
                        elif not self.check_system_driver():
                            runtime_unloaded = True
                            unload_confirmed = True
                        else:
                            attempts = unload_result["attempts"]
                            self.write_log(
                                "WARN",
                                "Driver Protection",
                                detail=f"FilterUnload failed after {attempts} attempt(s): 0x{unload_status & 0xFFFFFFFF:08X}",
                                success=False,
                            )
                            return False

                self._close_driver_port()

                if unload_confirmed:
                    deadline = time.monotonic() + 0.5

                    while time.monotonic() < deadline and self.check_system_driver():
                        time.sleep(0.01)

                    if self.check_system_driver():
                        self.write_log(
                            "INFO",
                            "Driver Protection",
                            detail="Filter unloaded; SCM state is still settling",
                        )

                return runtime_unloaded
            except Exception as e:
                log_exception("PYAS_Driver.DriverMixin.stop_system_driver:689")
                self.write_log("WARN", "stop_system_driver", detail=str(e), success=False)
                return False
            finally:
                if not runtime_unloaded and self.check_system_driver():
                    self._resume_driver_listener()

    def check_system_driver(self):
        runtime_state = self._query_driver_state()

        if runtime_state in (1, 2, 3, 4):
            return True

        service_state = self._query_driver_service_state()
        return service_state in (2, 3, 4)

    def clear_driver_rules(self):
        with self.lock_driver:
            if not self.driver_port:
                return False

            msg = PYAS_USER_MESSAGE()
            msg.Command = 4
            msg.Path = ""
            bytes_returned = ctypes.wintypes.DWORD(0)

            try:
                return (
                    self.fltlib.FilterSendMessage(
                        self.driver_port,
                        ctypes.byref(msg),
                        ctypes.sizeof(msg),
                        None,
                        0,
                        ctypes.byref(bytes_returned),
                    )
                    == 0
                )
            except Exception:
                log_exception("PYAS_Driver.DriverMixin.clear_driver_rules:723")
                return False

    def load_driver_rule_file(self, json_path):
        with self.lock_driver:
            if not self.driver_port:
                return False

            norm_path = os.path.abspath(json_path)

            if not os.path.exists(norm_path):
                return False

            nt_path = f"\\??\\{norm_path}"

            msg = PYAS_USER_MESSAGE()
            msg.Command = 3
            msg.Path = nt_path
            bytes_returned = ctypes.wintypes.DWORD(0)

            try:
                return (
                    self.fltlib.FilterSendMessage(
                        self.driver_port,
                        ctypes.byref(msg),
                        ctypes.sizeof(msg),
                        None,
                        0,
                        ctypes.byref(bytes_returned),
                    )
                    == 0
                )
            except Exception:
                log_exception("PYAS_Driver.DriverMixin.load_driver_rule_file:751")
                return False

    def _cancel_driver_receive(self, port, overlapped):
        try:
            ctypes.set_last_error(0)
            cancelled = self.kernel32.CancelIoEx(port, ctypes.byref(overlapped))
            error = ctypes.get_last_error()

            if not cancelled and error not in (0, ERROR_NOT_FOUND):
                return False

            wait_status = self.kernel32.WaitForSingleObject(overlapped.hEvent, 1000)

            if wait_status != WAIT_OBJECT_0:
                return False

            transferred = ctypes.wintypes.DWORD(0)
            self.kernel32.GetOverlappedResult(
                port, ctypes.byref(overlapped), ctypes.byref(transferred), False
            )
            return True
        except Exception:
            log_exception("PYAS_Driver.DriverMixin._cancel_driver_receive:774")
            return False

    def _receive_driver_message(self, port):
        message = PYAS_FULL_MESSAGE()
        overlapped = OVERLAPPED()
        event_handle = self.kernel32.CreateEventW(None, True, False, None)

        if not event_handle:
            return "error", None

        overlapped.hEvent = event_handle

        try:
            status = self.fltlib.FilterGetMessage(
                port,
                ctypes.byref(message),
                ctypes.sizeof(PYAS_FULL_MESSAGE),
                ctypes.byref(overlapped),
            )

            if status == 0:
                return "message", message

            if (status & 0xFFFFFFFF) != HRESULT_IO_PENDING:
                return "disconnect", None

            while True:
                if self.driver_stop_event.is_set():
                    self._cancel_driver_receive(port, overlapped)
                    return "stop", None

                wait_status = self.kernel32.WaitForSingleObject(event_handle, 20)

                if wait_status == WAIT_TIMEOUT:
                    continue

                if wait_status != WAIT_OBJECT_0:
                    self._cancel_driver_receive(port, overlapped)
                    return "error", None

                transferred = ctypes.wintypes.DWORD(0)

                if self.kernel32.GetOverlappedResult(
                    port, ctypes.byref(overlapped), ctypes.byref(transferred), False
                ):
                    return "message", message

                error = ctypes.get_last_error()

                if error == ERROR_OPERATION_ABORTED and self.driver_stop_event.is_set():
                    return "stop", None

                return "disconnect", None
        finally:
            self.kernel32.CloseHandle(event_handle)

    def pipe_server_thread(self):
        owned_port = None
        ready = False

        try:
            while self._driver_listener_should_run():
                temp_port = self._connect_driver_port(asynchronous=True)

                if not temp_port:
                    self.driver_stop_event.wait(0.02)
                    continue

                if not self._driver_listener_should_run():
                    self.kernel32.CloseHandle(temp_port)
                    break

                with self.lock_driver:
                    if self.driver_port:
                        accepted = False
                    else:
                        self.driver_port = temp_port
                        owned_port = temp_port
                        accepted = True

                if not accepted:
                    self.kernel32.CloseHandle(temp_port)
                    self.driver_stop_event.wait(0.02)
                    continue

                rule_files = []

                if os.path.exists(self.path_rules):
                    rule_files = sorted(
                        os.path.join(self.path_rules, name)
                        for name in os.listdir(self.path_rules)
                        if name.lower().endswith(".json") and name.lower() != "rules_driver_p1.json"
                    )

                load_failed = False

                for rule_file in rule_files:
                    if self.driver_stop_event.is_set() or not self.load_driver_rule_file(rule_file):
                        load_failed = True
                        break

                if load_failed:
                    self.driver_listener_failed_event.set()
                    break

                with self.lock_config:
                    whitelist = list(self.pyas_config.get("white_list", []))

                for item in whitelist:
                    if self.driver_stop_event.is_set():
                        break

                    if isinstance(item, dict) and item.get("file"):
                        self.sync_driver_whitelist(item["file"], True, item.get("is_dir"))

                if self.driver_stop_event.is_set():
                    break

                ready = True
                self.driver_listener_ready_event.set()

                while self._driver_listener_should_run():
                    with self.lock_driver:
                        current_port = self.driver_port
                        owns_current = self._driver_handle_value(
                            current_port
                        ) == self._driver_handle_value(owned_port)

                    if not owns_current:
                        break

                    receive_state, message = self._receive_driver_message(owned_port)

                    if receive_state != "message":
                        break

                    code = message.Data.MessageCode
                    pid = message.Data.ProcessId
                    target = message.Data.Path
                    exe_info = self.get_exe_info(pid)
                    safe_source = exe_info[1] if exe_info and exe_info[1] else "Unknown"

                    # 记下「这个路径是谁写的」:驱动事件是唯一在文件关闭后仍可回溯的来源
                    try:
                        from PYAS_Attribution import get_layer

                        get_layer().record_driver(target, pid, safe_source)
                    except Exception:
                        log_exception('PYAS_Driver.record_attribution')

                    if not self.is_in_whitelist(safe_source):
                        self.write_log(
                            "BLOCK",
                            "Driver Block",
                            detail="Driver protection event",
                            pid=pid,
                            source=safe_source,
                            target=target,
                            code=code,
                            file_hash=self.calc_file_hash(safe_source),
                            operate=None,
                            success=True,
                        )
                        # 驱动拦截永远不经弹窗,托盘通知是用户唯一知情渠道
                        if hasattr(self, "trigger_block_notification"):
                            self.trigger_block_notification("Driver Block", safe_source, target, code)

                self._close_driver_port(owned_port)
                owned_port = None
                ready = False
                self.driver_listener_ready_event.clear()

                if self.driver_stop_event.is_set():
                    break

                self.driver_stop_event.wait(0.02)

        except Exception as e:
            log_exception("PYAS_Driver.DriverMixin.pipe_server_thread:928")
            self.driver_listener_failed_event.set()

            if not self.driver_stop_event.is_set():
                self.write_log("WARN", "pipe_server_thread", detail=str(e), success=False)

        finally:
            if owned_port:
                try:
                    self.kernel32.CancelIoEx(owned_port, None)
                except Exception:
                    log_exception("PYAS_Driver.DriverMixin.pipe_server_thread:937")
                    pass

                self._close_driver_port(owned_port)

            if not ready and not self.driver_stop_event.is_set():
                self.driver_listener_failed_event.set()

            self.driver_listener_ready_event.clear()

            with self.lock_driver:
                if self.driver_listener_thread is threading.current_thread():
                    self.driver_listener_thread = None
