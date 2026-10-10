from PYAS_Diagnostics import log_exception
import ctypes
import ctypes.wintypes
import threading


WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
WS_POPUP = 0x80000000
WS_CAPTION = 0x00C00000
WS_SYSMENU = 0x00080000
WS_VSCROLL = 0x00200000
WS_EX_TOPMOST = 0x00000008

SS_LEFT = 0x00000000
ES_MULTILINE = 0x00000004
ES_AUTOVSCROLL = 0x00000040
ES_READONLY = 0x00000800

BS_PUSHBUTTON = 0x00000000
BS_DEFPUSHBUTTON = 0x00000001

WM_COMMAND = 0x0111
WM_TIMER = 0x0113
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_SETFONT = 0x0030

ID_BLOCK_BUTTON = 1001
ID_ALLOW_BUTTON = 1002
ID_COUNTDOWN_TIMER = 1

SPI_GETWORKAREA = 0x0030
HWND_TOPMOST = -1
SWP_SHOWWINDOW = 0x0040
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001

MB_ICONWARNING = 0x00000030
FW_BOLD = 700
OUT_DEFAULT_PRECIS = 0
CLIP_DEFAULT_PRECIS = 0
CLEARTYPE_QUALITY = 5
DEFAULT_PITCH = 0
FF_DONTCARE = 0
ERROR_CLASS_ALREADY_EXISTS = 1410
COLOR_BTNFACE = 15

DIALOG_CLASS_NAME = "PYAS_ThreatDialog"
DIALOG_STYLE = WS_POPUP | WS_CAPTION | WS_SYSMENU
DIALOG_WIDTH = 500
DIALOG_HEIGHT = 300
DIALOG_MARGIN = 16

INTERACTIVE_TIMEOUT_MIN = 5
INTERACTIVE_TIMEOUT_MAX = 300
INTERACTIVE_TIMEOUT_DEFAULT = 30

WNDPROC_TYPE = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t,
    ctypes.wintypes.HWND,
    ctypes.wintypes.UINT,
    ctypes.wintypes.WPARAM,
    ctypes.wintypes.LPARAM,
)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", ctypes.c_uint),
        ("lpfnWndProc", WNDPROC_TYPE),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", ctypes.wintypes.HINSTANCE),
        ("hIcon", ctypes.wintypes.HICON),
        ("hCursor", ctypes.wintypes.HANDLE),
        ("hbrBackground", ctypes.wintypes.HBRUSH),
        ("lpszMenuName", ctypes.wintypes.LPCWSTR),
        ("lpszClassName", ctypes.wintypes.LPCWSTR),
    ]


class MINMAXINFO(ctypes.Structure):
    _fields_ = [
        ("ptReserved", ctypes.wintypes.POINT),
        ("ptMaxSize", ctypes.wintypes.POINT),
        ("ptMaxPosition", ctypes.wintypes.POINT),
        ("ptMinTrackSize", ctypes.wintypes.POINT),
        ("ptMaxTrackSize", ctypes.wintypes.POINT),
    ]


DIALOG_TEXTS = {
    "btn_block": {
        "traditional_switch": "攔截",
        "simplified_switch": "拦截",
        "english_switch": "Block",
        "japanese_switch": "ブロック",
        "korean_switch": "차단",
        "french_switch": "Bloquer",
        "spanish_switch": "Bloquear",
        "hindi_switch": "ब्लॉक करें",
        "arabic_switch": "حظر",
        "russian_switch": "Блокировать",
        "slovenian_switch": "Blokiraj",
    },
    "btn_allow": {
        "traditional_switch": "放行",
        "simplified_switch": "放行",
        "english_switch": "Allow",
        "japanese_switch": "許可",
        "korean_switch": "허용",
        "french_switch": "Autoriser",
        "spanish_switch": "Permitir",
        "hindi_switch": "अनुमति दें",
        "arabic_switch": "السماح",
        "russian_switch": "Разрешить",
        "slovenian_switch": "Dovoli",
    },
    "label_source": {
        "traditional_switch": "來源",
        "simplified_switch": "来源",
        "english_switch": "Source",
        "japanese_switch": "ソース",
        "korean_switch": "소스",
        "french_switch": "Source",
        "spanish_switch": "Origen",
        "hindi_switch": "स्रोत",
        "arabic_switch": "المصدر",
        "russian_switch": "Источник",
        "slovenian_switch": "Vir",
    },
    "label_target": {
        "traditional_switch": "目標",
        "simplified_switch": "目标",
        "english_switch": "Target",
        "japanese_switch": "ターゲット",
        "korean_switch": "대상",
        "french_switch": "Cible",
        "spanish_switch": "Destino",
        "hindi_switch": "लक्ष्य",
        "arabic_switch": "الهدف",
        "russian_switch": "Цель",
        "slovenian_switch": "Cilj",
    },
    "label_pid": {
        "traditional_switch": "進程",
        "simplified_switch": "进程",
        "english_switch": "Process",
        "japanese_switch": "プロセス",
        "korean_switch": "프로세스",
        "french_switch": "Processus",
        "spanish_switch": "Proceso",
        "hindi_switch": "प्रक्रिया",
        "arabic_switch": "العملية",
        "russian_switch": "Процесс",
        "slovenian_switch": "Proces",
    },
    "countdown_auto_block": {
        "traditional_switch": "{0} 秒後自動攔截",
        "simplified_switch": "{0} 秒后自动拦截",
        "english_switch": "Auto block in {0}s",
        "japanese_switch": "{0} 秒後に自動ブロック",
        "korean_switch": "{0}초 후 자동 차단",
        "french_switch": "Blocage automatique dans {0} s",
        "spanish_switch": "Bloqueo automático en {0} s",
        "hindi_switch": "{0} सेकंड में स्वतः ब्लॉक",
        "arabic_switch": "حظر تلقائي بعد {0} ثانية",
        "russian_switch": "Автоблокировка через {0} с",
        "slovenian_switch": "Samodejna blokada čez {0} s",
    },
}

THREAT_DESCRIPTIONS = {
    "Process Block": {
        "traditional_switch": "偵測到可疑程式正在啟動，現已暫停並等待您處理。攔截將終止該進程；放行將恢復其執行。",
        "simplified_switch": "检测到可疑程序正在启动，现已暂停并等待您处理。拦截将终止该进程；放行将恢复其运行。",
        "english_switch": "A suspicious program was detected while starting and is now suspended. Block terminates the process; Allow resumes it.",
        "japanese_switch": "不審なプログラムの起動を検出し、現在停止中です。ブロックでプロセスを終了、許可で実行を再開します。",
        "korean_switch": "수상한 프로그램 시작이 감지되어 일시 중지되었습니다. 차단하면 프로세스가 종료되고, 허용하면 다시 실행됩니다.",
        "french_switch": "Un programme suspect a été détecté au démarrage et est suspendu. Bloquer termine le processus ; Autoriser le reprend.",
        "spanish_switch": "Se detectó un programa sospechoso al iniciarse y está suspendido. Bloquear termina el proceso; Permitir lo reanuda.",
        "hindi_switch": "एक संदिग्ध प्रोग्राम शुरू होते समय पाया गया और निलंबित है। ब्लॉक करने पर प्रक्रिया समाप्त होगी; अनुमति देने पर वह फिर चलेगी।",
        "arabic_switch": "تم اكتشاف برنامج مريب أثناء بدء التشغيل وقد أُوقف مؤقتًا. الحظر ينهي العملية؛ والسماح يستأنفها.",
        "russian_switch": "Подозрительная программа обнаружена при запуске и приостановлена. Блокировка завершит процесс; разрешение возобновит его.",
        "slovenian_switch": "Sumljiv program je bil zaznan ob zagonu in je začasno ustavljen. Blokada konča proces; dovoljenje ga nadaljuje.",
    },
    "Process DLL Block": {
        "traditional_switch": "偵測到可疑模組正被載入進程記憶體。攔截將終止該進程；放行將繼續載入。",
        "simplified_switch": "检测到可疑模块正被加载进进程内存。拦截将终止该进程；放行将继续加载。",
        "english_switch": "A suspicious module was detected loading into process memory. Block terminates the process; Allow continues loading.",
        "japanese_switch": "不審なモジュールのメモリへの読み込みを検出しました。ブロックでプロセスを終了、許可で読み込みを続行します。",
        "korean_switch": "수상한 모듈이 프로세스 메모리에 로드되는 것이 감지되었습니다. 차단하면 프로세스가 종료되고, 허용하면 계속 로드됩니다.",
        "french_switch": "Un module suspect a été détecté en cours de chargement en mémoire. Bloquer termine le processus ; Autoriser continue.",
        "spanish_switch": "Se detectó un módulo sospechoso cargándose en memoria. Bloquear termina el proceso; Permitir continúa la carga.",
        "hindi_switch": "प्रक्रिया मेमोरी में लोड हो रहा एक संदिग्ध मॉड्यूल पाया गया। ब्लॉक करने पर प्रक्रिया समाप्त होगी; अनुमति देने पर लोडिंग जारी रहेगी।",
        "arabic_switch": "تم اكتشاف وحدة مريبة تُحمَّل في ذاكرة العملية. الحظر ينهي العملية؛ والسماح يكمل التحميل.",
        "russian_switch": "Обнаружена загрузка подозрительного модуля в память процесса. Блокировка завершит процесс; разрешение продолжит загрузку.",
        "slovenian_switch": "Zaznan je bil sumljiv modul, ki se nalaga v pomnilnik procesa. Blokada konča proces; dovoljenje nadaljuje nalaganje.",
    },
    "File Block": {
        "traditional_switch": "偵測到可疑檔案已建立，彈窗期間已暫時鎖定以阻止執行。攔截將移入隔離區；放行將解除鎖定。",
        "simplified_switch": "检测到可疑文件已创建，弹窗期间已暂时锁定以阻止执行。拦截将移入隔离区；放行将解除锁定。",
        "english_switch": "A suspicious file was detected and temporarily locked to prevent execution. Block moves it to quarantine; Allow unlocks it.",
        "japanese_switch": "不審なファイルの作成を検出し、実行を防ぐため一時ロック中です。ブロックで隔離、許可でロック解除します。",
        "korean_switch": "수상한 파일 생성이 감지되어 실행을 막기 위해 임시 잠금 중입니다. 차단하면 격리하고, 허용하면 잠금이 해제됩니다.",
        "french_switch": "Un fichier suspect a été détecté et verrouillé pour empêcher son exécution. Bloquer le met en quarantaine ; Autoriser le déverrouille.",
        "spanish_switch": "Se detectó un archivo sospechoso y se bloqueó para impedir su ejecución. Bloquear lo envía a cuarentena; Permitir lo desbloquea.",
        "hindi_switch": "एक संदिग्ध फ़ाइल पाई गई और निष्पादन रोकने हेतु अस्थायी रूप से लॉक है। ब्लॉक करने पर क्वारंटाइन होगी; अनुमति देने पर अनलॉक होगी।",
        "arabic_switch": "تم اكتشاف ملف مريب وقُفل مؤقتًا لمنع تنفيذه. الحظر ينقله للحجر الصحي؛ والسماح يفك القفل.",
        "russian_switch": "Обнаружен подозрительный файл, временно заблокированный от запуска. Блокировка переместит его в карантин; разрешение разблокирует.",
        "slovenian_switch": "Zaznjena je bila sumljiva datoteka in začasno zaklenjena. Blokada jo premakne v karanteno; dovoljenje odklene.",
    },
    "Network Block": {
        "traditional_switch": "偵測到進程正連接已知惡意位址。攔截將終止該進程；放行將允許此次連接。",
        "simplified_switch": "检测到进程正连接已知恶意地址。拦截将终止该进程；放行将允许此次连接。",
        "english_switch": "The process was detected connecting to a known malicious address. Block terminates the process; Allow permits the connection.",
        "japanese_switch": "既知の悪意のあるアドレスへの接続を検出しました。ブロックでプロセスを終了、許可で接続を許可します。",
        "korean_switch": "프로세스가 알려진 악성 주소에 연결하는 것이 감지되었습니다. 차단하면 프로세스가 종료되고, 허용하면 연결이 허용됩니다.",
        "french_switch": "Le processus tente de se connecter à une adresse malveillante connue. Bloquer termine le processus ; Autoriser la connexion.",
        "spanish_switch": "El proceso intenta conectarse a una dirección maliciosa conocida. Bloquear termina el proceso; Permitir la conexión.",
        "hindi_switch": "प्रक्रिया किसी ज्ञात दुर्भावनापूर्ण पते से जुड़ रही पाई गई। ब्लॉक करने पर प्रक्रिया समाप्त होगी; अनुमति देने पर कनेक्शन स्वीकृत होगा।",
        "arabic_switch": "تُحاول العملية الاتصال بعنوان ضار معروف. الحظر ينهي العملية؛ والسماح يسمح بالاتصال.",
        "russian_switch": "Процесс подключается к известному вредоносному адресу. Блокировка завершит процесс; разрешение допустит соединение.",
        "slovenian_switch": "Proces se povezuje z znano zlonamerno naslovom. Blokada konča proces; dovoljenje omogoča povezavo.",
    },
    "Deferred Scan Block": {
        "traditional_switch": "重新掃描確認此檔案為惡意檔案。攔截將移入隔離區；放行將保留該檔案。",
        "simplified_switch": "重新扫描确认此文件为恶意文件。拦截将移入隔离区；放行将保留该文件。",
        "english_switch": "A rescan confirmed this file is malicious. Block moves it to quarantine; Allow keeps the file.",
        "japanese_switch": "再スキャンでこのファイルが悪意のあるものと確認されました。ブロックで隔離、許可で保持します。",
        "korean_switch": "재검사에서 이 파일이 악성으로 확인되었습니다. 차단하면 격리하고, 허용하면 파일을 유지합니다.",
        "french_switch": "Une nouvelle analyse confirme que ce fichier est malveillant. Bloquer le met en quarantaine ; Autoriser le conserve.",
        "spanish_switch": "Un nuevo análisis confirmó que el archivo es malicioso. Bloquear lo envía a cuarentena; Permitir lo conserva.",
        "hindi_switch": "पुनः स्कैन ने पुष्टि की कि यह फ़ाइल दुर्भावनापूर्ण है। ब्लॉक करने पर क्वारंटाइन होगी; अनुमति देने पर फ़ाइल रहेगी।",
        "arabic_switch": "أكد الفحص مجددًا أن هذا الملف ضار. الحظر ينقله للحجر الصحي؛ والسماح يحتفظ بالملف.",
        "russian_switch": "Повторная проверка подтвердила, что файл вредоносный. Блокировка переместит его в карантин; разрешение сохранит файл.",
        "slovenian_switch": "Ponovno pregledovanje je potrdilo, da je datoteka zlonamerna. Blokada jo premakne v karanteno; dovoljenje jo ohrani.",
    },
}

SUPPORTED_LANGS = frozenset(DIALOG_TEXTS["btn_block"].keys())


def loc_dialog_text(lang, key):
    text_dict = DIALOG_TEXTS.get(key, {})
    return text_dict.get(lang) or text_dict.get("traditional_switch", "")


def loc_threat_description(lang, action):
    text_dict = THREAT_DESCRIPTIONS.get(action, {})
    return text_dict.get(lang) or text_dict.get("traditional_switch", "")


class _ThreatDialogSession:
    _class_counter = 0

    def __init__(self, lang, title, message, timeout, countdown_formatter):
        self.lang = lang
        self.title = title
        self.message = message
        self.timeout = max(1, int(timeout))
        self.countdown_formatter = countdown_formatter
        self.choice = "block"
        self.hwnd = None
        self.labels = {}
        self.font_title = None
        self.font_body = None
        self.wndproc_ref = None
        self.remaining = self.timeout
        _ThreatDialogSession._class_counter += 1
        self.class_name = f"{DIALOG_CLASS_NAME}_{_ThreatDialogSession._class_counter}"

    @property
    def user32(self):
        return ctypes.windll.user32

    def run(self):
        self._ensure_api()
        instance = ctypes.windll.kernel32.GetModuleHandleW(None)
        scale = self._dpi_scale()
        frame = ctypes.wintypes.RECT(0, 0, int(DIALOG_WIDTH * scale), int(DIALOG_HEIGHT * scale))

        if self.user32.AdjustWindowRectEx(ctypes.byref(frame), DIALOG_STYLE, False, WS_EX_TOPMOST):
            window_width = frame.right - frame.left
            window_height = frame.bottom - frame.top
        else:
            window_width = int(DIALOG_WIDTH * scale)
            window_height = int(DIALOG_HEIGHT * scale)

        work_area = ctypes.wintypes.RECT()

        if self.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(work_area), 0):
            pos_x = work_area.right - window_width - int(DIALOG_MARGIN * scale)
            pos_y = work_area.bottom - window_height - int(DIALOG_MARGIN * scale)
        else:
            pos_x = int(DIALOG_MARGIN * scale)
            pos_y = int(DIALOG_MARGIN * scale)

        try:
            return self._run_window(instance, pos_x, pos_y, window_width, window_height, scale)
        finally:
            if self.hwnd:
                try:
                    self.user32.DestroyWindow(self.hwnd)
                except Exception:
                    pass

                self.hwnd = None

            for font in (self.font_title, self.font_body):
                if font:
                    try:
                        ctypes.windll.gdi32.DeleteObject(font)
                    except Exception:
                        pass

            self.font_title = None
            self.font_body = None
            self.user32.UnregisterClassW(self.class_name, instance)

    def _run_window(self, instance, pos_x, pos_y, window_width, window_height, scale):
        self.wndproc_ref = WNDPROC_TYPE(self.wndproc)
        window_class = WNDCLASSW()
        window_class.lpfnWndProc = self.wndproc_ref
        window_class.lpszClassName = self.class_name
        window_class.hInstance = instance
        window_class.hCursor = self.user32.LoadCursorW(None, ctypes.wintypes.LPCWSTR(32512))
        window_class.hbrBackground = ctypes.wintypes.HBRUSH(COLOR_BTNFACE + 1)
        ctypes.set_last_error(0)
        atom = self.user32.RegisterClassW(ctypes.byref(window_class))

        if not atom and ctypes.get_last_error() != ERROR_CLASS_ALREADY_EXISTS:
            return "block"

        self.hwnd = self.user32.CreateWindowExW(
            WS_EX_TOPMOST,
            self.class_name,
            self.title,
            DIALOG_STYLE,
            pos_x,
            pos_y,
            window_width,
            window_height,
            None,
            None,
            instance,
            None,
        )

        if not self.hwnd:
            return "block"

        client = ctypes.wintypes.RECT()
        self.user32.GetClientRect(self.hwnd, ctypes.byref(client))
        self._build_controls(client.right, client.bottom, scale)
        self.update_countdown()
        self.user32.SetWindowPos(
            self.hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW
        )
        self.user32.SetForegroundWindow(self.hwnd)
        self.user32.MessageBeep(MB_ICONWARNING)
        self.user32.SetTimer(self.hwnd, ID_COUNTDOWN_TIMER, 1000, None)

        msg = ctypes.wintypes.MSG()

        while self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            self.user32.TranslateMessage(ctypes.byref(msg))
            self.user32.DispatchMessageW(ctypes.byref(msg))

        return self.choice

    def wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_COMMAND:
            command_id = wparam & 0xFFFF

            if command_id == ID_BLOCK_BUTTON:
                self.choice = "block"
                self.user32.DestroyWindow(hwnd)
                return 0

            if command_id == ID_ALLOW_BUTTON:
                self.choice = "allow"
                self.user32.DestroyWindow(hwnd)
                return 0

        elif msg == WM_TIMER:
            if wparam == ID_COUNTDOWN_TIMER:
                self.remaining -= 1
                self.update_countdown()

                if self.remaining <= 0:
                    self.choice = "block"
                    self.user32.DestroyWindow(hwnd)

            return 0

        elif msg == WM_CLOSE:
            self.choice = "block"
            self.user32.DestroyWindow(hwnd)
            return 0

        elif msg == WM_DESTROY:
            self.user32.KillTimer(hwnd, ID_COUNTDOWN_TIMER)
            ctypes.windll.user32.PostQuitMessage(0)
            return 0

        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def update_countdown(self):
        if self.hwnd and self.labels.get("countdown"):
            text = self.countdown_formatter(max(0, self.remaining))
            self.user32.SetWindowTextW(self.labels["countdown"], text)

    def _build_controls(self, width, height, scale):
        pad = int(20 * scale)
        line_height = int(24 * scale)
        button_width = int(96 * scale)
        button_height = int(34 * scale)
        countdown_height = int(22 * scale)
        button_y = height - pad - button_height
        countdown_y = button_y - int(8 * scale) - countdown_height
        self.font_title = ctypes.windll.gdi32.CreateFontW(
            -int(17 * scale),
            0, 0, 0,
            FW_BOLD, 0, 0, 0,
            0, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE,
            "Segoe UI",
        )
        self.font_body = ctypes.windll.gdi32.CreateFontW(
            -int(14 * scale),
            0, 0, 0,
            400, 0, 0, 0,
            0, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE,
            "Segoe UI",
        )
        title_label = self._create_control(
            "STATIC", SS_LEFT, pad, pad, width - pad * 2, line_height, self.title
        )
        self.labels["title"] = title_label
        message_top = pad + line_height + int(8 * scale)
        message_height = countdown_y - int(8 * scale) - message_top
        self.labels["message"] = self._create_control(
            "EDIT",
            ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            pad,
            message_top,
            width - pad * 2,
            message_height,
            self.message,
        )
        self.labels["countdown"] = self._create_control(
            "STATIC",
            SS_LEFT,
            pad,
            countdown_y,
            int(260 * scale),
            countdown_height,
            "",
        )
        self._create_control(
            "BUTTON",
            BS_PUSHBUTTON,
            width - pad - button_width * 2 - int(10 * scale),
            button_y,
            button_width,
            button_height,
            loc_dialog_text(self.lang, "btn_allow"),
            ID_ALLOW_BUTTON,
        )
        self._create_control(
            "BUTTON",
            BS_DEFPUSHBUTTON,
            width - pad - button_width,
            button_y,
            button_width,
            button_height,
            loc_dialog_text(self.lang, "btn_block"),
            ID_BLOCK_BUTTON,
        )

        if self.font_title:
            self.user32.SendMessageW(title_label, WM_SETFONT, self.font_title, 1)

        if self.font_body:
            for control in (self.labels["message"], self.labels["countdown"]):
                self.user32.SendMessageW(control, WM_SETFONT, self.font_body, 1)

    def _create_control(self, class_name, style, x, y, width, height, text, control_id=0):
        return self.user32.CreateWindowExW(
            0,
            class_name,
            text,
            WS_CHILD | WS_VISIBLE | style,
            x,
            y,
            width,
            height,
            self.hwnd,
            control_id,
            None,
            None,
        )

    def _ensure_api(self):
        user32 = self.user32
        user32.CreateWindowExW.argtypes = [
            ctypes.wintypes.DWORD,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.LPCWSTR,
            ctypes.wintypes.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.wintypes.HWND,
            ctypes.wintypes.HMENU,
            ctypes.wintypes.HINSTANCE,
            ctypes.c_void_p,
        ]
        user32.CreateWindowExW.restype = ctypes.wintypes.HWND
        user32.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
        user32.RegisterClassW.restype = ctypes.wintypes.WORD
        user32.UnregisterClassW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.HINSTANCE]
        user32.UnregisterClassW.restype = ctypes.wintypes.BOOL
        user32.DefWindowProcW.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.UINT,
            ctypes.wintypes.WPARAM,
            ctypes.wintypes.LPARAM,
        ]
        user32.DefWindowProcW.restype = ctypes.c_ssize_t
        user32.DestroyWindow.argtypes = [ctypes.wintypes.HWND]
        user32.DestroyWindow.restype = ctypes.wintypes.BOOL
        user32.SetWindowTextW.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.LPCWSTR]
        user32.SetWindowTextW.restype = ctypes.wintypes.BOOL
        user32.SetTimer.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
        ]
        user32.SetTimer.restype = ctypes.c_void_p
        user32.KillTimer.argtypes = [ctypes.wintypes.HWND, ctypes.c_uint]
        user32.KillTimer.restype = ctypes.wintypes.BOOL
        user32.GetMessageW.argtypes = [
            ctypes.POINTER(ctypes.wintypes.MSG),
            ctypes.wintypes.HWND,
            ctypes.c_uint,
            ctypes.c_uint,
        ]
        user32.GetMessageW.restype = ctypes.wintypes.BOOL
        user32.PostQuitMessage.argtypes = [ctypes.c_int]
        user32.SetWindowPos.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.HWND,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.wintypes.UINT,
        ]
        user32.SetWindowPos.restype = ctypes.wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [ctypes.wintypes.HWND]
        user32.SetForegroundWindow.restype = ctypes.wintypes.BOOL
        user32.SystemParametersInfoW.argtypes = [
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_uint,
        ]
        user32.SystemParametersInfoW.restype = ctypes.wintypes.BOOL
        user32.LoadCursorW.argtypes = [ctypes.wintypes.HINSTANCE, ctypes.wintypes.LPCWSTR]
        user32.LoadCursorW.restype = ctypes.wintypes.HANDLE
        gdi32 = ctypes.windll.gdi32
        gdi32.CreateFontW.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.wintypes.LPCWSTR,
        ]
        gdi32.CreateFontW.restype = ctypes.wintypes.HFONT
        gdi32.DeleteObject.argtypes = [ctypes.wintypes.HANDLE]
        gdi32.DeleteObject.restype = ctypes.wintypes.BOOL
        user32.SendMessageW.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.UINT,
            ctypes.wintypes.WPARAM,
            ctypes.wintypes.LPARAM,
        ]
        user32.SendMessageW.restype = ctypes.c_ssize_t
        user32.MessageBeep.argtypes = [ctypes.c_uint]
        user32.MessageBeep.restype = ctypes.wintypes.BOOL
        ctypes.windll.kernel32.GetModuleHandleW.argtypes = [ctypes.wintypes.LPCWSTR]
        ctypes.windll.kernel32.GetModuleHandleW.restype = ctypes.wintypes.HMODULE

    def _dpi_scale(self):
        try:
            get_dpi = getattr(self.user32, "GetDpiForSystem", None)

            if get_dpi:
                dpi = get_dpi() or 96
                return dpi / 96.0

        except Exception:
            log_exception("PYAS_Dialog._ThreatDialogSession._dpi_scale")

        return 1.0


class DialogMixin:
    def get_interactive_timeout(self):
        with self.lock_config:
            try:
                timeout = int(
                    self.pyas_config.get("interactive_timeout", INTERACTIVE_TIMEOUT_DEFAULT)
                )
            except Exception:
                timeout = INTERACTIVE_TIMEOUT_DEFAULT

        return max(INTERACTIVE_TIMEOUT_MIN, min(timeout, INTERACTIVE_TIMEOUT_MAX))

    def get_interactive_lang(self):
        with self.lock_config:
            lang = self.pyas_config.get("language", "traditional_switch")

        return lang if lang in SUPPORTED_LANGS else "traditional_switch"

    def request_block_decision(self, action, source=None, target=None, pid=None):
        with self.lock_config:
            if not self.pyas_config.get("interactive_switch", False):
                return True

        lang = self.get_interactive_lang()
        title = self.get_block_action_title(action)
        lines = [loc_threat_description(lang, action)]

        if source:
            lines.append(f"{loc_dialog_text(lang, 'label_source')}: {source}")

        if target:
            lines.append(f"{loc_dialog_text(lang, 'label_target')}: {target}")

        if pid:
            lines.append(f"{loc_dialog_text(lang, 'label_pid')}: {pid}")

        timeout = self.get_interactive_timeout()
        return self.show_threat_prompt(title, "\r\n".join(lines), timeout)

    def show_threat_prompt(self, title, message, timeout=INTERACTIVE_TIMEOUT_DEFAULT):
        result = {"choice": "block"}
        done = threading.Event()
        lock_interactive = getattr(self, "lock_interactive", None) or threading.RLock()

        def run():
            try:
                with lock_interactive:
                    session = _ThreatDialogSession(
                        self.get_interactive_lang(),
                        title,
                        message,
                        timeout,
                        lambda remaining: loc_dialog_text(
                            self.get_interactive_lang(), "countdown_auto_block"
                        ).replace("{0}", str(remaining)),
                    )
                    result["choice"] = session.run()
            except Exception:
                log_exception("PYAS_Dialog.DialogMixin.show_threat_prompt.run")
                result["choice"] = "block"
            finally:
                done.set()

        worker = threading.Thread(target=run, daemon=True, name="PYAS.ThreatDialog")
        worker.start()

        if not done.wait(timeout + 15):
            return True

        return result["choice"] != "allow"
