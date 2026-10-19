#define AppId "{{a7d7bac3-93b8-4630-8308-c7a56bf7fdf4}"
#define AppName "PYAS"
#define AppVersion "3.7.1.15"
#define AppPublisher "PYAS Security"
#define AppURL "https://github.com/upcyan/PYAS_cyanmod"
#define AppExeName "PYAS.exe"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName} Setup
VersionInfoProductVersion={#AppVersion}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppPublisher}\{#AppName}
AllowNoIcons=yes
LicenseFile=SetupResources\licence.rtf
ShowLanguageDialog=yes
WizardStyle=modern
WizardImageFile=SetupResources\wizardImage.bmp
WizardSmallImageFile=SetupResources\headerImage.png
SetupIconFile=Payload\Interface\static\img\icon.ico
UninstallDisplayIcon={app}\{#AppExeName}
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
; 防止重复点击安装包启动多个安装程序实例(Inno 6.3+ 指令)
SetupMutex=PYAS_Setup_Mutex
Compression=lzma2/max
SolidCompression=yes
OutputDir=Output
OutputBaseFilename=PYAS_Setup
UsePreviousTasks=no
SetupLogging=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "chinesetraditional"; MessagesFile: "compiler:Languages\ChineseTraditional.isl"
Name: "japanese"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "hindi"; MessagesFile: "compiler:Languages\Hindi.islu"
Name: "arabic"; MessagesFile: "compiler:Languages\Arabic.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "slovenian"; MessagesFile: "compiler:Languages\Slovenian.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "Redist\VC_redist.x64.exe"; DestDir: "{tmp}\PYAS_Redist"; Flags: deleteafterinstall ignoreversion; AfterInstall: EnsureVCRedist
Source: "Redist\MicrosoftEdgeWebview2Setup.exe"; Flags: dontcopy noencryption
Source: "SetupResources\stop_menu.ps1"; Flags: dontcopy noencryption
Source: "SetupResources\stop_menu.ps1"; DestDir: "{app}\Menu"; Flags: ignoreversion
Source: "Payload\Engine\*"; DestDir: "{app}\Engine"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\Interface\*"; DestDir: "{app}\Interface"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\License\*"; DestDir: "{app}\License"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\PYAS_Launcher.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "Payload\PYAS.exe"; DestDir: "{app}"; Flags: ignoreversion; AfterInstall: FinalizeDriverRemoval
Source: "Payload\PYAS_Menu.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "Payload\Menu\*"; DestDir: "{app}\Menu"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\Plugins\*"; DestDir: "{app}\Plugins"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; Machine policy lives in administrator-owned PYAS.Policy, initialized only by
; the fixed authorization helper. Runtime logs/preferences use LocalAppData.
; This deprecated directory must not grant new Users modify permissions.
Name: "{commonappdata}\PYAS"; Permissions: users-readexec
; The elevated helper's bootloader output lands here. Pre-creating it keeps the
; directory administrator-owned, so a standard user cannot plant a reparse point
; that would redirect the launcher's elevated write.
Name: "{commonappdata}\PYAS\Logs"; Permissions: users-readexec

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Menu\trust_menu.ps1"" -RespectConfig"; Flags: runhidden waituntilterminated; Check: IsModernMenuSupported
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Menu\register_menu.ps1"" -ExternalLocation ""{app}"" -RespectConfig"; Flags: runhidden waituntilterminated runasoriginaluser; Check: IsModernMenuSupported

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Menu\unregister_menu.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "PYASModernMenu"

[Registry]
Root: HKCU; Subkey: "Software\Classes\*\shell\PYAS_Scan"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Classes\Directory\shell\PYAS_Scan"; Flags: uninsdeletekey dontcreatekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "PYAS_Security"; Flags: uninsdeletevalue dontcreatekey

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\PYAS"

[Icons]
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\PYAS_Launcher.exe"; IconFilename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{group}\{#AppName}"; Filename: "{app}\PYAS_Launcher.exe"; IconFilename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Run]
; 用原始(未提权)用户令牌启动应用:PyInstaller 6.22+ 的 onefile 防篡改校验
; 只对提权进程生效,提权 postinstall 启动存在祖先进程退出时序竞态,会弹
; "Security validation failure: invalid originating onefile parent process"
Filename: "{app}\PYAS_Launcher.exe"; Description: "{cm:LaunchProgram,{#StringChange(AppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runasoriginaluser; Check: CanLaunchApp

[CustomMessages]
english.InstallingVCRuntime=Installing Microsoft Visual C++ Runtime...
english.InstallingWebView2Runtime=Installing Microsoft Edge WebView2 Runtime...
english.Dependencies=Dependencies:
english.InstallWebView2=Install Microsoft Edge WebView2 Runtime
english.InstallVCRedist=Install Microsoft Visual C++ Runtime
english.LegacyVersionDetected=An older version of PYAS was detected. Please uninstall it manually before installing.
english.QuitFailed=PYAS or its driver could not be stopped safely. Restart Windows and run Setup again.
english.QuitRetry=PYAS could not be closed automatically (attempt %1 of 3). Right-click the PYAS tray icon and choose Exit, then click Retry.
english.QuitRestart=PYAS is still running, so Setup cannot replace its files. Restart Windows and run Setup again.
english.DependencyInstallFailed=Required Microsoft runtime installation failed. Setup cannot continue.
english.WebView2InstallFailed=Microsoft Edge WebView2 Runtime could not be detected. Check your connection or install the Evergreen Runtime manually, then retry Setup.%n%nDetails: %1
chinesesimplified.InstallingVCRuntime=正在安装 Microsoft Visual C++ 运行库...
chinesesimplified.InstallingWebView2Runtime=正在安装 Microsoft Edge WebView2 运行时...
chinesesimplified.Dependencies=依赖组件:
chinesesimplified.InstallWebView2=安装 Microsoft Edge WebView2 运行时
chinesesimplified.InstallVCRedist=安装 Microsoft Visual C++ 运行库
chinesesimplified.LegacyVersionDetected=检测到旧版本 PYAS。请先手动卸载旧版，再运行本安装程序。
chinesesimplified.QuitFailed=无法安全停止 PYAS 或其驱动。请重启 Windows 后再次运行安装程序。
chinesesimplified.QuitRetry=无法自动关闭 PYAS（第 %1 次尝试，共 3 次）。请右键托盘中的 PYAS 图标退出程序，然后点击“重试”。
chinesesimplified.QuitRestart=PYAS 进程仍在运行，安装程序无法替换文件。请重启 Windows 后再次运行安装程序。
chinesesimplified.DependencyInstallFailed=必需的 Microsoft 运行库安装失败，安装程序无法继续。
chinesesimplified.WebView2InstallFailed=无法检测到 Microsoft Edge WebView2 运行时。请检查网络或手动安装常青版运行时，然后重试安装。%n%n详细信息：%1
chinesetraditional.InstallingVCRuntime=正在安裝 Microsoft Visual C++ 執行庫...
chinesetraditional.InstallingWebView2Runtime=正在安裝 Microsoft Edge WebView2 執行環境...
chinesetraditional.Dependencies=相依元件:
chinesetraditional.InstallWebView2=安裝 Microsoft Edge WebView2 執行環境
chinesetraditional.InstallVCRedist=安裝 Microsoft Visual C++ 執行庫
chinesetraditional.LegacyVersionDetected=偵測到舊版 PYAS。請先手動解除安裝舊版，再執行本安裝程式。
chinesetraditional.QuitFailed=無法安全停止 PYAS 或其驅動。請重新啟動 Windows 後再次執行安裝程式。
chinesetraditional.QuitRetry=無法自動關閉 PYAS（第 %1 次嘗試，共 3 次）。請右鍵點擊系統匣中的 PYAS 圖示結束程式，然後按「重試」。
chinesetraditional.QuitRestart=PYAS 處理程序仍在執行，安裝程式無法取代檔案。請重新啟動 Windows 後再執行安裝程式。
chinesetraditional.DependencyInstallFailed=必要的 Microsoft 執行庫安裝失敗，安裝程式無法繼續。
chinesetraditional.WebView2InstallFailed=無法偵測到 Microsoft Edge WebView2 執行環境。請檢查網路或手動安裝常青版執行環境，再重試安裝。%n%n詳細資訊：%1
japanese.InstallingVCRuntime=Microsoft Visual C++ ランタイムをインストールしています...
japanese.InstallingWebView2Runtime=Microsoft Edge WebView2 ランタイムをインストールしています...
japanese.Dependencies=依存コンポーネント:
japanese.InstallWebView2=Microsoft Edge WebView2 ランタイムをインストール
japanese.InstallVCRedist=Microsoft Visual C++ ランタイムをインストール
japanese.LegacyVersionDetected=旧バージョンの PYAS が検出されました。インストールする前に旧バージョンを手動でアンインストールしてください。
japanese.QuitFailed=PYAS またはそのドライバーを安全に停止できませんでした。Windows を再起動してから、セットアップを再実行してください。
japanese.QuitRetry=PYAS を自動で終了できませんでした（%1/3 回目）。タスクトレイの PYAS アイコンを右クリックして終了し、「再試行」をクリックしてください。
japanese.QuitRestart=PYAS がまだ実行中のため、セットアップはファイルを置き換えられません。Windows を再起動してからセットアップを再実行してください。
japanese.DependencyInstallFailed=必須の Microsoft ランタイムのインストールに失敗したため、セットアップを続行できません。
japanese.WebView2InstallFailed=Microsoft Edge WebView2 ランタイムを検出できませんでした。接続を確認するか、Evergreen ランタイムを手動でインストールしてから、セットアップを再実行してください。%n%n詳細: %1
korean.InstallingVCRuntime=Microsoft Visual C++ 런타임 설치 중...
korean.InstallingWebView2Runtime=Microsoft Edge WebView2 런타임 설치 중...
korean.Dependencies=종속 구성 요소:
korean.InstallWebView2=Microsoft Edge WebView2 런타임 설치
korean.InstallVCRedist=Microsoft Visual C++ 런타임 설치
korean.LegacyVersionDetected=이전 버전의 PYAS가 감지되었습니다. 설치하기 전에 이전 버전을 수동으로 제거하십시오.
korean.QuitFailed=PYAS 또는 해당 드라이버를 안전하게 중지하지 못했습니다. Windows를 다시 시작한 후 설치 프로그램을 다시 실행하십시오.
korean.QuitRetry=PYAS를 자동으로 종료하지 못했습니다(3회 중 %1회). 트레이의 PYAS 아이콘을 마우스 오른쪽 버튼으로 클릭해 종료한 뒤 '다시 시도'를 누르세요.
korean.QuitRestart=PYAS가 아직 실행 중이라 설치 프로그램이 파일을 교체할 수 없습니다. Windows를 다시 시작한 후 설치 프로그램을 다시 실행하십시오.
korean.DependencyInstallFailed=필수 Microsoft 런타임 설치에 실패하여 설치를 계속할 수 없습니다.
korean.WebView2InstallFailed=Microsoft Edge WebView2 런타임을 감지할 수 없습니다. 네트워크를 확인하거나 Evergreen 런타임을 수동으로 설치한 후 설치를 다시 시도하십시오.%n%n세부 정보: %1
french.InstallingVCRuntime=Installation du package Microsoft Visual C++ Redistributable...
french.InstallingWebView2Runtime=Installation du runtime Microsoft Edge WebView2...
french.Dependencies=Dépendances :
french.InstallWebView2=Installer le runtime Microsoft Edge WebView2
french.InstallVCRedist=Installer Microsoft Visual C++ Redistributable
french.LegacyVersionDetected=Une ancienne version de PYAS a été détectée. Veuillez la désinstaller manuellement avant de lancer l'installation.
french.QuitFailed=PYAS ou son pilote n'a pas pu être arrêté en toute sécurité. Redémarrez Windows et relancez l'installation.
french.QuitRetry=PYAS n'a pas pu être fermé automatiquement (tentative %1 sur 3). Quittez PYAS via l'icône de la zone de notification, puis cliquez sur Réessayer.
french.QuitRestart=PYAS est toujours en cours d'exécution : l'installation ne peut pas remplacer ses fichiers. Redémarrez Windows et relancez l'installation.
french.DependencyInstallFailed=L'installation des runtimes Microsoft requis a échoué. Impossible de continuer l'installation.
french.WebView2InstallFailed=Le runtime Microsoft Edge WebView2 n'a pas pu être détecté. Vérifiez votre connexion ou installez manuellement le runtime Evergreen, puis réessayez.%n%nDétails : %1
spanish.InstallingVCRuntime=Instalando Microsoft Visual C++ Redistributable...
spanish.InstallingWebView2Runtime=Instalando el runtime de Microsoft Edge WebView2...
spanish.Dependencies=Dependencias:
spanish.InstallWebView2=Instalar el runtime de Microsoft Edge WebView2
spanish.InstallVCRedist=Instalar Microsoft Visual C++ Redistributable
spanish.LegacyVersionDetected=Se detectó una versión anterior de PYAS. Desinstálela manualmente antes de ejecutar este programa de instalación.
spanish.QuitFailed=No se pudo detener PYAS o su controlador de forma segura. Reinicie Windows y vuelva a ejecutar el programa de instalación.
spanish.QuitRetry=No se pudo cerrar PYAS automáticamente (intento %1 de 3). Salga de PYAS desde el icono de la bandeja y pulse Reintentar.
spanish.QuitRestart=PYAS sigue en ejecución, así que el instalador no puede reemplazar sus archivos. Reinicie Windows y vuelva a ejecutar el instalador.
spanish.DependencyInstallFailed=Error al instalar los runtimes de Microsoft necesarios. El programa de instalación no puede continuar.
spanish.WebView2InstallFailed=No se pudo detectar el runtime de Microsoft Edge WebView2. Compruebe la conexión o instale manualmente el runtime Evergreen y reintente la instalación.%n%nDetalles: %1
hindi.InstallingVCRuntime=Microsoft Visual C++ रनटाइम इंस्टॉल हो रहा है...
hindi.InstallingWebView2Runtime=Microsoft Edge WebView2 रनटाइम इंस्टॉल हो रहा है...
hindi.Dependencies=निर्भरताएँ:
hindi.InstallWebView2=Microsoft Edge WebView2 रनटाइम इंस्टॉल करें
hindi.InstallVCRedist=Microsoft Visual C++ रनटाइम इंस्टॉल करें
hindi.LegacyVersionDetected=PYAS का पुराना संस्करण मिला। कृपया इंस्टॉल करने से पहले पुराने संस्करण को मैन्युअल रूप से अनइंस्टॉल करें।
hindi.QuitFailed=PYAS या उसके ड्राइवर को सुरक्षित रूप से बंद नहीं किया जा सका। Windows पुनरारंभ करें और सेटअप फिर से चलाएँ।
hindi.QuitRetry=PYAS को स्वतः बंद नहीं किया जा सका (%1/3 प्रयास)। ट्रे आइकन से PYAS बंद करें, फिर “पुनः प्रयास करें” दबाएँ।
hindi.QuitRestart=PYAS अभी भी चल रहा है, इसलिए सेटअप इसकी फ़ाइलें बदल नहीं सकता। Windows पुनः आरंभ करें और सेटअप फिर चलाएँ।
hindi.DependencyInstallFailed=आवश्यक Microsoft रनटाइम इंस्टॉलेशन विफल रहा। सेटअप जारी नहीं रह सकता।
hindi.WebView2InstallFailed=Microsoft Edge WebView2 रनटाइम का पता नहीं चल सका। कनेक्शन जांचें या Evergreen रनटाइम मैन्युअल रूप से इंस्टॉल करें, फिर सेटअप पुनः प्रयास करें।%n%nविवरण: %1
arabic.InstallingVCRuntime=جارٍ تثبيت Microsoft Visual C++ Runtime...
arabic.InstallingWebView2Runtime=جارٍ تثبيت Microsoft Edge WebView2 Runtime...
arabic.Dependencies=التبعيات:
arabic.InstallWebView2=تثبيت Microsoft Edge WebView2 Runtime
arabic.InstallVCRedist=تثبيت Microsoft Visual C++ Runtime
arabic.LegacyVersionDetected=تم اكتشاف إصدار قديم من PYAS. يرجى إلغاء تثبيته يدويًا قبل تشغيل برنامج التثبيت هذا.
arabic.QuitFailed=تعذر إيقاف PYAS أو برنامج التشغيل الخاص به بأمان. أعد تشغيل Windows ثم شغّل برنامج التثبيت مرة أخرى.
arabic.QuitRetry=تعذّر إغلاق PYAS تلقائيًا (المحاولة %1 من 3). أغلق PYAS من أيقونته في شريط النظام ثم اضغط «إعادة المحاولة».
arabic.QuitRestart=لا يزال PYAS قيد التشغيل، لذا لا يستطيع برنامج الإعداد استبدال ملفاته. أعد تشغيل Windows ثم شغّل برنامج الإعداد مرة أخرى.
arabic.DependencyInstallFailed=فشل تثبيت بيئات تشغيل Microsoft المطلوبة. لا يمكن لبرنامج التثبيت المتابعة.
arabic.WebView2InstallFailed=تعذر اكتشاف Microsoft Edge WebView2 Runtime. تحقق من الاتصال أو ثبّت Evergreen Runtime يدويًا ثم أعد محاولة التثبيت.%n%nالتفاصيل: %1
russian.InstallingVCRuntime=Установка распространяемого пакета Microsoft Visual C++...
russian.InstallingWebView2Runtime=Установка среды выполнения Microsoft Edge WebView2...
russian.Dependencies=Зависимости:
russian.InstallWebView2=Установить среду выполнения Microsoft Edge WebView2
russian.InstallVCRedist=Установить распространяемый пакет Microsoft Visual C++
russian.LegacyVersionDetected=Обнаружена старая версия PYAS. Удалите её вручную перед запуском программы установки.
russian.QuitFailed=Не удалось безопасно остановить PYAS или его драйвер. Перезапустите Windows и снова запустите программу установки.
russian.QuitRetry=Не удалось закрыть PYAS автоматически (попытка %1 из 3). Завершите PYAS через значок в области уведомлений и нажмите «Повторить».
russian.QuitRestart=PYAS всё ещё работает, поэтому установщик не может заменить его файлы. Перезагрузите Windows и снова запустите установщик.
russian.DependencyInstallFailed=Не удалось установить требуемые среды выполнения Microsoft. Установка не может быть продолжена.
russian.WebView2InstallFailed=Не удалось обнаружить среду выполнения Microsoft Edge WebView2. Проверьте подключение или вручную установите Evergreen Runtime, затем повторите установку.%n%nПодробности: %1
slovenian.InstallingVCRuntime=Nameščanje paketa Microsoft Visual C++ Runtime...
slovenian.InstallingWebView2Runtime=Nameščanje Microsoft Edge WebView2 Runtime...
slovenian.Dependencies=Odvisnosti:
slovenian.InstallWebView2=Namesti Microsoft Edge WebView2 Runtime
slovenian.InstallVCRedist=Namesti Microsoft Visual C++ Runtime
slovenian.LegacyVersionDetected=Zaznjena je bila starejša različica PYAS. Pred zagonom te namestitve jo ročno odstranite.
slovenian.QuitFailed=PYAS ali njegovega gonilnika ni bilo mogoče varno zaustaviti. Ponovno zaženite Windows in znova zaženite namestitev.
slovenian.QuitRetry=PYAS ni bilo mogoče samodejno zapreti (poskus %1 od 3). Zaprite PYAS prek ikone v sistemski vrstici in kliknite »Poskusi znova«.
slovenian.QuitRestart=PYAS še vedno teče, zato namestitveni program ne more zamenjati njegovih datotek. Znova zaženite Windows in nato namestitev.
slovenian.DependencyInstallFailed=Namestitev zahtevanih Microsoftovih izvajalnih knjižnic ni uspela. Namestitve ni mogoče nadaljevati.
slovenian.WebView2InstallFailed=Microsoft Edge WebView2 Runtime ni bilo mogoče zaznati. Preverite povezavo ali ročno namestite Evergreen Runtime in poskusite znova.%n%nPodrobnosti: %1

[Code]
var
  DependencyRestartRequired: Boolean;
  DependenciesReady: Boolean;

function FindWindow(lpClassName: LongWord; lpWindowName: string): HWND;
  external 'FindWindowW@user32.dll stdcall';

function FindWindowEx(Parent, Previous: HWND; ClassName: LongWord; Title: string): HWND;
  external 'FindWindowExW@user32.dll stdcall';
function GetClassName(Window: HWND; Buffer: string; Capacity: Integer): Integer;
  external 'GetClassNameW@user32.dll stdcall';
function GetWindowThreadProcessId(Window: HWND; var ProcessId: Cardinal): Cardinal;
  external 'GetWindowThreadProcessId@user32.dll stdcall';
function OpenProcess(Access: Cardinal; Inherit: Boolean; ProcessId: Cardinal): THandle;
  external 'OpenProcess@kernel32.dll stdcall';
function QueryFullProcessImageName(Process: THandle; Flags: Cardinal; Buffer: string; var Capacity: Cardinal): Boolean;
  external 'QueryFullProcessImageNameW@kernel32.dll stdcall';
function CloseHandle(Handle: THandle): Boolean;
  external 'CloseHandle@kernel32.dll stdcall';

function FindVerifiedMainWindow: HWND;
var
  Window: HWND;
  ProcessId, Capacity: Cardinal;
  Process: THandle;
  ClassName, ImagePath: string;
begin
  Result := 0;
  Window := FindWindowEx(0, 0, 0, 'PYAS Security Cyanmod');
  while Window <> 0 do
  begin
    ClassName := StringOfChar(#0, 256);
    SetLength(ClassName, GetClassName(Window, ClassName, 256));
    if Pos('WindowsForms10.Window.', ClassName) = 1 then
    begin
      ProcessId := 0;
      GetWindowThreadProcessId(Window, ProcessId);
      Process := OpenProcess($1000, False, ProcessId);
      if Process <> 0 then
      begin
        try
          Capacity := 32768;
          ImagePath := StringOfChar(#0, Capacity);
          if QueryFullProcessImageName(Process, 0, ImagePath, Capacity) then
          begin
            SetLength(ImagePath, Capacity);
            if CompareText(ExtractFileName(ImagePath), '{#AppExeName}') = 0 then
            begin
              Result := Window;
              Exit;
            end;
          end;
        finally
          CloseHandle(Process);
        end;
      end;
    end;
    Window := FindWindowEx(0, Window, 0, 'PYAS Security Cyanmod');
  end;
end;

function GetTickCount: Cardinal;
  external 'GetTickCount@kernel32.dll stdcall';

function IsValidRuntimeVersion(Version: string): Boolean;
begin
  Result := (Length(Trim(Version)) > 0) and (Trim(Version) <> '0.0.0.0');
end;

function QueryWebView2Version(RootKey: Integer; RootName: string; LogDetails: Boolean): Boolean;
var
  Version: string;
  PackedVersion: Int64;
begin
  Result := False;
  if RegQueryStringValue(RootKey, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) then
  begin
    if StrToVersion(Trim(Version), PackedVersion) then
      Result := PackedVersion > 0;
    if LogDetails or Result then
      Log('WebView2 ' + RootName + ': pv=' + Version + ', valid=' + IntToStr(Ord(Result)));
  end
  else if LogDetails then
    Log('WebView2 ' + RootName + ': version not found or not readable');
end;

function IsWebView2Installed(LogDetails: Boolean): Boolean;
begin
  Result := QueryWebView2Version(HKLM32, 'HKLM32', LogDetails);
  if not Result and IsWin64 then
    Result := QueryWebView2Version(HKLM64, 'HKLM64', LogDetails);
  if not Result then
    Result := QueryWebView2Version(HKCU32, 'HKCU32', LogDetails);
  if not Result and IsWin64 then
    Result := QueryWebView2Version(HKCU64, 'HKCU64', LogDetails);
end;

function WaitForWebView2: Boolean;
var
  Attempt: Integer;
begin
  for Attempt := 0 to 60 do
  begin
    Result := IsWebView2Installed(False);
    if Result then Exit;
    if Attempt < 60 then Sleep(500);
  end;
  Result := False;
end;

function IsVCRedistInstalled: Boolean;
var
  Installed: Cardinal;
  Version: string;
begin
  Result := False;
  if RegQueryDWordValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Installed', Installed) and (Installed = 1) then
  begin
    if RegQueryStringValue(HKLM64, 'SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64', 'Version', Version) then
      Result := IsValidRuntimeVersion(Version)
    else
      Result := True;
  end;
end;

function DependencyExitCodeSucceeded(ResultCode: Integer): Boolean;
begin
  Result := (ResultCode = 0) or (ResultCode = 1641) or (ResultCode = 3010);
  if (ResultCode = 1641) or (ResultCode = 3010) then
    DependencyRestartRequired := True;
end;

procedure EnsureVCRedist;
var
  ResultCode: Integer;
  InstallerPath: string;
begin
  if IsVCRedistInstalled then Exit;
  InstallerPath := ExpandConstant('{tmp}\PYAS_Redist\VC_redist.x64.exe');
  WizardForm.StatusLabel.Caption := CustomMessage('InstallingVCRuntime');
  if not Exec(InstallerPath, '/quiet /norestart', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or
     not DependencyExitCodeSucceeded(ResultCode) or not IsVCRedistInstalled then
  begin
    DependenciesReady := False;
    RaiseException(CustomMessage('DependencyInstallFailed'));
  end;
end;

function EnsureWebView2: string;
var
  ResultCode: Integer;
  InstallerPath, Detail: string;
  Started: Boolean;
begin
  Result := '';
  if IsWebView2Installed(True) then
  begin
    Log('WebView2 is already installed; skipping the bootstrapper');
    Exit;
  end;
  WizardForm.PreparingLabel.Caption := CustomMessage('InstallingWebView2Runtime');
  ExtractTemporaryFile('MicrosoftEdgeWebview2Setup.exe');
  InstallerPath := ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe');
  Log('Starting WebView2 bootstrapper: ' + InstallerPath + ' /silent /install');
  ResultCode := -1;
  Started := Exec(InstallerPath, '/silent /install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if Started then
  begin
    Detail := Format('WebView2 installer exit code: %d (0x%x)', [ResultCode, ResultCode]);
    if not DependencyExitCodeSucceeded(ResultCode) then
      Log('WebView2 installer returned a non-success code; checking the runtime before failing');
  end
  else
    Detail := Format('WebView2 installer launch error: %d (%s)', [ResultCode, SysErrorMessage(ResultCode)]);
  Log(Detail);
  if IsWebView2Installed(True) then
  begin
    Log('WebView2 was detected after the installation attempt; continuing Setup');
    Exit;
  end;
  if Started then
  begin
    Log('Waiting up to 30 seconds for WebView2 registration');
    if WaitForWebView2 then
    begin
      Log('WebView2 registration completed; continuing Setup');
      Exit;
    end;
  end;
  IsWebView2Installed(True);
  Log('WebView2 prerequisite failed: ' + Detail);
  Result := FmtMessage(CustomMessage('WebView2InstallFailed'), [Detail]);
end;

function StopMenuServer(InstallPath, ScriptPath: string): Boolean;
var
  ResultCode: Integer;
begin
  ResultCode := -1;
  Result := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptPath +
    '" -InstallPath "' + InstallPath + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := Result and (ResultCode = 0);
  Log(Format('Menu helper shutdown: directory=%s, exit=%d', [InstallPath, ResultCode]));
end;

function PrepareToInstall(var NeedsRestart: Boolean): string;
begin
  DependenciesReady := False;
  try
    Result := EnsureWebView2;
    if Result = '' then
    begin
      ExtractTemporaryFile('stop_menu.ps1');
      if not StopMenuServer(ExpandConstant('{app}'), ExpandConstant('{tmp}\stop_menu.ps1')) then
        Result := CustomMessage('QuitFailed');
    end;
  except
    Log('WebView2 prerequisite exception: ' + GetExceptionMessage);
    Result := FmtMessage(CustomMessage('WebView2InstallFailed'), [GetExceptionMessage]);
  end;
  DependenciesReady := Result = '';
  NeedsRestart := DependencyRestartRequired;
end;

function WaitForMainWindowToClose(TimeoutMs: Cardinal): Boolean;
var
  Deadline: Cardinal;
begin
  Deadline := GetTickCount + TimeoutMs;
  repeat
    if FindVerifiedMainWindow = 0 then
    begin
      Result := True;
      Exit;
    end;
    Sleep(100);
  until GetTickCount >= Deadline;
  Result := False;
end;

function ProcessImageRunning(const ImageName: string): Boolean;
var
  ResultCode: Integer;
  TempFile: string;
  Output: AnsiString;
begin
  { tasklist 在「没匹配」时也返回 0,只能看输出内容 }
  Result := False;
  TempFile := ExpandConstant('{tmp}\pyas-tasklist.txt');
  DeleteFile(TempFile);
  if not Exec(ExpandConstant('{cmd}'),
    '/C tasklist /FI "IMAGENAME eq ' + ImageName + '" /NH > "' + TempFile + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Exit;
  Output := '';
  if FileExists(TempFile) and LoadStringFromFile(TempFile, Output) then
    Result := Pos(Lowercase(ImageName), Lowercase(String(Output))) > 0;
  DeleteFile(TempFile);
end;

function WaitForProcessExit(const ImageName: string; TimeoutMs: Cardinal): Boolean;
var
  Deadline: Cardinal;
begin
  Deadline := GetTickCount + TimeoutMs;
  repeat
    if not ProcessImageRunning(ImageName) then
    begin
      Result := True;
      Exit;
    end;
    Sleep(300);
  until GetTickCount >= Deadline;
  Result := False;
end;

function QuitOldInstance(InstallPath: string; TimeoutMs: Cardinal): Boolean;
var
  ResultCode: Integer;
  ExePath: string;
begin
  Result := True;
  ExePath := InstallPath + '\{#AppExeName}';
  if not FileExists(ExePath) then Exit;

  if not ProcessImageRunning('{#AppExeName}') then
  begin
    Log('PYAS is not running; nothing to stop');
    Exit;
  end;

  { 托盘常驻时没有主窗口但进程还在:一样发 -quit,判据改成「进程是否真的消失」 }
  if FindVerifiedMainWindow = 0 then
    Log('No verified PYAS main window; sending -quit to the running process anyway');

  Exec(ExePath, '-quit', InstallPath, SW_HIDE, ewWaitUntilTerminated, ResultCode);

  { -quit 的退出码受权限与消息通道影响;以进程是否真的消失为准 }
  if WaitForProcessExit('{#AppExeName}', TimeoutMs) then
    Exit;

  { A running driver must shut down through its controlled unload protocol. }
  Log(Format('Controlled PYAS shutdown failed; exit code=%d', [ResultCode]));
  Result := False;
end;

function EnsureOldInstanceStopped(InstallPath: string): Boolean;
var
  Attempt: Integer;
begin
  { 首次失败已经等过 15 秒;后面的重试用户多半已退出,不必再等那么久 }
  Result := QuitOldInstance(InstallPath, 15000);
  if Result then Exit;

  { 自动关闭失败:先请用户从托盘退出,再重试;退出后用进程状态确认,而不是等窗口 }
  Log('Automatic shutdown failed; asking the user to exit PYAS manually');
  for Attempt := 1 to 3 do
  begin
    if MsgBox(FmtMessage(CustomMessage('QuitRetry'), [IntToStr(Attempt)]),
              mbError, MB_RETRYCANCEL) <> IDRETRY then
      Exit;
    if not ProcessImageRunning('{#AppExeName}') then
    begin
      Log('PYAS exited after the manual prompt; continuing');
      Result := True;
      Exit;
    end;
    if QuitOldInstance(InstallPath, 8000) then
    begin
      Result := True;
      Exit;
    end;
  end;

  Log('PYAS is still running after 3 attempts; asking for a reboot');
  MsgBox(CustomMessage('QuitRestart'), mbCriticalError, MB_OK);
end;

procedure FinalizeDriverRemoval;
var
  ResultCode: Integer;
  ExePath: string;
begin
  ExePath := ExpandConstant('{app}\PYAS_Launcher.exe');
  if not Exec(ExePath, '--wait -driver-uninstall', ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    RaiseException(CustomMessage('QuitFailed'));
end;

function InitializeSetup(): Boolean;
var
  OldInstallPath: string;
  LegacyPath: string;
begin
  DependencyRestartRequired := False;
  DependenciesReady := True;
  LegacyPath := ExpandConstant('{pf32}\{#AppName}');
  if DirExists(LegacyPath) and FileExists(LegacyPath + '\{#AppExeName}') then
  begin
    MsgBox(CustomMessage('LegacyVersionDetected'), mbCriticalError, MB_OK);
    Result := False;
    Exit;
  end;

  if RegQueryStringValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + ExpandConstant('{#AppId}') + '_is1', 'InstallLocation', OldInstallPath) or
     RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' + ExpandConstant('{#AppId}') + '_is1', 'InstallLocation', OldInstallPath) then
  begin
    if not EnsureOldInstanceStopped(OldInstallPath) then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

function InitializeUninstall(): Boolean;
begin
  if not EnsureOldInstanceStopped(ExpandConstant('{app}')) then
  begin
    Result := False;
    Exit;
  end;

  Result := True;
  if FileExists(ExpandConstant('{app}\Menu\stop_menu.ps1')) then
  begin
    Result := StopMenuServer(ExpandConstant('{app}'), ExpandConstant('{app}\Menu\stop_menu.ps1'));
    if not Result then
      MsgBox(CustomMessage('QuitFailed'), mbCriticalError, MB_OK);
  end;
end;

function CanLaunchApp: Boolean;
begin
  Result := DependenciesReady and not DependencyRestartRequired;
end;

function NeedRestart: Boolean;
begin
  Result := DependencyRestartRequired;
end;
procedure RemoveLegacyStartupTask;
var
  TaskService: Variant;
  RootFolder: Variant;
begin
  try
    TaskService := CreateOleObject('Schedule.Service');
    TaskService.Connect();
    RootFolder := TaskService.GetFolder('\');
    try
      RootFolder.DeleteTask('PYAS_Security_ATS', 0);
      Log('Removed legacy PYAS scheduled startup task');
    except
      Log('Legacy PYAS scheduled startup task was not present or could not be removed');
    end;
  except
    Log('Task Scheduler COM was unavailable while cleaning the legacy startup task');
  end;
end;

function IsModernMenuSupported: Boolean;
var
  Version: TWindowsVersion;
begin
  GetWindowsVersionEx(Version);
  Result := Version.Build >= 22000;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    RemoveLegacyStartupTask;
  end;
end;

procedure RemoveStartupTasks;
var
  TaskService, RootFolder, Tasks, Task: Variant;
  I: Integer;
  TaskName, ExecutablePath: string;
begin
  try
    TaskService := CreateOleObject('Schedule.Service');
    TaskService.Connect();
    RootFolder := TaskService.GetFolder('\');
    Tasks := RootFolder.GetTasks(1);
    ExecutablePath := ExpandConstant('{app}\{#AppExeName}');
    for I := Tasks.Count downto 1 do
    begin
      Task := Tasks.Item(I);
      TaskName := Task.Name;
      if (TaskName = 'PYAS_Security_ATS') or (Pos('PYAS_Security_ATS_S-1-', TaskName) = 1) then
      begin
        if (Task.Definition.Actions.Count = 1) and
           (CompareText(Task.Definition.Actions.Item(1).Path, ExecutablePath) = 0) then
        begin
          RootFolder.DeleteTask(TaskName, 0);
          Log('Removed PYAS startup task: ' + TaskName);
        end;
      end;
    end;
  except
    Log('Could not remove all PYAS startup tasks');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    RemoveStartupTasks;
  end
  else if CurUninstallStep = usPostUninstall then
  begin
    DelTree(ExpandConstant('{app}'), True, True, True);
  end;
end;
