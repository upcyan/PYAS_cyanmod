// PYAS_Menu.cpp — out-of-proc COM server
// 为 Windows 11 新版右键菜单提供 PYAS 扫描入口(sparse package + IExplorerCommand)。
// 由包清单(desktop4:FileExplorerContextMenus + com:ExeServer)激活:
//   explorer -> CoCreateInstance(CLSID) -> 本进程注册类工厂并返回 IExplorerCommand
// Invoke 时按选中项逐个启动同目录 PYAS.exe -scan "<path>"。
#include <windows.h>
#include <stdio.h>
#include <shobjidl_core.h>
#include <shlwapi.h>
#include <crtdbg.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "uuid.lib")

static const CLSID CLSID_PYASCommand =
    {0xB7A5C1E2, 0x4D8F, 0x4E6A, {0x9C, 0x3B, 0x1F, 0x2D, 0x5A, 0x7E, 0x9B, 0x64}};

static const GUID GUID_CommandName =
    {0x5C2E8A7F, 0x1D3B, 0x4F9C, {0xA6, 0x8E, 0x2B, 0x9D, 0x4C, 0x1F, 0x7A, 0x53}};

static volatile long g_objectCount = 0;
static volatile long g_serverLockCount = 0;
static UINT_PTR g_idleTimer = 0;
static const UINT IDLE_TIMEOUT_MS = 60000;
static void CALLBACK IdleTimerProc(HWND, UINT, UINT_PTR, DWORD);

static void ArmIdleExit()
{
    if (g_idleTimer)
        KillTimer(nullptr, g_idleTimer);
    g_idleTimer = SetTimer(nullptr, 0, IDLE_TIMEOUT_MS, IdleTimerProc);
}

// ---------------- 引用计数基类 ----------------
template <typename T>
class RefCounted
{
    LONG m_refs = 1;
    bool m_trackObjects;

protected:
    RefCounted(bool trackObjects = true) : m_trackObjects(trackObjects)
    {
        if (m_trackObjects) InterlockedIncrement(&g_objectCount);
    }
    virtual ~RefCounted()
    {
        if (m_trackObjects) InterlockedDecrement(&g_objectCount);
    }

public:
    ULONG STDMETHODCALLTYPE AddRef() { return (ULONG)InterlockedIncrement(&m_refs); }
    ULONG STDMETHODCALLTYPE Release()
    {
        ULONG refs = (ULONG)InterlockedDecrement(&m_refs);
        if (refs == 0)
            delete static_cast<T *>(this);
        return refs;
    }
};

// ---------------- IExplorerCommand 实现 ----------------
class PYASCommand final : public RefCounted<PYASCommand>, public IExplorerCommand
{
public:
    STDMETHODIMP_(ULONG) AddRef() override { return RefCounted<PYASCommand>::AddRef(); }
    STDMETHODIMP_(ULONG) Release() override { return RefCounted<PYASCommand>::Release(); }

    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override
    {
        static const QITAB qi[] = {
            QITABENT(PYASCommand, IExplorerCommand),
            {0, 0},
        };
        return QISearch(this, qi, riid, ppv);
    }

    STDMETHODIMP GetFlags(EXPCMDFLAGS *pFlags) override
    {
        if (!pFlags)
            return E_POINTER;
        *pFlags = ECF_DEFAULT;
        return S_OK;
    }

    STDMETHODIMP GetCanonicalName(GUID *pguidCommandName) override
    {
        if (!pguidCommandName)
            return E_POINTER;
        *pguidCommandName = GUID_CommandName;
        return S_OK;
    }

    STDMETHODIMP GetTitle(IShellItemArray *, LPWSTR *ppszName) override
    {
        if (!ppszName)
            return E_POINTER;
        const wchar_t *title =
            (PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_CHINESE)
                ? L"使用 PYAS 扫描"
                : L"Scan with PYAS";
        *ppszName = StrDupW(title);
        return *ppszName ? S_OK : E_OUTOFMEMORY;
    }

    STDMETHODIMP GetIcon(IShellItemArray *, LPWSTR *ppszIcon) override
    {
        if (!ppszIcon)
            return E_POINTER;
        wchar_t exe[MAX_PATH] = L"";
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        PathRemoveFileSpecW(exe);
        PathAppendW(exe, L"PYAS.exe");
        // 图标引用格式: "exe 路径,0"
        wchar_t iconRef[MAX_PATH + 4] = L"";
        swprintf_s(iconRef, L"%s,0", exe);
        *ppszIcon = StrDupW(iconRef);
        return *ppszIcon ? S_OK : E_OUTOFMEMORY;
    }

    STDMETHODIMP GetToolTip(IShellItemArray *, LPWSTR *ppszInfotip) override
    {
        if (!ppszInfotip)
            return E_POINTER;
        *ppszInfotip = StrDupW(L"PYAS Security Cyanmod");
        return *ppszInfotip ? S_OK : E_OUTOFMEMORY;
    }

    STDMETHODIMP GetState(IShellItemArray *, BOOL, EXPCMDSTATE *pCmdState) override
    {
        if (!pCmdState)
            return E_POINTER;
        *pCmdState = ECS_ENABLED;
        return S_OK;
    }

    STDMETHODIMP Invoke(IShellItemArray *psiItemArray, IBindCtx *) override
    {
        if (!psiItemArray)
            return E_INVALIDARG;

        DWORD count = 0;
        psiItemArray->GetCount(&count);

        wchar_t exeDir[MAX_PATH] = L"";
        GetModuleFileNameW(nullptr, exeDir, MAX_PATH);
        PathRemoveFileSpecW(exeDir);
        wchar_t target[MAX_PATH] = L"";
        PathCombineW(target, exeDir, L"PYAS.exe");

        for (DWORD i = 0; i < count; ++i)
        {
            IShellItem *item = nullptr;
            if (FAILED(psiItemArray->GetItemAt(i, &item)) || !item)
                continue;

            PWSTR path = nullptr;
            if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) && path)
            {
                size_t argLen = wcslen(target) + wcslen(path) + 24;
                wchar_t *args = (wchar_t *)CoTaskMemAlloc(argLen * sizeof(wchar_t));
                if (args)
                {
                    swprintf_s(args, argLen, L"\"%s\" -scan \"%s\"", target, path);
                    STARTUPINFOW si = {sizeof(STARTUPINFOW)};
                    PROCESS_INFORMATION pi = {};
                    if (CreateProcessW(target, args, nullptr, nullptr, FALSE,
                                       0, nullptr, nullptr, &si, &pi))
                    {
                        CloseHandle(pi.hThread);
                        CloseHandle(pi.hProcess);
                    }
                    else if (GetLastError() == ERROR_ELEVATION_REQUIRED)
                    {
                        // ShellExecute supplies argv[0] itself. Elevation is
                        // requested only when Windows requires it for PYAS.
                        swprintf_s(args, argLen, L"-scan \"%s\"", path);
                        ShellExecuteW(nullptr, L"runas", target, args, exeDir, SW_SHOWNORMAL);
                    }
                    CoTaskMemFree(args);
                }
                CoTaskMemFree(path);
            }
            item->Release();
        }
        return S_OK;
    }

    STDMETHODIMP EnumSubCommands(IEnumExplorerCommand **) override
    {
        return E_NOTIMPL;
    }
};

// ---------------- IClassFactory 实现 ----------------
class PYASFactory final : public RefCounted<PYASFactory>, public IClassFactory
{
public:
    // COM retains this factory throughout registration; it is not an active command.
    PYASFactory() : RefCounted<PYASFactory>(false) {}
    STDMETHODIMP_(ULONG) AddRef() override { return RefCounted<PYASFactory>::AddRef(); }
    STDMETHODIMP_(ULONG) Release() override { return RefCounted<PYASFactory>::Release(); }

    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override
    {
        static const QITAB qi[] = {
            QITABENT(PYASFactory, IClassFactory),
            {0, 0},
        };
        return QISearch(this, qi, riid, ppv);
    }

    STDMETHODIMP CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppv) override
    {
        if (!ppv)
            return E_POINTER;
        if (pUnkOuter)
            return CLASS_E_NOAGGREGATION;

        ArmIdleExit();  // 新激活重置空闲计时

        PYASCommand *command = new PYASCommand();
        HRESULT hr = command->QueryInterface(riid, ppv);
        command->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL fLock) override
    {
        if (fLock)
            InterlockedIncrement(&g_serverLockCount);
        else
            InterlockedDecrement(&g_serverLockCount);
        return S_OK;
    }
};

// ---------------- 空闲退出计时器 ----------------
static void CALLBACK IdleTimerProc(HWND, UINT, UINT_PTR, DWORD)
{
    // 仅当没有任何存活对象且没有服务器锁时退出
    if (g_objectCount == 0 && g_serverLockCount == 0)
    {
        KillTimer(nullptr, g_idleTimer);
        g_idleTimer = 0;
        CoSuspendClassObjects();
        PostQuitMessage(0);
    }
    else
    {
        ArmIdleExit();  // 仍有对象存活,继续等待
    }
}

int wmain(int argc, wchar_t **argv)
{
    bool embedding = false;
    for (int i = 1; i < argc; ++i)
    {
        if (!_wcsicmp(argv[i], L"-Embedding"))
            embedding = true;
    }

    // 手动启动(无 -Embedding)没有意义,直接退出
    if (!embedding)
        return 0;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr))
        return 1;

    PYASFactory *factory = new PYASFactory();
    DWORD regId = 0;
    hr = CoRegisterClassObject(
        CLSID_PYASCommand,
        static_cast<IClassFactory *>(factory),
        CLSCTX_LOCAL_SERVER,
        REGCLS_MULTIPLEUSE,
        &regId);
    factory->Release();

    if (FAILED(hr))
    {
        CoUninitialize();
        return 1;
    }

    ArmIdleExit();

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (regId)
        CoRevokeClassObject(regId);
    if (g_idleTimer)
        KillTimer(nullptr, g_idleTimer);
    CoUninitialize();
    return 0;
}
