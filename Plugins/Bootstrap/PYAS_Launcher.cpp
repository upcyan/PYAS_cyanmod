// Starts an independent frozen instance without loading Python in this process.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

// The elevated policy helper is the only child that can die inside the
// PyInstaller bootloader, before any Python code exists. A hidden process owns
// no console, so the bootloader's stderr is the single record of that failure.
// Everything below routes it to one fixed, root-owned file.
constexpr wchar_t kPolicyHelperFlag[] = L"--pyas-policy-helper";
constexpr ULONGLONG kLogRollBytes = 512ull * 1024ull;

std::wstring Stamp() {
    SYSTEMTIME now{};
    GetLocalTime(&now);
    wchar_t text[48] = {};
    swprintf_s(text, L"%04u-%02u-%02u %02u:%02u:%02u.%03u", now.wYear, now.wMonth,
        now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds);
    return text;
}

bool IsLink(const std::wstring& path) {
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

void AppendText(HANDLE file, const std::wstring& text) {
    if (!file || file == INVALID_HANDLE_VALUE || text.empty()) return;
    const int size = WideCharToMultiByte(CP_UTF8, 0, text.c_str(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) return;
    std::string bytes(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()),
        &bytes[0], size, nullptr, nullptr);
    DWORD written = 0;
    WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
}

std::wstring Inherited(PCWSTR name) {
    wchar_t value[2048] = {};
    const DWORD length = GetEnvironmentVariableW(name, value, ARRAYSIZE(value));
    if (!length) return L"<unset>";
    return std::wstring(value, length);
}

int CountArguments(const std::wstring& text) {
    int count = 0;
    bool inside = false;
    for (const wchar_t ch : text) {
        if (ch == L' ') { inside = false; continue; }
        if (!inside) { inside = true; ++count; }
    }
    return count;
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    const BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, size, &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

// Fixed location only: no caller-supplied path, so a request cannot redirect
// an elevated write. A planted reparse point disables logging instead of being
// followed, which keeps this diagnostic from becoming a write primitive.
HANDLE OpenBootstrapLog(std::wstring& path) {
    wchar_t base[32768] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, base)))
        return nullptr;
    const std::wstring root = std::wstring(base) + L"\\PYAS";
    const std::wstring folder = root + L"\\Logs";
    // The parent is installer-owned (users-readexec). Creating it here would
    // inherit ProgramData's default rights instead and hand Users write access,
    // so logging gives up rather than weakening that directory.
    if (GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES) return nullptr;
    CreateDirectoryW(folder.c_str(), nullptr);
    if (IsLink(root) || IsLink(folder)) return nullptr;
    path = folder + L"\\policy-helper-bootstrap.log";
    if (IsLink(path)) return nullptr;

    WIN32_FILE_ATTRIBUTE_DATA attributes{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes)) {
        const ULONGLONG size = (static_cast<ULONGLONG>(attributes.nFileSizeHigh) << 32)
            | attributes.nFileSizeLow;
        if (size > kLogRollBytes) DeleteFileW(path.c_str());
    }

    SECURITY_ATTRIBUTES inherit{};
    inherit.nLength = sizeof(inherit);
    inherit.bInheritHandle = TRUE;
    return CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        &inherit, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
}

int Fail(const wchar_t* message, DWORD code, HANDLE log = nullptr) {
    if (log) {
        AppendText(log, std::wstring(L"launcher failure: ") + message
            + L" (code " + std::to_wstring(code) + L")\n");
        CloseHandle(log);  // process exits next; the record must already be on disk
    }
    wchar_t* detail = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
        reinterpret_cast<wchar_t*>(&detail), 0, nullptr);
    std::wstring text(message);
    text += L"\n\n";
    if (detail) { text += detail; LocalFree(detail); }
    MessageBoxW(nullptr, text.c_str(), L"PYAS startup", MB_OK | MB_ICONERROR);
    return static_cast<int>(code ? code : ERROR_GEN_FAILURE);
}

}  // namespace

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR arguments, int) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!length || length >= buffer.size()) return Fail(L"Cannot locate PYAS launcher.", GetLastError());
    std::wstring directory(buffer.data(), length);
    const auto slash = directory.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return Fail(L"Invalid launcher location.", ERROR_BAD_PATHNAME);
    directory.resize(slash);
    const std::wstring executable = directory + L"\\PYAS.exe";

    std::wstring forwarded = arguments ? arguments : L"";
    const bool probe = forwarded == L"--pyas-bootstrap-probe";
    bool waitForExit = probe;
    if (forwarded == L"--wait") { waitForExit = true; forwarded.clear(); }
    else if (forwarded.rfind(L"--wait ", 0) == 0) { waitForExit = true; forwarded.erase(0, 7); }

    // Restart support: the previous instance must be gone before the new one
    // starts, otherwise the single-instance mutex makes the new process forward
    // to the dying one and quietly exit. Its policy is only read at startup, so
    // this is the only way to apply a saved policy without user action.
    std::wstring waitForPid;
    if (forwarded.rfind(L"--restart ", 0) == 0) {
        waitForPid = forwarded.substr(10);
        forwarded.clear();
    }

    // Only the waiting policy helper is supervised here: it runs hidden, so its
    // bootloader output would otherwise be lost. Normal GUI children keep the
    // untouched startup path.
    std::wstring logPath;
    HANDLE log = nullptr;
    if (waitForExit && forwarded.find(kPolicyHelperFlag) != std::wstring::npos) {
        log = OpenBootstrapLog(logPath);
        if (log == INVALID_HANDLE_VALUE) log = nullptr;
    }
    const ULONGLONG started = GetTickCount64();
    if (log) {
        AppendText(log, L"==== [" + Stamp() + L"] policy helper launch ====\n");
        AppendText(log, L"elevated=" + std::to_wstring(IsElevated() ? 1 : 0)
            + L" pid=" + std::to_wstring(GetCurrentProcessId())
            + L" args=" + std::to_wstring(CountArguments(forwarded)) + L"\n");
        AppendText(log, L"executable=" + executable + L"\n");
        AppendText(log, L"directory=" + directory + L"\n");
        // The inherited onefile state is the prime suspect for a bootloader
        // abort, so it is recorded exactly as received.
        AppendText(log, L"inherited _PYI_APPLICATION_HOME_DIR="
            + Inherited(L"_PYI_APPLICATION_HOME_DIR") + L"\n");
        AppendText(log, L"inherited _PYI_ARCHIVE_FILE="
            + Inherited(L"_PYI_ARCHIVE_FILE") + L"\n");
        AppendText(log, L"inherited _PYI_PARENT_PROCESS_LEVEL="
            + Inherited(L"_PYI_PARENT_PROCESS_LEVEL") + L"\n");
        AppendText(log, L"inherited PYINSTALLER_RESET_ENVIRONMENT="
            + Inherited(L"PYINSTALLER_RESET_ENVIRONMENT") + L"\n");
    }

    // Public PyInstaller contract; do not mutate its private _PYI_* state.
    if (!SetEnvironmentVariableW(L"PYINSTALLER_RESET_ENVIRONMENT", L"1")) {
        return Fail(L"Cannot prepare an independent PYAS instance.", GetLastError(), log);
    }
    if (log) AppendText(log, L"reset=1\n--- child output ---\n");

    std::wstring command = L"\"" + executable + L"\"";
    if (!forwarded.empty()) { command += L" "; command += forwarded; }
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    // Only the non-interactive build probe owns a kill-on-close tree. Normal
    // GUI children (notably the updater) must be allowed to outlive the GUI.
    HANDLE job = nullptr;
    if (probe) {
        job = CreateJobObjectW(nullptr, nullptr);
        if (!job) return Fail(L"Cannot create startup supervision.", GetLastError(), log);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
            DWORD error = GetLastError(); CloseHandle(job);
            return Fail(L"Cannot configure startup supervision.", error, log);
        }
    }

    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    BOOL inheritHandles = FALSE;
    HANDLE nullDevice = nullptr;

    if (!waitForPid.empty()) {
        const DWORD previous = static_cast<DWORD>(wcstoul(waitForPid.c_str(), nullptr, 10));
        if (previous) {
            HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, previous);
            if (process) {
                // Bounded: a stuck shutdown must not leave the user with no app.
                WaitForSingleObject(process, 60000);
                CloseHandle(process);
            }
            // The mutex and log handles are released just before the old process
            // object signals, so give the object manager a moment to catch up.
            Sleep(500);
        }
    }
    if (log) {
        SECURITY_ATTRIBUTES share{};
        share.nLength = sizeof(share);
        share.bInheritHandle = TRUE;
        nullDevice = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &share, OPEN_EXISTING, 0, nullptr);
        if (nullDevice == INVALID_HANDLE_VALUE) nullDevice = nullptr;
        startup.dwFlags |= STARTF_USESTDHANDLES;
        startup.hStdInput = nullDevice ? nullDevice : log;  // helper never reads stdin
        startup.hStdOutput = log;
        startup.hStdError = log;
        inheritHandles = TRUE;
    }

    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), mutableCommand.data(), nullptr, nullptr, inheritHandles,
            (probe ? CREATE_SUSPENDED : 0) | CREATE_UNICODE_ENVIRONMENT, nullptr, directory.c_str(), &startup, &process)) {
        DWORD error = GetLastError(); if (job) CloseHandle(job);
        if (nullDevice) CloseHandle(nullDevice);
        return Fail(L"Cannot start PYAS.", error, log);
    }
    if (nullDevice) CloseHandle(nullDevice);
    if (job && !AssignProcessToJobObject(job, process.hProcess)) {
        DWORD error = GetLastError(); TerminateProcess(process.hProcess, error);
        WaitForSingleObject(process.hProcess, INFINITE);
        CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(job);
        return Fail(L"Cannot supervise PYAS startup.", error, log);
    }
    if (probe && ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
        DWORD error = GetLastError(); TerminateJobObject(job, error);
        CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(job);
        return Fail(L"Cannot resume PYAS startup.", error, log);
    }
    CloseHandle(process.hThread);
    if (!waitForExit) { CloseHandle(process.hProcess); return 0; }
    DWORD wait = WaitForSingleObject(process.hProcess, INFINITE);
    DWORD result = ERROR_GEN_FAILURE;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &result);
    CloseHandle(process.hProcess); if (job) CloseHandle(job);
    if (log) {
        const ULONGLONG seconds = (GetTickCount64() - started) / 1000;
        AppendText(log, L"==== [" + Stamp() + L"] exit=" + std::to_wstring(result)
            + L" after " + std::to_wstring(seconds) + L"s ====\n\n");
        CloseHandle(log);
    }
    return static_cast<int>(result);
}
