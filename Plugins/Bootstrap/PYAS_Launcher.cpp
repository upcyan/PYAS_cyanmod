// Starts an independent frozen instance without loading Python in this process.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>

static int Fail(const wchar_t* message, DWORD code) {
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

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR arguments, int) {
    std::vector<wchar_t> buffer(32768);
    DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!length || length >= buffer.size()) return Fail(L"Cannot locate PYAS launcher.", GetLastError());
    std::wstring directory(buffer.data(), length);
    const auto slash = directory.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return Fail(L"Invalid launcher location.", ERROR_BAD_PATHNAME);
    directory.resize(slash);
    const std::wstring executable = directory + L"\\PYAS.exe";
    // Public PyInstaller contract; do not mutate its private _PYI_* state.
    if (!SetEnvironmentVariableW(L"PYINSTALLER_RESET_ENVIRONMENT", L"1"))
        return Fail(L"Cannot prepare an independent PYAS instance.", GetLastError());
    std::wstring forwarded = arguments ? arguments : L"";
    const bool probe = forwarded == L"--pyas-bootstrap-probe";
    bool waitForExit = probe;
    if (forwarded == L"--wait") { waitForExit = true; forwarded.clear(); }
    else if (forwarded.rfind(L"--wait ", 0) == 0) { waitForExit = true; forwarded.erase(0, 7); }
    std::wstring command = L"\"" + executable + L"\"";
    if (!forwarded.empty()) { command += L" "; command += forwarded; }
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    // Only the non-interactive build probe owns a kill-on-close tree. Normal
    // GUI children (notably the updater) must be allowed to outlive the GUI.
    HANDLE job = nullptr;
    if (probe) {
        job = CreateJobObjectW(nullptr, nullptr);
        if (!job) return Fail(L"Cannot create startup supervision.", GetLastError());
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
            DWORD error = GetLastError(); CloseHandle(job);
            return Fail(L"Cannot configure startup supervision.", error);
        }
    }
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(executable.c_str(), mutableCommand.data(), nullptr, nullptr, FALSE,
            (probe ? CREATE_SUSPENDED : 0) | CREATE_UNICODE_ENVIRONMENT, nullptr, directory.c_str(), &startup, &process)) {
        DWORD error = GetLastError(); if (job) CloseHandle(job);
        return Fail(L"Cannot start PYAS.", error);
    }
    if (job && !AssignProcessToJobObject(job, process.hProcess)) {
        DWORD error = GetLastError(); TerminateProcess(process.hProcess, error);
        WaitForSingleObject(process.hProcess, INFINITE);
        CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(job);
        return Fail(L"Cannot supervise PYAS startup.", error);
    }
    if (probe && ResumeThread(process.hThread) == static_cast<DWORD>(-1)) {
        DWORD error = GetLastError(); TerminateJobObject(job, error);
        CloseHandle(process.hThread); CloseHandle(process.hProcess); CloseHandle(job);
        return Fail(L"Cannot resume PYAS startup.", error);
    }
    CloseHandle(process.hThread);
    if (!waitForExit) { CloseHandle(process.hProcess); return 0; }
    DWORD wait = WaitForSingleObject(process.hProcess, INFINITE);
    DWORD result = ERROR_GEN_FAILURE;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &result);
    CloseHandle(process.hProcess); if (job) CloseHandle(job);
    return static_cast<int>(result);
}
