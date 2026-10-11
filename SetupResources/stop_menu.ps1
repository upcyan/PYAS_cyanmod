# Stops PYAS_Menu.exe processes whose image lives inside -InstallPath.
# The installer calls this (via the [Code] StopMenuServer helper) before
# replacing files: a running menu helper locks PYAS files and aborts the
# upgrade, which is exactly the failure this script exists to prevent.
# Contract (tests/test_menu_shutdown.py): match the full image path with a
# directory boundary (same-named processes in other directories survive),
# exit 0 once nothing in the target tree is running, safe to repeat.
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallPath
)

$ErrorActionPreference = 'Stop'

# Normalize to a directory prefix; the trailing backslash makes the boundary
# exact so C:\app\PYAS_Menu.exe matches but C:\appdata\PYAS_Menu.exe does not.
$target = [System.IO.Path]::GetFullPath($InstallPath.TrimEnd('\') + '\')

$victims = @(
    Get-CimInstance Win32_Process -Filter "Name = 'PYAS_Menu.exe'" | Where-Object {
        $_.ExecutablePath -and
        [System.IO.Path]::GetFullPath($_.ExecutablePath).StartsWith($target, [System.StringComparison]::OrdinalIgnoreCase)
    }
)

foreach ($victim in $victims) {
    $processId = $victim.ProcessId

    if (-not (Get-Process -Id $processId -ErrorAction SilentlyContinue)) {
        continue  # exited between enumeration and termination
    }

    try {
        Stop-Process -Id $processId -Force
    } catch {
        # Exiting right before we kill it is a benign race; if it is still
        # alive the kill genuinely failed and the installer must abort rather
        # than continue over a locked file.
        if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
            [Console]::Error.WriteLine("stop_menu: cannot stop PID ${processId}: $($_.Exception.Message)")
            exit 1
        }
    }

    # TerminateProcess is asynchronous: confirm exit before returning so the
    # installer never races a still-locked file.
    Wait-Process -Id $processId -Timeout 5 -ErrorAction SilentlyContinue

    if (Get-Process -Id $processId -ErrorAction SilentlyContinue) {
        [Console]::Error.WriteLine("stop_menu: PID ${processId} still running after 5s")
        exit 1
    }
}

exit 0
