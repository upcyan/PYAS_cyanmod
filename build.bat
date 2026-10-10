@echo off
setlocal
chcp 65001 >nul
set PYTHONIOENCODING=utf-8

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found in PATH. Please install Python 3.10+ first.
    pause
    exit /b 1
)

python "%~dp0build.py" %*
set EXITCODE=%errorlevel%

if not "%EXITCODE%"=="0" pause
endlocal
exit /b %EXITCODE%
