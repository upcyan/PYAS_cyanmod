@echo off
rem PYAS Security Cyanmod user self-test.
rem No args  : interactive menu (pick test items yourself)
rem --auto   : run everything automatically
rem --fast   : auto run, skip the long agent-scan wait
rem --only X : run items whose name contains X
chcp 65001 >nul
py -3 "%~dp0tests\selftest.py" %*
pause
