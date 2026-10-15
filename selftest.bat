@echo off
rem PYAS Security Cyanmod user self-test.
rem Full run:  py -3 tests\selftest.py
rem Fast run:  py -3 tests\selftest.py --fast
py -3 "%~dp0tests\selftest.py" %*
pause
