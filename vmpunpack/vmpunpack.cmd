@echo off
setlocal
set "PY="
set "OK="
for /f "delims=" %%v in ('py -3 -c "import sys;print(1 if sys.version_info>=(3,8) else 0)" 2^>nul') do set "OK=%%v"
if "%OK%"=="1" set "PY=py -3"
if defined PY goto :have
set "OK="
for /f "delims=" %%v in ('python -c "import sys;print(1 if sys.version_info>=(3,8) else 0)" 2^>nul') do set "OK=%%v"
if "%OK%"=="1" set "PY=python"
:have
if not defined PY (
  echo [!] Python 3.8+ not found - install it from python.org, then re-run.
  exit /b 1
)
%PY% "%~dp0vmpunpack.py" %*
exit /b %ERRORLEVEL%
