@echo off
setlocal
rem Pick an interpreter by RUNNING it and reading what it prints - not by `where python`, which is
rem satisfied by the Windows Store App Execution Alias stub and by Python 2 alike.
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
  echo     A bare "python" that opens the Microsoft Store is the Store alias, not an interpreter;
  echo     this check runs the interpreter and reads its output, so it sees through that.
  exit /b 1
)
if not exist C:\dumps mkdir C:\dumps >nul 2>&1
%PY% "%~dp0vmpunpack\vmpunpack.py" %*
exit /b %ERRORLEVEL%
