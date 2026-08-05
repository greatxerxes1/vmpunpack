@echo off
setlocal
where python >nul 2>&1 || (echo [!] Python 3 not found in PATH - install it first, then re-run. ^& exit /b 1)
if not exist C:\dumps mkdir C:\dumps >nul 2>&1
python "%~dp0vmpunpack\vmpunpack.py" %*
