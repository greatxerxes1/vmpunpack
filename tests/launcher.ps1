$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$repo = Split-Path -Parent $here
$work = Join-Path ([IO.Path]::GetTempPath()) 'vmpunpack-tests'
New-Item -ItemType Directory -Force $work | Out-Null
$stub = Join-Path $work 'stubdir'
$pass = 0; $fail = 0
function Check($name, $cond, $detail) {
  if ($cond) { $script:pass++; Write-Host "  PASS  $name   $detail" }
  else { $script:fail++; Write-Host "  FAIL  $name   $detail" }
}

# A stub that behaves like the worst case: on PATH, exits 0, prints nothing.
New-Item -ItemType Directory -Force $stub | Out-Null
Set-Content -Encoding ascii (Join-Path $stub 'py.cmd')     "@echo off`r`nexit /b 0"
Set-Content -Encoding ascii (Join-Path $stub 'python.cmd') "@echo off`r`nexit /b 0"

# ---- 1. silent exit-0 stub must be rejected
$probe = Join-Path $work 'probe.cmd'
Copy-Item (Join-Path $repo 'RUN_ME.cmd') $probe -Force
$saved = $env:PATH
$env:PATH = "$stub;$([Environment]::GetFolderPath('System'))"
$out = & cmd.exe /c "`"$probe`"" 2>&1 | Out-String
$code = $LASTEXITCODE
$env:PATH = $saved
Check 'stub that exits 0 but prints nothing is rejected' ($code -eq 1 -and $out -match 'not found') "code=$code"
Check 'rejection message mentions the Store alias' ($out -match 'Store alias') ''

# ---- 2. real interpreter is found, and the python exit code propagates
$out = & cmd.exe /c "`"$repo\RUN_ME.cmd`"" 2>&1 | Out-String
$code = $LASTEXITCODE
Check 'real interpreter found (argparse usage reached)' ($out -match 'usage: vmpunpack') "code=$code"
Check 'argparse exit code 2 propagates through the launcher' ($code -eq 2) "code=$code"

$out = & cmd.exe /c "`"$repo\RUN_ME.cmd`" C:\definitely\missing\sample.exe" 2>&1 | Out-String
$code = $LASTEXITCODE
Check 'tool exit code 1 propagates through the launcher' ($code -eq 1 -and $out -match 'target not found') "code=$code"

# ---- 3. inner launcher behaves the same
$out = & cmd.exe /c "`"$repo\vmpunpack\vmpunpack.cmd`"" 2>&1 | Out-String
$code = $LASTEXITCODE
Check 'inner vmpunpack.cmd reaches the tool and propagates' ($code -eq 2 -and $out -match 'usage: vmpunpack') "code=$code"

# ---- 4. path with spaces survives %* forwarding
$out = & cmd.exe /c "`"$repo\RUN_ME.cmd`" `"C:\some dir\with spaces\s.exe`"" 2>&1 | Out-String
Check 'quoted path with spaces forwarded intact' ($out -match 'with spaces\\s\.exe') ''

Write-Host ''
Write-Host "$pass passed, $fail failed"
if ($fail -gt 0) { exit 1 }
