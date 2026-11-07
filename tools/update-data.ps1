param([string]$NodePath = 'node', [string]$PythonPath = 'python')
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$LogDir = Join-Path $Root 'dist\intelligence\logs'
New-Item -ItemType Directory -Force $LogDir | Out-Null
$Log = Join-Path $LogDir ((Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
$env:SITECHECKER_PYTHON = $PythonPath
$NodeScript = Join-Path $Root 'tools\update-intelligence.js'
$ErrorLog = $Log + '.stderr.txt'
$process = Start-Process -FilePath $NodePath -ArgumentList ('"' + $NodeScript + '"') `
  -WorkingDirectory $Root -WindowStyle Hidden -Wait -PassThru `
  -RedirectStandardOutput $Log -RedirectStandardError $ErrorLog
if ($process.ExitCode -ne 0) { throw "データ更新に失敗しました。旧データを使用します。ログ: $Log / $ErrorLog" }
Write-Output "データ更新完了。ログ: $Log"
