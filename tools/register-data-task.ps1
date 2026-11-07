# 毎日10:00、ログオン中のユーザー権限でデータを生成する。公開・ストア提出は行わない。
$ErrorActionPreference = 'Stop'
$TaskName = 'SiteChecker データ更新'
$Root = Split-Path -Parent $PSScriptRoot
$Node = (Get-Command node -ErrorAction Stop).Source
$Python = (Get-Command python -ErrorAction Stop).Source
$Script = Join-Path $Root 'tools\update-data.ps1'
$PowerShell = (Get-Command powershell -ErrorAction Stop).Source
$Arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Script`" -NodePath `"$Node`" -PythonPath `"$Python`""
$action = New-ScheduledTaskAction -Execute $PowerShell -Argument $Arguments -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -Daily -At 10:00
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
  -Description 'HaGeZi・JPCERT/CC・CCJ・消費者庁のデータを取得しSQLiteと同梱データを生成する' -Force | Out-Null
Write-Output "登録しました: $TaskName（毎日10:00、出力先: $Root\dist\intelligence）"
