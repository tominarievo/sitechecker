# 定期評価（tools/periodic-check.js）を Windows のタスクスケジューラに登録する。
#   - 2週間ごと・土曜 10:00 に実行（PC が停止していた場合は、次に起動したときに実行）
#   - ログオン中のユーザー権限で実行（管理者権限は不要）
#
# 使い方:   powershell -ExecutionPolicy Bypass -File tools\register-task.ps1
# 解除:     Unregister-ScheduledTask -TaskName "SiteChecker 定期評価" -Confirm:$false

$ErrorActionPreference = 'Stop'

$TaskName = 'SiteChecker 定期評価'
$Root = Split-Path -Parent $PSScriptRoot
$Script = Join-Path $Root 'tools\periodic-check.js'
$Node = (Get-Command node -ErrorAction Stop).Source

$action = New-ScheduledTaskAction -Execute $Node -Argument "`"$Script`"" -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 2 -DaysOfWeek Saturday -At 10:00
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
  -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
  -Description '詐欺サイトチェッカー: urlscan.io から日本語通販ページを収集し、判定ルールの精度を評価する' -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName
$info = $task | Get-ScheduledTaskInfo
Write-Output "登録しました: $TaskName"
Write-Output "  実行内容: $Node `"$Script`""
Write-Output "  次回実行: $($info.NextRunTime)"
Write-Output "  結果の保存先: $env:USERPROFILE\sitechecker-data"
