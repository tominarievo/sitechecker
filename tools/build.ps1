# ストア提出用の ZIP を作成する（dist\sitechecker-<version>.zip）。
# 拡張機能の実行に必要なファイルだけを入れ、テスト・収集ツール等は含めない。
#
# 使い方: powershell -ExecutionPolicy Bypass -File tools\build.ps1

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$Root = Split-Path -Parent $PSScriptRoot
$manifest = Get-Content (Join-Path $Root 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$version = $manifest.version

$files = @(
  'manifest.json', 'background.js', 'detector.js', 'rdap.js', 'page-analyzer.js', 'content.js',
  'psl.js', 'phishing-analyzer.js', 'phishing-dom.js',
  'popup.html', 'popup.js', 'data/blocklist.txt', 'data/public_suffix_list.dat', 'data/brands.json',
  'LICENSE', 'THIRD_PARTY_NOTICES.md',
  'icons/icon16.png', 'icons/icon32.png', 'icons/icon48.png', 'icons/icon128.png'
)

# manifest.json から参照されているファイルが揃っているか確認
$referenced = @($manifest.background.service_worker, $manifest.action.default_popup) +
  @($manifest.content_scripts | ForEach-Object { $_.js }) +
  @($manifest.icons.PSObject.Properties | ForEach-Object { $_.Value })
foreach ($f in $referenced) {
  if ($files -notcontains $f) { throw "manifest.json が参照する $f が ZIP の対象に入っていません" }
}
# background.js が importScripts で読み込むファイル
$bg = Get-Content (Join-Path $Root 'background.js') -Raw -Encoding UTF8
foreach ($m in [regex]::Matches($bg, "importScripts\(([^)]*)\)")) {
  foreach ($q in [regex]::Matches($m.Groups[1].Value, "'([^']+)'")) {
    if ($files -notcontains $q.Groups[1].Value) { throw "background.js が読み込む $($q.Groups[1].Value) が ZIP の対象に入っていません" }
  }
}
# background.js が chrome.runtime.getURL で読み込む同梱データ
foreach ($m in [regex]::Matches($bg, "getURL\('([^']+)'\)")) {
  if ($files -notcontains $m.Groups[1].Value) { throw "background.js が読み込む $($m.Groups[1].Value) が ZIP の対象に入っていません" }
}
foreach ($f in $files) {
  if (-not (Test-Path (Join-Path $Root $f))) { throw "ファイルがありません: $f" }
}

$dist = Join-Path $Root 'dist'
New-Item -ItemType Directory -Force $dist | Out-Null
$zipPath = Join-Path $dist "sitechecker-$version.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

# ZIP 内のパス区切りは必ず "/"（ストアの要件）
$zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
try {
  foreach ($f in $files) {
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
      $zip, (Join-Path $Root $f), $f, [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
  }
} finally {
  $zip.Dispose()
}

$size = [math]::Round((Get-Item $zipPath).Length / 1KB)
Write-Output "作成しました: $zipPath（$size KB、$($files.Count) ファイル、バージョン $version）"
