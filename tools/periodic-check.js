/**
 * 定期評価（タスクスケジューラから2週間ごとに実行する想定）。
 *   1. 正規通販サイトのページを urlscan.io から取得（キャッシュ済みなら再取得しない）
 *   2. 直近の日本語通販ページ（偽通販の候補を含む）を urlscan.io から収集
 *   3. URL の特徴で仮ラベルを付ける
 *   4. ページ内容のルールの精度を評価し、レポートと推移（history.csv）を保存
 *
 * 安全のための方針: 詐欺サイトに接続するのは urlscan.io 側で、こちらは urlscan.io の API にのみアクセスする。
 * 取得した HTML は拡張子 .txt で保存し、ブラウザで開かず文字列としてのみ扱う。
 *
 * 使い方: node tools/periodic-check.js [--data <フォルダ>] [--key-file <file>] [--days 14] [--max 200]
 *   既定のデータフォルダ: %USERPROFILE%\sitechecker-data   既定のキー: %USERPROFILE%\.urlscan-key
 */
'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const args = {
  data: path.join(os.homedir(), 'sitechecker-data'),
  keyFile: path.join(os.homedir(), '.urlscan-key'),
  days: 14,
  max: 200,
};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]; const v = process.argv[i + 1];
  if (a === '--data') { args.data = v; i++; }
  else if (a === '--key-file') { args.keyFile = v; i++; }
  else if (a === '--days') { args.days = Number(v); i++; }
  else if (a === '--max') { args.max = Number(v); i++; }
}

const today = new Date().toISOString().slice(0, 10);
const runDir = path.join(args.data, 'runs', today);
const legitCache = path.join(args.data, 'legit-cache');
const legitLists = ['legit_jp_shops.txt', 'legit_jp_shops2.txt'].map((f) => path.join(ROOT, 'tests', 'data', f));
fs.mkdirSync(runDir, { recursive: true });

const logFile = path.join(runDir, 'run.log');
const log = (msg) => {
  const line = `[${new Date().toISOString()}] ${msg}`;
  console.log(line);
  fs.appendFileSync(logFile, line + '\n');
};

function run(label, script, scriptArgs) {
  log(`開始: ${label}`);
  const r = spawnSync(process.execPath, [path.join(ROOT, script), ...scriptArgs], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
  });
  fs.appendFileSync(logFile, (r.stdout || '') + (r.stderr || ''));
  if (r.status !== 0) throw new Error(`${label} が失敗しました（終了コード ${r.status}）。${logFile} を確認してください。`);
  log(`完了: ${label}`);
  return r.stdout || '';
}

try {
  if (!fs.existsSync(args.keyFile)) throw new Error(`API キーのファイルがありません: ${args.keyFile}`);

  // 1. 正規通販サイト（初回のみ API を使い、以降はキャッシュ）
  run('正規通販サイトの取得', 'tests/urlscan-eval.js', [
    ...legitLists.flatMap((f) => ['--white', f + ':head']), '--sample', '100',
    '--cache', legitCache, '--key-file', args.keyFile,
  ]);

  // 2. 偽通販の候補を含む日本語通販ページの収集
  run('通販ページの収集', 'tools/urlscan-collect.js', [
    '--out', runDir, '--key-file', args.keyFile, '--days', String(args.days), '--max', String(args.max),
  ]);

  // 3. 仮ラベル
  const labelOut = run('仮ラベル付け', 'tools/auto-label.js', ['--samples', runDir, ...legitLists.flatMap((f) => ['--legit', f])]);

  // 4. 評価
  const report = run('評価', 'tests/content-eval.js', [
    '--samples', runDir, '--labels', path.join(runDir, 'labels.json'),
    ...legitLists.flatMap((f) => ['--legit', f]), '--legit-cache', legitCache, '--miss-by-page',
  ]);

  const header = [
    `# 詐欺サイトチェッカー 定期評価レポート（${today}）`,
    '',
    `収集: 直近${args.days}日の urlscan.io 公開スキャン ／ ${labelOut.split('\n')[0]}`,
    '※ 詐欺のラベルは URL の特徴で付けているため、「ページ内容のみのスコア」が独立した指標です。',
    '※ 判断保留のサイトは labels-review.tsv で確認できます。',
    '',
  ].join('\n');
  fs.writeFileSync(path.join(runDir, 'report.txt'), header + report, 'utf8');

  // 推移の記録
  const num = (re) => { const m = report.match(re); return m ? m[1] : ''; };
  const target = report.match(/評価対象: 詐欺 (\d+)件 \/ 正規 (\d+)件/) || [];
  const pageOnly = report.split('■ ページ内容のみのスコア')[1] || '';
  const row = [
    today, target[1] || '', target[2] || '',
    (pageOnly.match(/40%以上: 検知 (\d+)%/) || [])[1] || '',
    (pageOnly.match(/40%以上: 検知 \d+%\s+誤検知 (\d+)%/) || [])[1] || '',
    num(/40%以上: 検知 \d+% → (\d+)%/),
    num(/40%以上: 検知 \d+% → \d+%\s+誤検知 \d+% → (\d+)%/),
  ];
  const historyFile = path.join(args.data, 'history.csv');
  if (!fs.existsSync(historyFile)) {
    fs.writeFileSync(historyFile, '﻿日付,詐欺件数,正規件数,ページ内容のみ検知率%,ページ内容のみ誤検知率%,URL+ページ検知率%,URL+ページ誤検知率%\n', 'utf8');
  }
  fs.appendFileSync(historyFile, row.join(',') + '\n', 'utf8');

  log(`レポート: ${path.join(runDir, 'report.txt')}`);
  log(`推移: ${historyFile}`);
} catch (e) {
  log('エラー: ' + e.message);
  process.exit(1);
}
