/**
 * 同梱の Public Suffix List（data/public_suffix_list.dat）を最新版に更新する。
 * 使い方: node tools/update-psl.js
 *
 * 出典: https://publicsuffix.org/list/public_suffix_list.dat （Mozilla Public License 2.0）
 * 公式の案内どおり、このURLからのみ取得する。更新後は拡張機能を再読み込みし、
 * node tests/phishing-analyzer.test.js で登録ドメインの判定を確認すること。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const SOURCE = 'https://publicsuffix.org/list/public_suffix_list.dat';
const OUT = path.join(__dirname, '..', 'data', 'public_suffix_list.dat');

(async () => {
  const res = await fetch(SOURCE);
  if (!res.ok) throw new Error(`ダウンロード失敗: HTTP ${res.status}`);
  const text = await res.text();
  // 取得内容の妥当性を確認（ICANN・PRIVATE の両セクションと主要なルールがあること）
  for (const marker of ['===BEGIN ICANN DOMAINS===', '===BEGIN PRIVATE DOMAINS===', '\nco.jp\n', '\ngithub.io\n']) {
    if (!text.includes(marker)) throw new Error(`想定した内容が含まれていません: ${marker.trim()}`);
  }
  fs.writeFileSync(OUT, text, 'utf8');
  const rules = text.split('\n').filter((l) => l.trim() && !l.startsWith('//')).length;
  console.log(`書き出し: ${OUT}（${rules} ルール、${Math.round(text.length / 1024)} KB）`);
})().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
