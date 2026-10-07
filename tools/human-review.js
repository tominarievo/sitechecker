/**
 * 人手による「独立した」ラベル付けを支援する。
 * 自動ラベルや判定スコアは見せない（判断が引きずられないようにする）ブラインド形式の確認シートを作り、
 * 記入済みのシートから labels-human.json を作る。
 *
 * 1. シート作成:  node tools/human-review.js --make <収集フォルダ> [--since 2026-10-08] [--exclude <過去の収集フォルダ>]...
 *      → <収集フォルダ>/human-review.tsv（Excel で開ける）
 *      --since   : この日付以降のスキャンだけを対象にする（ルール作成に使っていない新しいデータに限定）
 *      --exclude : 過去に使った収集フォルダのドメインを除外する
 * 2. 記入:       human_label 列に black（詐欺）/ white（正規）/ 空欄（判断できない）を記入して保存
 *      urlscan 列のリンク先（urlscan.io の結果ページ）でスクリーンショットを確認できる。
 *      詐欺サイトそのもの（url 列）はブラウザで開かないこと。
 * 3. 取り込み:   node tools/human-review.js --import <収集フォルダ>
 *      → <収集フォルダ>/labels-human.json
 * 4. 評価:       node tests/content-eval.js --samples <収集フォルダ> --labels <収集フォルダ>/labels-human.json
 */
'use strict';

const fs = require('fs');
const path = require('path');

const args = { make: null, imp: null, since: null, exclude: [] };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]; const v = process.argv[i + 1];
  if (a === '--make') { args.make = v; i++; }
  else if (a === '--import') { args.imp = v; i++; }
  else if (a === '--since') { args.since = v; i++; }
  else if (a === '--exclude') { args.exclude.push(v); i++; }
}

const readSamples = (dir) => fs.readFileSync(path.join(dir, 'samples.jsonl'), 'utf8')
  .split('\n').filter(Boolean).map((l) => JSON.parse(l));
const clean = (s) => String(s || '').replace(/[\t\r\n]+/g, ' ').trim();

if (args.make) {
  const excluded = new Set(args.exclude.flatMap((d) => readSamples(d).map((s) => s.domain)));
  const rows = readSamples(args.make)
    .filter((s) => !excluded.has(s.domain))
    .filter((s) => !args.since || (s.time && s.time >= args.since));
  // 並び順で判断が偏らないよう、ドメイン名順に並べる
  rows.sort((a, b) => a.domain.localeCompare(b.domain));
  const lines = ['human_label\tdomain\ttitle\turlscan\turl（開かないこと）'];
  rows.forEach((s) => lines.push(['', s.domain, clean(s.title).slice(0, 80), `https://urlscan.io/result/${s.id}/`, clean(s.url)].join('\t')));
  const out = path.join(args.make, 'human-review.tsv');
  fs.writeFileSync(out, '﻿' + lines.join('\r\n'), 'utf8');
  console.log(`確認シート: ${out}（${rows.length}件${excluded.size ? `、過去のデータと重複する ${excluded.size} ドメインを除外` : ''}）`);
} else if (args.imp) {
  const file = path.join(args.imp, 'human-review.tsv');
  const lines = fs.readFileSync(file, 'utf8').replace(/^﻿/, '').split(/\r?\n/).slice(1).filter(Boolean);
  const labels = {};
  const count = { black: 0, white: 0, skipped: 0 };
  lines.forEach((l) => {
    const [label, domain] = l.split('\t');
    const v = String(label || '').trim().toLowerCase();
    if (v === 'black' || v === 'white') { labels[domain] = v; count[v]++; } else { count.skipped++; }
  });
  const out = path.join(args.imp, 'labels-human.json');
  fs.writeFileSync(out, JSON.stringify(labels, null, 1));
  console.log(`取り込み: 詐欺 ${count.black} / 正規 ${count.white} / 未記入 ${count.skipped} → ${out}`);
} else {
  console.error('使い方: node tools/human-review.js --make <dir> [--since YYYY-MM-DD] [--exclude <dir>]... | --import <dir>');
  process.exit(1);
}
