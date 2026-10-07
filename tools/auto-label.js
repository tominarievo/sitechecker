/**
 * tools/urlscan-collect.js で集めたサンプルに、仮のラベルを自動で付ける。
 * ページ内容は見ず、URL・ドメインの特徴だけで判定する（ページ内容のルールを独立に評価するため）。
 *
 *   black   : URL の判定スコアが 40% 以上（格安TLD＋ランダム文字列などの構造）
 *   white   : 法人・公的な属性型JPドメイン（.co.jp 等）、または正規通販リストに載っているドメイン
 *   unknown : 上記以外（人が確認する）
 *
 * 使い方: node tools/auto-label.js --samples <フォルダ> [--legit <正規サイト一覧>]...
 *   → <フォルダ>/labels.json と <フォルダ>/labels-review.tsv（確認用の一覧）を出力
 *   既に labels.json があれば、"black"/"white" に手で直した値は上書きしない（manual に記録）
 */
'use strict';

const fs = require('fs');
const path = require('path');

require(path.join(__dirname, '..', 'detector.js'));
const { analyze, THRESHOLD_CAUTION } = globalThis.SiteRiskDetector;

const args = { samples: null, legit: [] };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]; const v = process.argv[i + 1];
  if (a === '--samples') { args.samples = v; i++; }
  else if (a === '--legit') { args.legit.push(v); i++; }
}
if (!args.samples) {
  console.error('使い方: node tools/auto-label.js --samples <dir> [--legit <file>]...');
  process.exit(1);
}

const JP_ORG = ['.co.jp', '.or.jp', '.ne.jp', '.ac.jp', '.go.jp', '.lg.jp', '.ed.jp', '.gr.jp'];
const legitDomains = new Set();
args.legit.forEach((f) => fs.readFileSync(f, 'utf8').split(/\r?\n/).map((l) => l.trim())
  .filter((l) => l && !l.startsWith('#')).forEach((h) => legitDomains.add(analyze(h).domain)));

const samples = fs.readFileSync(path.join(args.samples, 'samples.jsonl'), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const labelFile = path.join(args.samples, 'labels.json');
const manualFile = path.join(args.samples, 'labels-manual.json');
const manual = fs.existsSync(manualFile) ? JSON.parse(fs.readFileSync(manualFile, 'utf8')) : {};

const labels = {};
const review = ['label\treason\turl_score\thost\ttitle'];
samples.forEach((s) => {
  const r = analyze(s.url || s.host);
  let label = 'unknown';
  let reason = '';
  if (manual[s.domain]) { label = manual[s.domain]; reason = '手動'; }
  else if (JP_ORG.some((sfx) => s.domain.endsWith(sfx))) { label = 'white'; reason = '属性型JPドメイン'; }
  else if (legitDomains.has(s.domain)) { label = 'white'; reason = '正規通販リスト'; }
  else if (r.score >= THRESHOLD_CAUTION) { label = 'black'; reason = r.reasons.map((x) => x.category).join('+'); }
  labels[s.domain] = label;
  review.push([label, reason, r.score, s.host, String(s.title || '').replace(/\s+/g, ' ').slice(0, 60)].join('\t'));
});

// 偽通販は同じタイトルのひな形を多数のドメインで使い回すため、
// 詐欺と判定したページと「タイトルが完全一致」する判断保留のページも詐欺とする
const normTitle = (t) => String(t || '').replace(/\s+/g, ' ').trim();
const blackTitles = new Set(samples.filter((s) => labels[s.domain] === 'black').map((s) => normTitle(s.title)).filter((t) => t.length >= 8));
samples.forEach((s, i) => {
  if (labels[s.domain] === 'unknown' && blackTitles.has(normTitle(s.title))) {
    labels[s.domain] = 'black';
    review[i + 1] = review[i + 1].replace(/^unknown\t/, 'black\tタイトルが詐欺ページと一致');
  }
});

fs.writeFileSync(labelFile, JSON.stringify(labels, null, 1));
fs.writeFileSync(path.join(args.samples, 'labels-review.tsv'), '﻿' + review.join('\n'), 'utf8');
const count = {};
Object.values(labels).forEach((v) => { count[v] = (count[v] || 0) + 1; });
console.log(`ラベル: 詐欺 ${count.black || 0} / 正規 ${count.white || 0} / 判断保留 ${count.unknown || 0}`);
console.log(`確認用一覧: ${path.join(args.samples, 'labels-review.tsv')}`);
console.log('手で直す場合は labels-manual.json に {"登録ドメイン": "black"|"white"} を書いて再実行してください。');
