/**
 * 収集したページ（tools/urlscan-collect.js / tests/urlscan-eval.js のキャッシュ）を使って、
 * ページ内容の判定ルールごとの「詐欺ページでの反応率」と「正規ページでの反応率」を比べる。
 * HTML はファイルから文字列として読むだけで、ネットワーク通信は行わない。
 *
 * 使い方:
 *   node tests/content-eval.js --samples <collectの出力フォルダ> --labels <labels.json>
 *        [--legit <正規サイト一覧> --legit-cache <urlscan-eval の --cache フォルダ>]... [--miss-by-page]
 *
 * --miss-by-page  見逃し一覧を「ページ内容のみのスコア」で出す（URLの特徴でラベルを付けたデータ向け）
 *
 * labels.json: { "<登録ドメイン>": "black" | "white" | "unknown", ... }
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { htmlToText } = require('./html-to-text');

require(path.join(__dirname, '..', 'detector.js'));
require(path.join(__dirname, '..', 'page-analyzer.js'));
const { analyze, THRESHOLD_CAUTION, THRESHOLD_DANGER } = globalThis.SiteRiskDetector;
const { analyzePage } = globalThis.SiteRiskPageAnalyzer;

const args = { samples: null, labels: null, legit: [], legitCache: null, missByPage: false, withBlocklist: false, target: false };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]; const v = process.argv[i + 1];
  if (a === '--samples') { args.samples = v; i++; }
  else if (a === '--labels') { args.labels = v; i++; }
  else if (a === '--legit') { args.legit.push(v); i++; }
  else if (a === '--legit-cache') { args.legitCache = v; i++; }
  else if (a === '--miss-by-page') { args.missByPage = true; }
  else if (a === '--with-blocklist') { args.withBlocklist = true; }
  else if (a === '--target') { args.target = true; }
}

const pages = []; // { label, host, url, title, html }

if (args.samples) {
  const labels = args.labels ? JSON.parse(fs.readFileSync(args.labels, 'utf8')) : {};
  fs.readFileSync(path.join(args.samples, 'samples.jsonl'), 'utf8').split('\n').filter(Boolean).forEach((l) => {
    const s = JSON.parse(l);
    const label = labels[s.domain] || 'unknown';
    const file = path.join(args.samples, 'dom', s.id + '.html.txt');
    if (label !== 'unknown' && fs.existsSync(file)) pages.push({ label, host: s.host, url: s.url, title: s.title, file });
  });
}

if (args.legitCache) {
  args.legit.forEach((list) => {
    fs.readFileSync(list.replace(/:head$/, ''), 'utf8').split(/\r?\n/).map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#')).forEach((host) => {
        const sf = path.join(args.legitCache, 'search', host + '.json');
        if (!fs.existsSync(sf)) return;
        const scan = JSON.parse(fs.readFileSync(sf, 'utf8'));
        const file = scan && path.join(args.legitCache, 'dom', scan.id + '.html.txt');
        if (file && fs.existsSync(file)) pages.push({ label: 'white', host, url: scan.url, title: '', file });
      });
  });
}

// ---- 判定 -------------------------------------------------------------------
const blocklist = args.withBlocklist
  ? new Set(fs.readFileSync(path.join(__dirname, '..', 'data', 'blocklist.txt'), 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#')))
  : null;
const rows = pages.map((p) => {
  const doc = htmlToText(fs.readFileSync(p.file, 'utf8'));
  const { isShop, signals } = analyzePage(doc);
  // 既定ではブラックリストを使わない（ルール作りのデータとの循環を避ける）。--with-blocklist で出荷時と同じ設定にする
  const urlOnly = analyze(p.url || p.host, { blocklist });
  const combined = analyze(p.url || p.host, { blocklist, pageSignals: signals });
  const pageScore = Math.max(0, Math.min(100, signals.reduce((sum, s) => sum + s.points, 0)));
  return { ...p, title: p.title || doc.title, textLen: doc.text.length, isShop, signals,
    urlScore: urlOnly.score, urlReasons: urlOnly.reasons, score: combined.score, pageScore };
}).filter((r) => r.textLen >= 200); // エラーページ等を除外

const black = rows.filter((r) => r.label === 'black');
const white = rows.filter((r) => r.label === 'white');
const pct = (a, b) => (b ? ((a / b) * 100).toFixed(0) + '%' : '-');

console.log(`評価対象: 詐欺 ${black.length}件 / 正規 ${white.length}件（本文200文字以上）`);

// ルールごとの反応率
const ruleKey = (s) => s.detail.replace(/（.*$/, '');
const rules = [...new Set(rows.flatMap((r) => r.signals.map(ruleKey)))];
console.log('\n■ ページ内容のルール別 反応率（詐欺 / 正規）');
rules.map((k) => ({
  k,
  b: black.filter((r) => r.signals.some((s) => ruleKey(s) === k)).length,
  w: white.filter((r) => r.signals.some((s) => ruleKey(s) === k)).length,
})).sort((x, y) => y.b - x.b).forEach(({ k, b, w }) => {
  console.log(`  ${pct(b, black.length).padStart(4)} / ${pct(w, white.length).padStart(4)}  ${k}`);
});

// URL ルールの反応率（参考）
const urlCats = [...new Set(rows.flatMap((r) => r.urlReasons.map((x) => x.category)))];
console.log('\n■ URLルールの区分別 反応率（詐欺 / 正規）');
urlCats.forEach((c) => {
  const b = black.filter((r) => r.urlReasons.some((x) => x.category === c)).length;
  const w = white.filter((r) => r.urlReasons.some((x) => x.category === c)).length;
  console.log(`  ${pct(b, black.length).padStart(4)} / ${pct(w, white.length).padStart(4)}  ${c}`);
});

// しきい値別
console.log('\n■ しきい値別（URLのみ → URL+ページ内容）');
[THRESHOLD_CAUTION, 30, 25].forEach((t) => {
  const d = (arr, key) => arr.filter((r) => r[key] >= t).length;
  console.log(`  ${t}%以上: 検知 ${pct(d(black, 'urlScore'), black.length)} → ${pct(d(black, 'score'), black.length)}` +
    `   誤検知 ${pct(d(white, 'urlScore'), white.length)} → ${pct(d(white, 'score'), white.length)}`);
});
console.log(`  危険(${THRESHOLD_DANGER}%以上): 検知 ${pct(black.filter((r) => r.score >= THRESHOLD_DANGER).length, black.length)}`);

// ページ内容だけのスコア（URLの特徴でラベルを付けたデータでは、こちらが独立した指標になる）
console.log('\n■ ページ内容のみのスコア');
[THRESHOLD_CAUTION, 30, 25].forEach((t) => {
  const d = (arr) => arr.filter((r) => r.pageScore >= t).length;
  console.log(`  ${t}%以上: 検知 ${pct(d(black), black.length)}   誤検知 ${pct(d(white), white.length)}`);
});

const fp = white.filter((r) => r.score >= THRESHOLD_CAUTION);
if (fp.length) {
  console.log('\n■ 正規ページの誤検知');
  fp.forEach((r) => console.log(`  ${r.score}%  ${r.host}  ${r.signals.map((s) => s.detail + '+' + s.points).join(' / ')}`));
}
const missKey = args.missByPage ? 'pageScore' : 'score';
const miss = black.filter((r) => r[missKey] < THRESHOLD_CAUTION);
if (miss.length) {
  console.log(`\n■ 詐欺ページの見逃し${args.missByPage ? '（ページ内容のみ）' : ''}（${miss.length}件、先頭15件）`);
  miss.slice(0, 15).forEach((r) => console.log(`  ${String(r[missKey]).padStart(3)}%  ${r.host}  「${r.title.slice(0, 30)}」 ${r.signals.map((s) => s.detail.replace(/（.*$/, '') + '+' + s.points).join(' / ')}`));
}

// ---- 出荷基準の判定（--target）: 偽通販・正規各300件以上、検知率90%以上、誤検知率1%以下 ----
if (args.target) {
  const det = black.filter((r) => r.score >= THRESHOLD_CAUTION).length / (black.length || 1);
  const fpr = white.filter((r) => r.score >= THRESHOLD_CAUTION).length / (white.length || 1);
  const checks = [
    [black.length >= 300, `偽通販の件数 ${black.length} ≥ 300`],
    [white.length >= 300, `正規サイトの件数 ${white.length} ≥ 300`],
    [det >= 0.9, `検知率（注意以上）${(det * 100).toFixed(1)}% ≥ 90%`],
    [fpr <= 0.01, `誤検知率（注意以上）${(fpr * 100).toFixed(1)}% ≤ 1%`],
  ];
  console.log(`
■ 出荷基準（${args.withBlocklist ? 'ブラックリストあり＝出荷時の設定' : 'ブラックリストなし'}、RDAP・フィッシングの追加チェックはオフ）`);
  checks.forEach(([ok, label]) => console.log(`  ${ok ? '✓' : '✗'} ${label}`));
  console.log(checks.every(([ok]) => ok) ? '  → 基準を満たしています' : '  → 基準を満たしていません');
}
