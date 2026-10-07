/**
 * urlscan.io の公開スキャンから、日本語の通販系ページ（偽通販の候補を含む）を収集する。
 *
 * 安全のための方針:
 * - 詐欺サイトに接続するのは urlscan.io 側。こちらは urlscan.io の API にのみアクセスする
 * - 取得した HTML はブラウザで開かず、拡張子 .txt で保存して文字列としてのみ扱う
 * - リクエスト間隔を空け、取得済みのものは再取得しない
 *
 * 使い方:
 *   node tools/urlscan-collect.js --out <フォルダ> [--key-file <file>] [--days 60] [--per-query 100] [--max 200]
 *   → <フォルダ>/samples.jsonl（1行1件のメタデータ）と <フォルダ>/dom/<id>.html.txt を出力
 *   既存の samples.jsonl があれば追記する（同じスキャンIDは重複させない）
 */
'use strict';

const fs = require('fs');
const path = require('path');

require(path.join(__dirname, '..', 'detector.js'));
const { analyze } = globalThis.SiteRiskDetector;

const API = 'https://urlscan.io';
const INTERVAL_MS = 2500;
const MAX_DOM_BYTES = 3 * 1024 * 1024;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 偽通販サイトのタイトルに多い言い回し（正規サイトも一部使うため、ここでは「候補集め」にのみ使う）
const QUERIES = [
  'page.title:"株式会社" AND page.title:"いち早く通販"',
  'page.title:"最安値挑戦"',
  'page.title:"最安値に挑戦"',
  'page.title:"お見逃しなく"',
  'page.title:"ショッピングサイト"',
  'page.title:"送料無料" AND page.title:"OFF"',
  'page.title:"公式通販"',
  'page.title:"アウトレット" AND page.title:"送料無料"',
];

const args = { out: null, keyFile: null, days: 60, perQuery: 100, max: 200 };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]; const v = process.argv[i + 1];
  if (a === '--out') { args.out = v; i++; }
  else if (a === '--key-file') { args.keyFile = v; i++; }
  else if (a === '--days') { args.days = Number(v); i++; }
  else if (a === '--per-query') { args.perQuery = Number(v); i++; }
  else if (a === '--max') { args.max = Number(v); i++; }
}
if (!args.out) {
  console.error('使い方: node tools/urlscan-collect.js --out <dir> [--key-file <file>] [--days 60] [--per-query 100] [--max 200]');
  process.exit(1);
}
const API_KEY = (process.env.URLSCAN_API_KEY || (args.keyFile ? fs.readFileSync(args.keyFile, 'utf8') : '')).trim();
if (!API_KEY) { console.error('API キーがありません（URLSCAN_API_KEY または --key-file）'); process.exit(1); }

const DOM_DIR = path.join(args.out, 'dom');
const SAMPLES = path.join(args.out, 'samples.jsonl');
fs.mkdirSync(DOM_DIR, { recursive: true });

let lastRequest = 0;
async function api(url, json = true) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const wait = lastRequest + INTERVAL_MS - Date.now();
    if (wait > 0) await sleep(wait);
    lastRequest = Date.now();
    const res = await fetch(url, { headers: { 'API-Key': API_KEY } });
    if (res.status === 429) {
      const after = Number(res.headers.get('x-rate-limit-reset-after') || 60);
      process.stderr.write(`  レート制限: ${after}秒待機\n`);
      await sleep((after + 1) * 1000);
      continue;
    }
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    if (json) return res.json();
    const buf = Buffer.from(await res.arrayBuffer());
    return buf.subarray(0, MAX_DOM_BYTES).toString('utf8');
  }
  throw new Error('レート制限が解除されません');
}

const hasKana = (s) => /[ぁ-ゖァ-ヺ]/.test(s || '');

(async () => {
  const existing = fs.existsSync(SAMPLES)
    ? fs.readFileSync(SAMPLES, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : [];
  const seenIds = new Set(existing.map((s) => s.id));
  const seenDomains = new Set(existing.map((s) => s.domain));

  // 1. 候補を検索
  const candidates = [];
  for (const q of QUERIES) {
    const query = `${q} AND date:>now-${args.days}d`;
    const json = await api(`${API}/api/v1/search/?size=${args.perQuery}&q=${encodeURIComponent(query)}`);
    const results = (json && json.results) || [];
    let added = 0;
    for (const h of results) {
      const page = h.page || {};
      if (Number(page.status) !== 200 || !hasKana(page.title) || seenIds.has(h._id)) continue;
      const r = analyze(page.url || page.domain);
      if (!r.domain || r.whitelisted || seenDomains.has(r.domain)) continue; // 1登録ドメインにつき1件
      seenIds.add(h._id);
      seenDomains.add(r.domain);
      candidates.push({ id: h._id, url: page.url, host: r.hostname, domain: r.domain, title: page.title,
        time: h.task && h.task.time, query: q });
      added++;
    }
    console.log(`検索: ${q} → ${results.length}件中 ${added}件を候補に追加`);
  }

  // 2. 描画後の HTML（DOM スナップショット）を取得
  const take = candidates.slice(0, Math.max(0, args.max - existing.length));
  console.log(`\nDOM取得: ${take.length}件（既存 ${existing.length}件）`);
  const out = fs.createWriteStream(SAMPLES, { flags: 'a' });
  for (let i = 0; i < take.length; i++) {
    const c = take[i];
    try {
      const html = await api(`${API}/dom/${c.id}/`, false);
      if (!html) continue;
      fs.writeFileSync(path.join(DOM_DIR, c.id + '.html.txt'), html);
      out.write(JSON.stringify(c) + '\n');
    } catch (e) {
      process.stderr.write(`  失敗 ${c.host}: ${e.message}\n`);
    }
    if (i % 20 === 19) process.stderr.write(`  ${i + 1}/${take.length}\n`);
  }
  out.end();
  console.log(`保存先: ${SAMPLES}`);
})().catch((e) => { console.error(e.message); process.exit(1); });
