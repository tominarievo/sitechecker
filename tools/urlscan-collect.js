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
 *        [--frame keyword|generic] [--since YYYY-MM-DD] [--pages N] [--exclude <過去の収集フォルダ>]... [--interval ms]
 *   → <フォルダ>/samples.jsonl（1行1件のメタデータ）と <フォルダ>/dom/<id>.html.txt を出力
 *   既存の samples.jsonl があれば追記する（同じスキャンIDは重複させない）
 *
 * 収集の枠（--frame）:
 *   keyword（既定）: 偽通販のタイトルに多い言い回しで検索する。判定ルールの文言と重なるため、
 *                    ルール作り・傾向の把握用。精度評価に使うと検知率が実際より高く出る
 *   generic        : 判定ルールに依存しない条件で集める（精度評価用）。
 *                    「日本語タイトルに一般的な語（の・を・に…）を含む」「TLS 証明書が新しい（30日未満）」
 *                    ページを集め、本文の価格表示（¥・円）が5件以上ある「通販らしいページ」だけを残す。
 *                    価格表示は判定ルールでは使っていない特徴
 *   neutral        : 判定ルールで使っていない、通販全般に現れる語（送料無料・SALE・公式…）でタイトルを検索し、
 *                    generic と同じく価格表示で通販らしいページだけを残す（精度評価の偽通販側の候補集め用）
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

// 判定ルールに依存しない収集枠（generic）: 日本語タイトルによく現れる一般的な語
const GENERIC_QUERIES = ['の', 'を', 'に', 'で', 'と', 'は', 'が', 'も'].map((w) => `page.title:"${w}" AND page.tlsAgeDays:<30`);
// 判定ルールで使っていない、通販全般に現れる語（neutral 枠）。
// 「通販」「ショップ」「激安」「最安値」はルールの文言（○○通販サイト、専門ショップ、激安入荷、最安値挑戦）と重なるため使わない
const NEUTRAL_QUERIES = ['送料無料', 'SALE', 'セール', 'クーポン', 'ポイント', '公式', 'ストア', '新作', '限定', '人気']
  .map((w) => `page.title:"${w}"`);
const MIN_PRICES = 5; // generic・neutral 枠で「通販らしいページ」とみなす価格表示の件数

const args = {
  out: null, keyFile: null, days: 60, perQuery: 100, max: 200,
  frame: 'keyword', since: null, pages: 1, exclude: [], interval: INTERVAL_MS,
};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]; const v = process.argv[i + 1];
  if (a === '--out') { args.out = v; i++; }
  else if (a === '--key-file') { args.keyFile = v; i++; }
  else if (a === '--days') { args.days = Number(v); i++; }
  else if (a === '--per-query') { args.perQuery = Number(v); i++; }
  else if (a === '--max') { args.max = Number(v); i++; }
  else if (a === '--frame') { args.frame = v; i++; }
  else if (a === '--since') { args.since = v; i++; }
  else if (a === '--pages') { args.pages = Number(v); i++; }
  else if (a === '--exclude') { args.exclude.push(v); i++; }
  else if (a === '--interval') { args.interval = Number(v); i++; }
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
    const wait = lastRequest + args.interval - Date.now();
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

/** 本文中の価格表示（¥1,234 / 1,234円）の件数。HTML をテキストとして数えるだけ */
function countPrices(html) {
  const text = String(html || '').replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ');
  return (text.match(/[¥￥]\s?\d{1,3}(?:,\d{3})+|[¥￥]\s?\d{3,}|\d{1,3}(?:,\d{3})+\s?円|\d{3,}\s?円/g) || []).length;
}

const readSamples = (dir) => {
  const f = path.join(dir, 'samples.jsonl');
  return fs.existsSync(f) ? fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
};

(async () => {
  const existing = fs.existsSync(SAMPLES)
    ? fs.readFileSync(SAMPLES, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : [];
  const seenIds = new Set(existing.map((s) => s.id));
  // 過去の収集（ルール作りに使ったデータ等）と同じ登録ドメインは除外する
  const seenDomains = new Set([...existing, ...args.exclude.flatMap(readSamples)].map((s) => s.domain));
  const queries = args.frame === 'generic' ? GENERIC_QUERIES : args.frame === 'neutral' ? NEUTRAL_QUERIES : QUERIES;
  const filterByPrice = args.frame !== 'keyword';
  const dateCond = args.since ? `date:>=${args.since}` : `date:>now-${args.days}d`;

  // 1. 候補を検索（--pages で search_after によるページ送り）
  const candidates = [];
  for (const q of queries) {
    const query = `${q} AND ${dateCond}`;
    let results = [];
    let after = null;
    for (let pg = 0; pg < args.pages; pg++) {
      const json = await api(`${API}/api/v1/search/?size=${args.perQuery}&q=${encodeURIComponent(query)}` +
        (after ? `&search_after=${encodeURIComponent(after)}` : ''));
      const batch = (json && json.results) || [];
      results = results.concat(batch);
      if (batch.length < args.perQuery || !batch[batch.length - 1].sort) break;
      after = batch[batch.length - 1].sort.join(',');
    }
    let added = 0;
    for (const h of results) {
      const page = h.page || {};
      if (Number(page.status) !== 200 || !hasKana(page.title) || seenIds.has(h._id)) continue;
      const r = analyze(page.url || page.domain);
      if (!r.domain || r.whitelisted || seenDomains.has(r.domain)) continue; // 1登録ドメインにつき1件
      seenIds.add(h._id);
      seenDomains.add(r.domain);
      candidates.push({ id: h._id, url: page.url, host: r.hostname, domain: r.domain, title: page.title,
        time: h.task && h.task.time, query: q, frame: args.frame });
      added++;
    }
    console.log(`検索: ${q} → ${results.length}件中 ${added}件を候補に追加`);
  }

  // 2. 描画後の HTML（DOM スナップショット）を取得
  // generic 枠は DOM を見て通販らしいページだけを残すため、上限は「DOM を取得する件数」として扱う
  const take = candidates.slice(0, Math.max(0, filterByPrice ? args.max : args.max - existing.length));
  console.log(`\nDOM取得: ${take.length}件（既存 ${existing.length}件）`);
  const out = fs.createWriteStream(SAMPLES, { flags: 'a' });
  let kept = 0;
  let skipped = 0;
  for (let i = 0; i < take.length; i++) {
    const c = take[i];
    try {
      const html = await api(`${API}/dom/${c.id}/`, false);
      if (!html) continue;
      if (filterByPrice) {
        c.prices = countPrices(html);
        if (c.prices < MIN_PRICES) { skipped++; continue; } // 通販らしくないページは保存しない
      }
      fs.writeFileSync(path.join(DOM_DIR, c.id + '.html.txt'), html);
      out.write(JSON.stringify(c) + '\n');
      kept++;
    } catch (e) {
      process.stderr.write(`  失敗 ${c.host}: ${e.message}\n`);
    }
    if (i % 20 === 19) process.stderr.write(`  ${i + 1}/${take.length}\n`);
  }
  out.end();
  console.log(`保存: ${kept}件${filterByPrice ? `（価格表示が${MIN_PRICES}件未満のため除外: ${skipped}件）` : ''}`);
  console.log(`保存先: ${SAMPLES}`);
})().catch((e) => { console.error(e.message); process.exit(1); });
