/**
 * urlscan.io の公開スキャン結果を使って、ページ内容の解析（page-analyzer.js）を含めた判定精度を評価する。
 *
 * 安全のための方針:
 * - 詐欺サイトに接続するのは urlscan.io 側。こちらは urlscan.io の API にのみアクセスする
 * - 取得した HTML（描画後の DOM スナップショット）はブラウザで開かず、文字列としてのみ処理する
 * - 取得データは --cache のフォルダ（プロジェクト外を推奨）にだけ保存する
 * - API への負荷をかけないよう、リクエストの間隔を空け、結果はキャッシュする
 *
 * 使い方:
 *   API キーは環境変数 URLSCAN_API_KEY か、--key-file で指定したファイル（キーだけを1行で記載）から読み込む。
 *   node tests/urlscan-eval.js --black caa.txt --black jpcert.csv --white white.txt \
 *        --sample 50 --cache <フォルダ> [--key-file <ファイル>] [--out <フォルダ>]
 *
 * リストの形式は tests/evaluate.js と同じ（1行1ドメイン / URL / JPCERT csv 等。":head" で先頭から抽出）。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { htmlToText } = require('./html-to-text');

require(path.join(__dirname, '..', 'detector.js'));
require(path.join(__dirname, '..', 'page-analyzer.js'));
const { analyze, THRESHOLD_CAUTION } = globalThis.SiteRiskDetector;
const { analyzePage } = globalThis.SiteRiskPageAnalyzer;

const API = 'https://urlscan.io';
const INTERVAL_MS = 2500;      // リクエスト間隔
const MAX_DOM_BYTES = 3 * 1024 * 1024;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- 引数 -----------------------------------------------------------------
const args = { black: [], white: [], sample: 50, seed: 42, cache: null, keyFile: null, out: null };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]; const v = process.argv[i + 1];
  if (a === '--black') { args.black.push(v); i++; }
  else if (a === '--white') { args.white.push(v); i++; }
  else if (a === '--sample') { args.sample = Number(v); i++; }
  else if (a === '--seed') { args.seed = Number(v); i++; }
  else if (a === '--cache') { args.cache = v; i++; }
  else if (a === '--key-file') { args.keyFile = v; i++; }
  else if (a === '--out') { args.out = v; i++; }
}
if (!args.cache || (!args.black.length && !args.white.length)) {
  console.error('使い方: node tests/urlscan-eval.js --black <file> --white <file> --cache <dir> [--sample N] [--key-file <file>] [--out <dir>]');
  process.exit(1);
}
const API_KEY = (process.env.URLSCAN_API_KEY || (args.keyFile ? fs.readFileSync(args.keyFile, 'utf8') : '')).trim();
if (!API_KEY) {
  console.error('API キーがありません。環境変数 URLSCAN_API_KEY を設定するか、--key-file を指定してください。');
  process.exit(1);
}
fs.mkdirSync(path.join(args.cache, 'search'), { recursive: true });
fs.mkdirSync(path.join(args.cache, 'dom'), { recursive: true });

// ---- リスト読み込み（evaluate.js と同じ形式） --------------------------------------
function parseLine(line) {
  let s = line.trim();
  if (!s || s.startsWith('#') || s.startsWith('!')) return null;
  const jpcert = s.match(/^\d{4}\/\d{2}\/\d{2}[^,]*,([^,]+),/);
  if (jpcert) return jpcert[1];
  if (/^date,url,/i.test(s)) return null;
  const csv = s.match(/^\d+,(.+)$/);
  if (csv) s = csv[1];
  return s.replace(/^\*\./, '');
}

function rng(seed) {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function loadList(spec) {
  const m = spec.match(/^(.*?)((?::(?:head))*)$/);
  const file = m[1];
  const head = m[2].includes('head');
  const hosts = fs.readFileSync(file, 'utf8').split(/\r?\n/).map(parseLine).filter(Boolean)
    .map((x) => analyze(x).hostname).filter(Boolean);
  let items = [...new Set(hosts)];
  if (!head) {
    const rand = rng(args.seed);
    for (let i = items.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [items[i], items[j]] = [items[j], items[i]];
    }
  }
  return { name: path.basename(file), items: items.slice(0, args.sample) };
}

// ---- urlscan API ------------------------------------------------------------
let lastRequest = 0;
async function api(url, { json = true } = {}) {
  for (let attempt = 0; attempt < 4; attempt++) {
    const wait = lastRequest + INTERVAL_MS - Date.now();
    if (wait > 0) await sleep(wait);
    lastRequest = Date.now();
    const res = await fetch(url, { headers: { 'API-Key': API_KEY, Accept: json ? 'application/json' : 'text/html' } });
    if (res.status === 429) {
      const after = Number(res.headers.get('x-rate-limit-reset-after') || res.headers.get('retry-after') || 60);
      process.stderr.write(`  レート制限: ${after}秒待機\n`);
      await sleep((after + 1) * 1000);
      continue;
    }
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`HTTP ${res.status} ${url.replace(API, '')}`);
    if (json) return res.json();
    const buf = Buffer.from(await res.arrayBuffer());
    return buf.length > MAX_DOM_BYTES ? buf.subarray(0, MAX_DOM_BYTES).toString('utf8') : buf.toString('utf8');
  }
  throw new Error('レート制限が解除されません');
}

/** ドメインの最新の公開スキャンを探す（キャッシュ付き） */
async function findScan(host) {
  const file = path.join(args.cache, 'search', host.replace(/[^a-z0-9.-]/gi, '_') + '.json');
  if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  const q = encodeURIComponent(`page.domain:"${host}"`);
  const json = await api(`${API}/api/v1/search/?q=${q}&size=10`);
  const hits = (json && json.results) || [];
  // 描画に成功したスキャン（HTTP 200）を優先
  const hit = hits.find((h) => h.page && Number(h.page.status) === 200) || hits[0] || null;
  const scan = hit ? { id: hit._id, url: (hit.page && hit.page.url) || (hit.task && hit.task.url), time: hit.task && hit.task.time,
    status: hit.page && hit.page.status, country: hit.page && hit.page.country } : null;
  fs.writeFileSync(file, JSON.stringify(scan));
  return scan;
}

async function getDom(id) {
  const file = path.join(args.cache, 'dom', id + '.html.txt'); // 拡張子を .txt にしてブラウザで開かれないようにする
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8');
  const html = await api(`${API}/dom/${id}/`, { json: false });
  fs.writeFileSync(file, html || '');
  return html || '';
}

// ---- 評価 -------------------------------------------------------------------
function loadBlocklist() {
  const file = path.join(__dirname, '..', 'data', 'blocklist.txt');
  return new Set(fs.readFileSync(file, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#')));
}

const pct = (a, b) => (b ? ((a / b) * 100).toFixed(1) + '%' : '-');

async function evaluate(list, kind, blocklist) {
  const rows = [];
  for (let i = 0; i < list.items.length; i++) {
    const host = list.items[i];
    process.stderr.write(`  [${list.name}] ${i + 1}/${list.items.length} ${host}\n`);
    let scan = null; let page = null; let error = null;
    try {
      scan = await findScan(host);
      if (scan) {
        const html = await getDom(scan.id);
        if (html && html.length > 200) page = htmlToText(html);
      }
    } catch (e) { error = e.message; }

    const urlOnly = analyze(scan ? scan.url : host, { blocklist });
    const pageResult = page ? analyzePage(page) : null;
    const combined = analyze(scan ? scan.url : host, { blocklist, pageSignals: pageResult ? pageResult.signals : [] });
    rows.push({ host, scan, error, hasPage: !!page, title: page ? page.title : '', isShop: pageResult ? pageResult.isShop : null,
      urlOnly: urlOnly.score, combined: combined.score, pageSignals: pageResult ? pageResult.signals : [] });
  }

  const withPage = rows.filter((r) => r.hasPage);
  const det = (arr, key) => arr.filter((r) => r[key] >= THRESHOLD_CAUTION).length;
  const label = kind === 'black' ? '検知率' : '誤検知率';
  console.log(`\n■ [${kind === 'black' ? 'ブラック' : 'ホワイト'}] ${list.name}（${rows.length}件）`);
  console.log(`  urlscan にスキャンあり: ${rows.filter((r) => r.scan).length}件 ／ 本文を取得: ${withPage.length}件 ／ うち通販ページ判定: ${withPage.filter((r) => r.isShop).length}件`);
  console.log(`  本文を取得できた${withPage.length}件での${label}: URLのみ ${pct(det(withPage, 'urlOnly'), withPage.length)} → URL+ページ内容 ${pct(det(withPage, 'combined'), withPage.length)}`);
  const sig = {};
  withPage.forEach((r) => r.pageSignals.forEach((s) => { const k = s.detail.replace(/（.*$/, ''); sig[k] = (sig[k] || 0) + 1; }));
  console.log('  ページ内容の検出: ' + (Object.entries(sig).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k}=${v}`).join(' ／ ') || 'なし'));
  const show = kind === 'black'
    ? withPage.filter((r) => r.combined < THRESHOLD_CAUTION).slice(0, 10)
    : withPage.filter((r) => r.combined >= THRESHOLD_CAUTION);
  if (show.length) {
    console.log(kind === 'black' ? '  見逃し例（本文あり）:' : '  誤検知:');
    show.forEach((r) => console.log(`    ${String(r.combined).padStart(3)}%  ${r.host}  「${r.title.slice(0, 40)}」  ${r.pageSignals.map((s) => s.detail + '+' + s.points).join(' / ')}`));
  }
  const errors = rows.filter((r) => r.error);
  if (errors.length) console.log(`  エラー: ${errors.length}件（例: ${errors[0].error}）`);
  return { kind, name: list.name, rows };
}

(async () => {
  const blocklist = loadBlocklist();
  const all = [];
  for (const f of args.black) all.push(await evaluate(loadList(f), 'black', blocklist));
  for (const f of args.white) all.push(await evaluate(loadList(f), 'white', blocklist));
  if (args.out) {
    fs.mkdirSync(args.out, { recursive: true });
    const file = path.join(args.out, 'urlscan-results.json');
    fs.writeFileSync(file, JSON.stringify(all.map((x) => ({ ...x, rows: x.rows.map((r) => ({ ...r })) })), null, 1));
    console.log('\n結果: ' + file);
  }
})().catch((e) => { console.error(e.message); process.exit(1); });
