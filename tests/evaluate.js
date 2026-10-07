/**
 * 判定ロジックのオフライン評価スクリプト。
 * リストのURL/ドメインには一切アクセスせず、文字列として detector.js に渡すだけ。
 *
 * 使い方:
 *   node tests/evaluate.js --black <file> [--black <file> ...] --white <file> [--white <file> ...]
 *                          [--sample 1000] [--seed 42] [--out <dir>]
 *                          [--no-blocklist] [--rdap <件数>] [--rdap-cache <file>]
 *
 * --no-blocklist  同梱ブラックリスト（data/blocklist.txt）を使わずに判定
 * --rdap N        各リストの先頭N件について RDAP で登録日を照会して判定に加える。
 *                 問い合わせ先は rdap.org / 各レジストリのみ（リスト内のサイトには接続しない）。
 *                 負荷をかけないよう 1 件ずつ間隔を空けて照会し、結果はキャッシュする。
 *
 * 対応フォーマット: 1行1ドメイン / 1行1URL / hostsファイル / Trancoのcsv（rank,domain）/ "*.domain"
 *                  / JPCERT/CC phishurl-list の csv（date,URL,description）
 * ファイル名の後ろに ":jp" を付けると .jp ドメインだけを抽出（例: top-1m.csv:jp）
 * ファイル名の後ろに ":head" を付けると先頭から抽出（既定は無作為抽出）
 */
'use strict';

const fs = require('fs');
const path = require('path');

require(path.join(__dirname, '..', 'detector.js'));
require(path.join(__dirname, '..', 'rdap.js'));
const { analyze, THRESHOLD_CAUTION, THRESHOLD_DANGER } = globalThis.SiteRiskDetector;
const { lookupRegistration } = globalThis.SiteRiskRdap;

// ---- 引数 -----------------------------------------------------------------

const args = {
  black: [], white: [], sample: 1000, seed: 42, out: null,
  blocklist: true, rdap: 0, rdapCache: path.join(__dirname, '.rdap-cache.json'),
};
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  const v = process.argv[i + 1];
  if (a === '--black') { args.black.push(v); i++; }
  else if (a === '--white') { args.white.push(v); i++; }
  else if (a === '--sample') { args.sample = Number(v); i++; }
  else if (a === '--seed') { args.seed = Number(v); i++; }
  else if (a === '--out') { args.out = v; i++; }
  else if (a === '--no-blocklist') { args.blocklist = false; }
  else if (a === '--rdap') { args.rdap = Number(v); i++; }
  else if (a === '--rdap-cache') { args.rdapCache = v; i++; }
}
if (!args.black.length && !args.white.length) {
  console.error('使い方: node tests/evaluate.js --black <file> --white <file> [--sample N] [--out dir]');
  process.exit(1);
}

// ---- 読み込み ---------------------------------------------------------------

function parseLine(line) {
  let s = line.trim();
  if (!s || s.startsWith('#') || s.startsWith('!')) return null;
  s = s.replace(/\s+#.*$/, '');
  const jpcert = s.match(/^\d{4}\/\d{2}\/\d{2}[^,]*,([^,]+),/);
  if (jpcert) return jpcert[1];
  if (/^date,url,/i.test(s)) return null;
  const hosts = s.match(/^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)/);
  if (hosts) s = hosts[1];
  const csv = s.match(/^\d+,(.+)$/);
  if (csv) s = csv[1];
  s = s.replace(/^\|\|/, '').replace(/\^.*$/, '').replace(/^\*\./, '');
  if (!s || s === 'localhost') return null;
  return s;
}

// 再現性のある乱数（mulberry32）
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
  const m = spec.match(/^(.*?)((?::(?:jp|head))*)$/);
  const file = m[1];
  const opts = m[2].split(':').filter(Boolean);
  const jpOnly = opts.includes('jp');
  const head = opts.includes('head');
  let items = fs.readFileSync(file, 'utf8').split(/\r?\n/).map(parseLine).filter(Boolean);
  if (jpOnly) items = items.filter((d) => /\.jp(?:[/:]|$)/i.test(d.replace(/^https?:\/\//, '')));
  items = [...new Set(items)];
  if (items.length > args.sample) {
    if (head) {
      items = items.slice(0, args.sample);
    } else {
      const rand = rng(args.seed);
      for (let i = items.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [items[i], items[j]] = [items[j], items[i]];
      }
      items = items.slice(0, args.sample);
    }
  }
  return { name: path.basename(file) + (opts.length ? ':' + opts.join(':') : ''), items };
}

// ---- 評価 -----------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function loadBlocklist() {
  const file = path.join(__dirname, '..', 'data', 'blocklist.txt');
  return new Set(fs.readFileSync(file, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#')));
}

let rdapCache = {};
let rdapBootstrap = null;
function loadRdapCache() {
  try { rdapCache = JSON.parse(fs.readFileSync(args.rdapCache, 'utf8')); } catch (_) { rdapCache = {}; }
}
function saveRdapCache() {
  fs.writeFileSync(args.rdapCache, JSON.stringify(rdapCache));
}

async function domainInfoFor(domain) {
  if (rdapCache[domain] && rdapCache[domain].status !== 'error') return rdapCache[domain];
  if (!rdapBootstrap) rdapBootstrap = await globalThis.SiteRiskRdap.fetchBootstrap();
  const tld = domain.split('.').pop();
  if (!rdapBootstrap[tld]) return (rdapCache[domain] = { status: 'unsupported' }); // 非対応TLDは通信しない
  const info = await lookupRegistration(domain, { bootstrap: rdapBootstrap, timeoutMs: 10000 });
  rdapCache[domain] = info;
  await sleep(1200); // rdap.org・各レジストリに負荷をかけないよう間隔を空ける
  return info;
}

async function evaluate(list, blocklist) {
  const results = [];
  const rdapStats = {};
  for (let i = 0; i < list.items.length; i++) {
    const input = list.items[i];
    let domainInfo = null;
    if (i < args.rdap) {
      const first = analyze(input);
      if (first.rdapEligible && !first.whitelisted) {
        domainInfo = await domainInfoFor(first.domain);
        rdapStats[domainInfo.status] = (rdapStats[domainInfo.status] || 0) + 1;
        if (i % 25 === 24) { saveRdapCache(); process.stderr.write(`  RDAP ${list.name}: ${i + 1}/${Math.min(args.rdap, list.items.length)}\n`); }
      }
    }
    results.push({ input, r: analyze(input, { blocklist, domainInfo }), rdap: i < args.rdap });
  }
  if (args.rdap) saveRdapCache();
  const valid = results.filter((x) => x.r.level !== 'invalid' && x.r.level !== 'unsupported');
  const n = valid.length;
  const danger = valid.filter((x) => x.r.score >= THRESHOLD_DANGER).length;
  const caution = valid.filter((x) => x.r.score >= THRESHOLD_CAUTION && x.r.score < THRESHOLD_DANGER).length;
  const whitelisted = valid.filter((x) => x.r.whitelisted).length;
  const anyReason = valid.filter((x) => x.r.score > 0).length;

  const buckets = [0, 0, 0, 0, 0]; // 0, 1-39, 40-59, 60-79, 80-100
  valid.forEach(({ r }) => {
    const s = r.score;
    buckets[s === 0 ? 0 : s < 40 ? 1 : s < 60 ? 2 : s < 80 ? 3 : 4]++;
  });

  const cats = {};
  valid.forEach(({ r }) => new Set(r.reasons.map((x) => x.category)).forEach((c) => {
    cats[c] = (cats[c] || 0) + 1;
  }));

  const tlds = {};
  valid.forEach(({ r }) => { tlds[r.tld] = (tlds[r.tld] || 0) + 1; });

  const blocklisted = valid.filter((x) => x.r.blocklisted).length;
  const rdapSubset = valid.filter((x) => x.rdap);
  const rdapDetect = rdapSubset.filter((x) => x.r.score >= THRESHOLD_CAUTION).length;
  const ages = rdapSubset.map((x) => x.r.domainAgeDays).filter((d) => d != null);
  return {
    name: list.name, total: results.length, n, danger, caution, whitelisted, anyReason, buckets, cats, tlds,
    blocklisted, rdapStats, rdapN: rdapSubset.length, rdapDetect, ages, results: valid,
  };
}

const pct = (a, b) => (b ? ((a / b) * 100).toFixed(1) + '%' : '-');
const top = (obj, k) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, k);

function report(ev, kind) {
  console.log(`\n■ [${kind === 'black' ? 'ブラック' : 'ホワイト'}] ${ev.name}  （有効 ${ev.n} / 読込 ${ev.total} 件）`);
  if (kind === 'black') {
    console.log(`  検知率（注意以上 ≥${THRESHOLD_CAUTION}%）: ${pct(ev.danger + ev.caution, ev.n)}   ` +
      `危険（≥${THRESHOLD_DANGER}%）: ${pct(ev.danger, ev.n)}   何らかの加点: ${pct(ev.anyReason, ev.n)}`);
    if (ev.whitelisted) console.log(`  ※ホワイトリストに該当して0%になった件数: ${ev.whitelisted}`);
  } else {
    if (ev.blocklisted) console.log(`  ※同梱ブラックリストに該当: ${ev.blocklisted}件`);
    console.log(`  誤検知率（注意以上）: ${pct(ev.danger + ev.caution, ev.n)}   ` +
      `うち危険: ${pct(ev.danger, ev.n)}   何らかの加点: ${pct(ev.anyReason, ev.n)}`);
  }
  const labels = ['0%', '1-39%', '40-59%', '60-79%', '80-100%'];
  console.log('  スコア分布: ' + ev.buckets.map((c, i) => `${labels[i]}=${c}`).join('  '));
  console.log('  判定要因（件数）: ' + (top(ev.cats, 12).map(([c, v]) => `${c}=${v}`).join('  ') || 'なし'));
  console.log('  TLD上位: ' + top(ev.tlds, 12).map(([t, v]) => `.${t}=${v}`).join('  '));
  if (kind === 'black') console.log(`  同梱ブラックリストに該当: ${pct(ev.blocklisted, ev.n)}`);
  if (ev.rdapN) {
    const a = ev.ages;
    const under = (d) => a.filter((x) => x < d).length;
    console.log(`  RDAP照会（先頭${ev.rdapN}件）: ` + Object.entries(ev.rdapStats).map(([k, v]) => `${k}=${v}`).join(' ') +
      `  ／ 登録日取得 ${a.length}件中: 30日未満=${under(30)} 90日未満=${under(90)} 1年未満=${under(365)} 2年以上=${a.filter((x) => x >= 730).length}`);
    console.log(`  RDAP照会した${ev.rdapN}件での${kind === 'black' ? '検知率' : '誤検知率'}: ${pct(ev.rdapDetect, ev.rdapN)}`);
  }

  const sample = kind === 'black'
    ? ev.results.filter((x) => x.r.score < THRESHOLD_CAUTION).slice(0, 15)
    : ev.results.filter((x) => x.r.score >= THRESHOLD_CAUTION).slice(0, 30);
  if (sample.length) {
    console.log(kind === 'black' ? '  見逃し例:' : '  誤検知した例:');
    sample.forEach(({ input, r }) => {
      console.log(`    ${String(r.score).padStart(3)}%  ${input}  [${r.reasons.map((x) => `${x.category}+${x.points}`).join(', ')}]`);
    });
  }
}

function writeCsv(ev, kind, dir) {
  const esc = (s) => `"${String(s).replace(/"/g, '""')}"`;
  const lines = ['kind,list,input,score,level,reasons'];
  ev.results.forEach(({ input, r }) => {
    lines.push([kind, ev.name, input, r.score, r.level, r.reasons.map((x) => `${x.category}+${x.points}:${x.detail}`).join(' | ')].map(esc).join(','));
  });
  const file = path.join(dir, `${kind}_${ev.name.replace(/[^a-z0-9_.-]/gi, '_')}.csv`);
  fs.writeFileSync(file, '﻿' + lines.join('\n'), 'utf8');
  return file;
}

// ---- 実行 -----------------------------------------------------------------

(async () => {
const blocklist = args.blocklist ? loadBlocklist() : null;
if (args.rdap) loadRdapCache();
console.log(`同梱ブラックリスト: ${blocklist ? blocklist.size + '件を使用' : '不使用'}` + (args.rdap ? `  ／ RDAP: 各リスト先頭${args.rdap}件` : ''));

const all = [];
for (const f of args.black) all.push(['black', await evaluate(loadList(f), blocklist)]);
for (const f of args.white) all.push(['white', await evaluate(loadList(f), blocklist)]);

all.forEach(([kind, ev]) => report(ev, kind));

const sum = (kind, key) => all.filter(([k]) => k === kind).reduce((s, [, ev]) => s + ev[key], 0);
console.log('\n======== 合計 ========');
if (args.black.length) {
  const n = sum('black', 'n');
  console.log(`ブラック ${n} 件: 検知率 ${pct(sum('black', 'danger') + sum('black', 'caution'), n)}（危険 ${pct(sum('black', 'danger'), n)}）`);
}
if (args.white.length) {
  const n = sum('white', 'n');
  console.log(`ホワイト ${n} 件: 誤検知率 ${pct(sum('white', 'danger') + sum('white', 'caution'), n)}（危険 ${pct(sum('white', 'danger'), n)}）`);
}

if (args.out) {
  fs.mkdirSync(args.out, { recursive: true });
  all.forEach(([kind, ev]) => console.log('CSV: ' + writeCsv(ev, kind, args.out)));
}
})();
