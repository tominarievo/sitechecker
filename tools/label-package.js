/**
 * 外部の作業者（クラウドソーシング等）にラベル付けを依頼するための依頼票を作り、回答を集計する。
 *
 * 安全とプライバシーの方針:
 * - 作業者には詐欺サイトの URL を渡さない。渡すのは urlscan.io のスクリーンショット画像の URL と、
 *   ドメイン名・ページタイトル（文字列）だけ
 * - 自動判定の結果やスコアは渡さない（判断が引きずられないようにする）
 *
 * 品質管理:
 * - 正解が分かっている確認用の問題（ゴールド）を混ぜ、作業者ごとの正答率を測る
 * - 1件を複数人に判定してもらい、正答率の基準を満たした作業者の回答で多数決する
 *
 * 1. 依頼票の作成:
 *    node tools/label-package.js --make <収集フォルダ> --gold <ゴールドのフォルダ> [--gold-rate 0.1] [--seed 1]
 *    → <収集フォルダ>/crowd/tasks.csv（作業者に渡す）、key.json（手元に保管・作業者に渡さない）
 *    ゴールドのフォルダには samples.jsonl と labels.json（{"登録ドメイン": "black"|"white"}）を置く
 * 2. 回答の集計:
 *    node tools/label-package.js --import <収集フォルダ> --answers <回答CSV> [--answers <回答CSV>]...
 *         [--min-gold-accuracy 0.8] [--min-votes 2]
 *    回答CSV: 列「task_id」「answer」と、作業者を表す列「worker_id」（無ければファイル名を作業者IDとする）
 *    → <収集フォルダ>/labels-human.json と crowd/report.txt
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ANSWERS = {
  black: ['詐欺', '偽', '偽通販', 'black', 'fake', 'scam'],
  white: ['正規', '本物', 'white', 'legit', 'genuine'],
  other: ['通販ではない', '通販以外', 'other', 'not shop', 'not-shop'],
  unsure: ['判断できない', 'わからない', '不明', 'unsure', 'unknown', ''],
};

const args = { make: null, imp: null, gold: null, goldRate: 0.1, seed: 1, answers: [], minGoldAccuracy: 0.8, minVotes: 2 };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i]; const v = process.argv[i + 1];
  if (a === '--make') { args.make = v; i++; }
  else if (a === '--import') { args.imp = v; i++; }
  else if (a === '--gold') { args.gold = v; i++; }
  else if (a === '--gold-rate') { args.goldRate = Number(v); i++; }
  else if (a === '--seed') { args.seed = Number(v); i++; }
  else if (a === '--answers') { args.answers.push(v); i++; }
  else if (a === '--min-gold-accuracy') { args.minGoldAccuracy = Number(v); i++; }
  else if (a === '--min-votes') { args.minVotes = Number(v); i++; }
}

const readSamples = (dir) => fs.readFileSync(path.join(dir, 'samples.jsonl'), 'utf8')
  .split('\n').filter(Boolean).map((l) => JSON.parse(l));
const clean = (s) => String(s || '').replace(/[\t\r\n"]+/g, ' ').trim();
const csvCell = (s) => `"${String(s).replace(/"/g, '""')}"`;

function rng(seed) {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function normalizeAnswer(raw) {
  const v = String(raw || '').trim().toLowerCase();
  for (const [key, words] of Object.entries(ANSWERS)) {
    if (words.some((w) => w.toLowerCase() === v)) return key;
  }
  return 'unsure';
}

function parseCsv(text) {
  const rows = [];
  let row = []; let cell = ''; let q = false;
  const t = text.replace(/^﻿/, '');
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (q) {
      if (c === '"' && t[i + 1] === '"') { cell += '"'; i++; } else if (c === '"') q = false; else cell += c;
    } else if (c === '"') q = true;
    else if (c === ',' || c === '\t') { row.push(cell); cell = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && t[i + 1] === '\n') i++;
      row.push(cell); rows.push(row); row = []; cell = '';
    } else cell += c;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((x) => x.trim()));
}

// ---- 1. 依頼票の作成 ----------------------------------------------------------
if (args.make) {
  const rand = rng(args.seed);
  const samples = readSamples(args.make);
  const items = samples.map((s) => ({ sampleId: s.id, domain: s.domain, title: s.title, gold: null }));
  if (args.gold) {
    const goldLabels = JSON.parse(fs.readFileSync(path.join(args.gold, 'labels.json'), 'utf8'));
    const goldSamples = readSamples(args.gold).filter((s) => goldLabels[s.domain] === 'black' || goldLabels[s.domain] === 'white');
    const want = Math.max(5, Math.round(items.length * args.goldRate));
    // 詐欺・正規を同数ずつ
    for (const label of ['black', 'white']) {
      const pool = goldSamples.filter((s) => goldLabels[s.domain] === label).sort(() => rand() - 0.5).slice(0, Math.ceil(want / 2));
      pool.forEach((s) => items.push({ sampleId: s.id, domain: s.domain, title: s.title, gold: label }));
    }
  }
  items.sort(() => rand() - 0.5);
  const key = {};
  const lines = ['task_id,ドメイン名,ページのタイトル,スクリーンショット,answer'];
  items.forEach((it, i) => {
    const id = `T${String(i + 1).padStart(4, '0')}`;
    key[id] = it;
    // ドメイン名は表計算ソフトでリンクにならないよう、無害化表記（evil[.]example）で渡す
    lines.push([id, clean(it.domain).split('.').join('[.]'), clean(it.title).slice(0, 80), `https://urlscan.io/screenshots/${it.sampleId}.png`, '']
      .map(csvCell).join(','));
  });
  const dir = path.join(args.make, 'crowd');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'tasks.csv'), '﻿' + lines.join('\r\n'), 'utf8');
  fs.writeFileSync(path.join(dir, 'key.json'), JSON.stringify(key, null, 1));
  const goldCount = items.filter((x) => x.gold).length;
  console.log(`依頼票: ${path.join(dir, 'tasks.csv')}（${items.length}件、うち確認用 ${goldCount}件）`);
  console.log(`照合用: ${path.join(dir, 'key.json')}（作業者には渡さないこと）`);
  process.exit(0);
}

// ---- 2. 回答の集計 ------------------------------------------------------------
if (args.imp) {
  const dir = path.join(args.imp, 'crowd');
  const key = JSON.parse(fs.readFileSync(path.join(dir, 'key.json'), 'utf8'));
  const votes = []; // { worker, task, answer }
  args.answers.forEach((file) => {
    const rows = parseCsv(fs.readFileSync(file, 'utf8'));
    const header = rows.shift().map((h) => h.trim().toLowerCase());
    const col = (name) => header.indexOf(name);
    const ti = col('task_id'); const ai = col('answer'); const wi = col('worker_id');
    if (ti < 0 || ai < 0) throw new Error(`${file}: 列 task_id と answer が必要です`);
    rows.forEach((r) => {
      const task = (r[ti] || '').trim();
      if (!key[task]) return;
      votes.push({ worker: wi >= 0 ? (r[wi] || '').trim() : path.basename(file), task, answer: normalizeAnswer(r[ai]) });
    });
  });

  // 作業者ごとの確認用問題（ゴールド）の正答率
  const workers = {};
  votes.forEach((v) => {
    const w = workers[v.worker] || (workers[v.worker] = { answered: 0, gold: 0, correct: 0 });
    w.answered++;
    const g = key[v.task].gold;
    if (g && v.answer !== 'unsure') { w.gold++; if (v.answer === g) w.correct++; }
  });
  const trusted = new Set(Object.entries(workers)
    .filter(([, w]) => w.gold >= 3 && w.correct / w.gold >= args.minGoldAccuracy).map(([id]) => id));

  // 多数決（信頼できる作業者の回答のみ。判断できないは数えない）
  const byTask = {};
  votes.filter((v) => trusted.has(v.worker) && !key[v.task].gold && v.answer !== 'unsure')
    .forEach((v) => (byTask[v.task] = byTask[v.task] || []).push(v.answer));
  const labels = {};
  const stat = { black: 0, white: 0, other: 0, tie: 0, few: 0 };
  let agreePairs = 0; let pairs = 0;
  Object.entries(byTask).forEach(([task, answers]) => {
    for (let i = 0; i < answers.length; i++) for (let j = i + 1; j < answers.length; j++) { pairs++; if (answers[i] === answers[j]) agreePairs++; }
    if (answers.length < args.minVotes) { stat.few++; return; }
    const count = {};
    answers.forEach((a) => (count[a] = (count[a] || 0) + 1));
    const sorted = Object.entries(count).sort((a, b) => b[1] - a[1]);
    if (sorted[1] && sorted[1][1] === sorted[0][1]) { stat.tie++; return; }
    const winner = sorted[0][0];
    stat[winner]++;
    if (winner === 'black' || winner === 'white') labels[key[task].domain] = winner;
  });

  fs.writeFileSync(path.join(args.imp, 'labels-human.json'), JSON.stringify(labels, null, 1));
  const report = [
    `回答: ${votes.length}件（作業者 ${Object.keys(workers).length}人）`,
    `確認用問題の正答率が ${Math.round(args.minGoldAccuracy * 100)}% 以上（3問以上回答）の作業者: ${trusted.size}人`,
    ...Object.entries(workers).map(([id, w]) => `  ${trusted.has(id) ? '採用' : '除外'} ${id}: 回答 ${w.answered}件、確認用 ${w.correct}/${w.gold}`),
    `判定者間の一致率（同じ問題の回答の組）: ${pairs ? Math.round((agreePairs / pairs) * 100) : '-'}%`,
    `確定: 詐欺 ${stat.black} / 正規 ${stat.white} / 通販ではない ${stat.other}（評価から除外）`,
    `未確定: 同数 ${stat.tie} / 回答不足（${args.minVotes}人未満）${stat.few}`,
    `出力: ${path.join(args.imp, 'labels-human.json')}`,
  ].join('\n');
  fs.writeFileSync(path.join(dir, 'report.txt'), report + '\n', 'utf8');
  console.log(report);
  process.exit(0);
}

console.error('使い方: node tools/label-package.js --make <dir> --gold <dir> | --import <dir> --answers <csv>...');
process.exit(1);
