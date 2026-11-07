/**
 * 同梱ブラックリスト（data/blocklist.txt）を最新版に更新する。
 * 取得するのはドメイン一覧のテキストファイルだけで、リスト内のサイトにはアクセスしない。
 *
 * 使い方: node tools/update-blocklist.js
 *
 * 出典: HaGeZi DNS Blocklists - Fake（偽ショップ・詐欺サイト）
 *       https://github.com/hagezi/dns-blocklists  (GPL-3.0)
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

require(path.join(__dirname, '..', 'detector.js'));
const { parse } = require(path.join(__dirname, '..', 'blocklist-data.js'));

const SOURCE = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt';
const OUT = path.join(__dirname, '..', 'data', 'blocklist.txt');
const FEED_OUT = path.join(__dirname, '..', 'docs', 'feed', 'blocklist.json');

async function updateBlocklist() {
  const res = await fetch(SOURCE, { signal: AbortSignal.timeout(60000) });
  if (!res.ok) throw new Error(`ダウンロード失敗: HTTP ${res.status}`);
  const text = await res.text();
  if (Buffer.byteLength(text) > 5 * 1024 * 1024) throw new Error('ダウンロードサイズが大きすぎます');

  const domains = [...new Set(text.split(/\r?\n/)
    .map((l) => l.trim().toLowerCase())
    .filter((l) => l && !l.startsWith('#') && /^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(l)))];

  // 安全策：ホワイトリストのドメインがリストに混入していたら除外する
  const removed = domains.filter((d) => globalThis.SiteRiskDetector.analyze(d).whitelisted);
  const kept = domains.filter((d) => !removed.includes(d)).sort();

  if (kept.length < 1000) throw new Error(`件数が少なすぎます（${kept.length}件）。取得元を確認してください。`);

  const generatedAt = new Date().toISOString();
  const canonical = kept.join('\n') + '\n';
  const feed = parse({
    schemaVersion: 1,
    source: 'hagezi-fake',
    generatedAt,
    count: kept.length,
    sha256: crypto.createHash('sha256').update(canonical).digest('hex'),
    domains: kept,
  });
  const header = [
    '# 詐欺サイトチェッカー 同梱ブラックリスト',
    `# 出典: HaGeZi DNS Blocklists - Fake (${SOURCE})`,
    '# ライセンス: GPL-3.0 (https://github.com/hagezi/dns-blocklists/blob/main/LICENSE)',
    `# 更新日: ${generatedAt.slice(0, 10)}  件数: ${kept.length}`,
  ];
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.mkdirSync(path.dirname(FEED_OUT), { recursive: true });
  const outputs = [[OUT, header.concat(kept).join('\n') + '\n'], [FEED_OUT, JSON.stringify(feed) + '\n']];
  for (const [file, contents] of outputs) fs.writeFileSync(file + '.tmp', contents, 'utf8');
  for (const [file] of outputs) fs.renameSync(file + '.tmp', file);

  console.log(`書き出し: ${OUT}（${kept.length}件）`);
  console.log(`配信用フィード: ${FEED_OUT}（生成日時 ${generatedAt}、SHA-256 ${feed.sha256}）`);
  if (removed.length) console.log(`ホワイトリストと重複のため除外: ${removed.join(', ')}`);
}

if (require.main === module) updateBlocklist().catch((e) => {
  console.error(e.message);
  process.exitCode = 1;
});

module.exports = { updateBlocklist };
