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

require(path.join(__dirname, '..', 'detector.js'));

const SOURCE = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt';
const OUT = path.join(__dirname, '..', 'data', 'blocklist.txt');

(async () => {
  const res = await fetch(SOURCE);
  if (!res.ok) throw new Error(`ダウンロード失敗: HTTP ${res.status}`);
  const text = await res.text();

  const domains = [...new Set(text.split(/\r?\n/)
    .map((l) => l.trim().toLowerCase())
    .filter((l) => l && !l.startsWith('#') && /^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(l)))];

  // 安全策：ホワイトリストのドメインがリストに混入していたら除外する
  const removed = domains.filter((d) => globalThis.SiteRiskDetector.analyze(d).whitelisted);
  const kept = domains.filter((d) => !removed.includes(d)).sort();

  if (kept.length < 1000) throw new Error(`件数が少なすぎます（${kept.length}件）。取得元を確認してください。`);

  const header = [
    '# 詐欺サイトチェッカー 同梱ブラックリスト',
    `# 出典: HaGeZi DNS Blocklists - Fake (${SOURCE})`,
    '# ライセンス: GPL-3.0 (https://github.com/hagezi/dns-blocklists/blob/main/LICENSE)',
    `# 更新日: ${new Date().toISOString().slice(0, 10)}  件数: ${kept.length}`,
  ];
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, header.concat(kept).join('\n') + '\n', 'utf8');

  console.log(`書き出し: ${OUT}（${kept.length}件）`);
  if (removed.length) console.log(`ホワイトリストと重複のため除外: ${removed.join(', ')}`);
})().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
