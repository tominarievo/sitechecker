'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
require('../threat-data.js');
require('../detector.js');
const T = globalThis.SiteRiskThreatData;
const sources = [{ id: 'jpcert:fixture', name: 'JPCERT/CC', url: 'https://github.com/JPCERTCC/phishurl-list' },
  { id: 'ccj:fixture', name: 'CCJ', url: 'https://www.kokusen.go.jp/' }];
const index = T.parse({ schemaVersion: 1, generatedAt: '2026-10-10', sources, records: [
  ['url', 'https://www.amazon.co.jp/hacked/login?a=1#/login', '2026-05-01', 0, 'Amazon', 'not_checked'],
  ['url', 'https://shared.example/account', '', 0, '銀行', 'not_checked'],
  ['host', 'shop.example', '2026-06-17', 1, '商品未着', 'closed_by_source'],
] });

test('URL全体の一致だけを照合。別パス・別クエリ・別フラグメントに拡張しない', () => {
  assert.equal(T.lookup(index, 'https://www.amazon.co.jp/hacked/login?a=1#/login').length, 1);
  for (const url of ['https://www.amazon.co.jp/', 'https://www.amazon.co.jp/hacked/login?a=2#/login',
    'https://www.amazon.co.jp/hacked/login?a=1#/other', 'https://shared.example/legit']) assert.equal(T.lookup(index, url).length, 0);
});
test('公表ホストは同じホストのページだけ。親・子・兄弟を巻き込まない', () => {
  assert.equal(T.lookup(index, 'http://shop.example/products').length, 1);
  for (const host of ['example', 'other.example', 'sub.shop.example']) assert.equal(T.lookup(index, 'https://' + host).length, 0);
});
test('ホスト大小文字・デフォルトポートは正規化し、パス大小文字は区別する', () => {
  assert.equal(T.canonicalUrl('https://SHARED.EXAMPLE:443/account'), 'https://shared.example/account');
  assert.equal(T.lookup(index, 'https://shared.example/Account').length, 0);
  assert.equal(T.canonicalUrl('https://user:password@shared.example/account'), null);
});
test('公表履歴は判定除外より優先し、減点で注意を消さない', () => {
  const r = SiteRiskDetector.analyze('https://www.amazon.co.jp/hacked/login?a=1#/login', {
    threatHistory: index, pageSignals: [{ category: '安心要因', detail: 'test', points: -100 }],
  });
  assert.equal(r.whitelisted, false); assert.ok(r.score >= 40);
  assert.equal(r.knownThreats.length, 1); assert.match(r.reasons[0].detail, /現在の稼働状況/);
  assert.equal(SiteRiskDetector.analyze('https://www.amazon.co.jp/', { threatHistory: index }).whitelisted, true);
});
test('閉鎖・確認日不明の情報を残し、同じ履歴の重複で点数を増やさない', () => {
  const closed = SiteRiskDetector.analyze('https://shop.example/', { threatHistory: index });
  assert.match(closed.reasons[0].detail, /サイト閉鎖/);
  const unknown = SiteRiskDetector.analyze('https://shared.example/account', { threatHistory: index });
  assert.match(unknown.reasons[0].detail, /確認日不明/);
  const duplicate = T.parse({ schemaVersion: 1, sources, records: [
    ['url', 'https://shared.example/account', '', 0, '銀行', 'not_checked'],
    ['url', 'https://shared.example/account', '2026-05-01', 0, '銀行', 'not_checked'],
  ] });
  assert.equal(SiteRiskDetector.analyze('https://shared.example/account', { threatHistory: duplicate }).score, unknown.score);
});
test('破損したデータは正常な空リストに見せず、読み込みエラーにする', () => {
  assert.throws(() => T.parse({ schemaVersion: 2, sources, records: [] }));
  assert.throws(() => T.parse({ schemaVersion: 1, sources, records: [['url', 'javascript:alert(1)', '', 0, '', 'not_checked']] }));
});
