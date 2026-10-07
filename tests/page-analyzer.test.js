/**
 * page-analyzer.js の単体テスト（外部ライブラリ不使用・オフライン）。
 * 使い方: node tests/page-analyzer.test.js
 */
'use strict';

const assert = require('assert');
const path = require('path');
require(path.join(__dirname, '..', 'page-analyzer.js'));
const { analyzePage } = globalThis.SiteRiskPageAnalyzer;

const FILLER = 'こちらのページでは人気の商品をご紹介しています。ぜひお買い求めください。'.repeat(3);

const cases = [
  {
    name: '典型的な偽通販サイト（個人名義口座・極端な割引・簡体字・中国系メール・特商法なし）',
    page: {
      text: `${FILLER}
        期間限定 最大90%OFF！ カートに入れる
        お支払い方法：銀行振込のみ
        振込先：○○銀行 普通 1234567 口座名義：ヤマダ タロウ
        販売業者：株式会社グローバルトレード
        お问题があれば联系してください：shop-help@qq.com
        这款商品は优惠价格で发货します`,
      links: [{ text: 'ホーム', href: '/' }],
    },
    expect: ['極端な割引率', '個人名義', '一致しない', '中国系フリーメール', '簡体字', '特定商取引法'],
    minPoints: 100,
  },
  {
    name: '正規の通販サイト（法人口座・特商法あり・通常の割引）',
    page: {
      text: `${FILLER}
        秋の感謝祭 全品20%OFF カートに入れる
        振込先：三井住友銀行 本店営業部 口座名義：カ）サンプルショップ
        販売業者：株式会社サンプルショップ
        お問い合わせ：support@sample-shop.co.jp`,
      links: [{ text: '特定商取引法に基づく表記', href: '/law' }],
    },
    expect: [],
    maxPoints: 0,
  },
  {
    name: '通販ではない一般ページ（ニュース記事）',
    page: {
      text: `${FILLER} 本日の天気は晴れ。気象庁によると、明日は全国的に雨の予報です。連絡先 news@gmail.com`,
      links: [],
    },
    expect: [],
    maxPoints: 0,
  },
  {
    name: '中国語のページ（日本語ではないので簡体字チェック対象外）',
    page: {
      text: '欢迎光临我们的商店，这里有优惠价格，订单发货时间为三天。',
      links: [],
    },
    expect: [],
    maxPoints: 0,
  },
  {
    name: '「9割引」表記の検出',
    page: { text: `${FILLER} 在庫一掃セール ９割引 カートに入れる 特定商取引法に基づく表記`, links: [] },
    expect: ['極端な割引率'],
  },
];

let failed = 0;
for (const c of cases) {
  const { signals } = analyzePage(c.page);
  const total = signals.reduce((s, x) => s + x.points, 0);
  try {
    c.expect.forEach((kw) => assert.ok(signals.some((s) => s.detail.includes(kw)), `「${kw}」が検出されていない`));
    if (c.expect.length === 0) assert.strictEqual(signals.length, 0, `誤検出: ${signals.map((s) => s.detail).join(' / ')}`);
    if (c.minPoints != null) assert.ok(total >= c.minPoints, `合計 ${total} < ${c.minPoints}`);
    if (c.maxPoints != null) assert.ok(total <= c.maxPoints, `合計 ${total} > ${c.maxPoints}`);
    console.log(`✓ ${c.name}（+${total}）`);
  } catch (e) {
    failed++;
    console.log(`✗ ${c.name}\n    ${e.message}\n    検出: ${signals.map((s) => `${s.detail}+${s.points}`).join(' / ') || 'なし'}`);
  }
}
console.log(failed ? `\n${failed} 件失敗` : '\nすべて成功');
process.exit(failed ? 1 : 0);
