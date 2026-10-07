/**
 * フィッシングの追加チェック（phishing-analyzer.js）と Public Suffix List 処理（psl.js）の単体テスト。
 * ページから抽出した結果（phishing-dom.js の出力と同じ形）を直接与えて採点を確認する。外部通信なし。
 * 使い方: node tests/phishing-analyzer.test.js
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..');
require(path.join(ROOT, 'psl.js'));
require(path.join(ROOT, 'phishing-analyzer.js'));
const psl = globalThis.SiteRiskPsl.parse(fs.readFileSync(path.join(ROOT, 'data', 'public_suffix_list.dat'), 'utf8'));
const { brands } = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'brands.json'), 'utf8'));
const { analyze, textSignals } = globalThis.SiteRiskPhishing;

const page = (over) => ({
  url: 'https://example.net/login', title: '', headings: [], forms: [],
  threat: { threat: false, deadline: false }, linkPairs: [], legal: { total: 0, empty: 0 }, ...over,
});
const form = (over) => ({ fieldKinds: ['email', 'password'], action: '', formActions: [], contextText: '', logoAlts: [], ...over });

let failed = 0;
function test(name, fn) {
  try { fn(); console.log(`✓ ${name}`); } catch (e) { failed++; console.log(`✗ ${name}\n    ${e.message}`); }
}
const run = (desc) => analyze(desc, { psl, brands });
const rules = (r) => r.reasons.map((x) => x.rule).sort().join(',');

// ---- Public Suffix List ----
test('PSL: 登録ドメインの判定', () => {
  assert.strictEqual(psl.getRegistrableDomain('www.amazon.co.jp'), 'amazon.co.jp');
  assert.strictEqual(psl.getRegistrableDomain('amazon.co.jp.evil.example'), 'evil.example');
  assert.strictEqual(psl.getRegistrableDomain('user.github.io'), 'user.github.io');
  assert.strictEqual(psl.getRegistrableDomain('bucket.s3.amazonaws.com'), 'bucket.s3.amazonaws.com');
  assert.strictEqual(psl.getRegistrableDomain('x.city.kawasaki.jp'), 'city.kawasaki.jp');
  assert.strictEqual(psl.getRegistrableDomain('github.io'), null);
});

// ---- 誤検知しないこと ----
test('公式ログイン（www.amazon.co.jp のサインイン）→ 警告なし', () => {
  const r = run(page({ url: 'https://www.amazon.co.jp/ap/signin', title: 'Amazonサインイン',
    forms: [form({ action: 'https://www.amazon.co.jp/ax/claim', contextText: 'Amazon サインイン パスワード', logoAlts: ['Amazon'] })] }));
  assert.strictEqual(r.level, 'none', rules(r));
  assert.strictEqual(r.reasons.length, 0, rules(r));
});

test('公式のサブドメイン（appleid.apple.com）→ 警告なし', () => {
  const r = run(page({ url: 'https://appleid.apple.com/sign-in', title: 'Apple Account にサインイン',
    forms: [form({ contextText: 'Apple Account サインイン' })] }));
  assert.strictEqual(r.reasons.length, 0, rules(r));
});

test('正規の外部認証（自社サイトの「Amazonでログイン」ボタン。パスワード欄なし）→ 警告なし', () => {
  const r = run(page({ url: 'https://shop.example.jp/login', title: 'ログイン | Example Shop',
    forms: [form({ fieldKinds: ['email'], contextText: 'メールアドレスでログイン Amazonアカウントでログイン' })] }));
  assert.strictEqual(r.reasons.length, 0, rules(r));
});

test('自社サイトのログイン（ブランド名なし）→ 警告なし', () => {
  const r = run(page({ url: 'https://member.example.jp/login', title: '会員ログイン',
    forms: [form({ action: 'https://member.example.jp/auth', contextText: '会員ID パスワード ログイン' })] }));
  assert.strictEqual(r.reasons.length, 0, rules(r));
});

test('通常の決済フォーム（カード番号・有効期限・CVV）→ 警告なし', () => {
  const r = run(page({ url: 'https://shop.example.jp/checkout', title: 'お支払い',
    forms: [form({ fieldKinds: ['card', 'expiry', 'cvv'], action: 'https://shop.example.jp/pay', contextText: 'カード番号 有効期限 セキュリティコード' })] }));
  assert.strictEqual(r.level, 'none', rules(r));
});

test('決済代行への送信（別ドメイン）だけ → 25点・1種類なので警告なし', () => {
  const r = run(page({ url: 'https://shop.example.jp/checkout', title: 'お支払い',
    forms: [form({ fieldKinds: ['card', 'expiry', 'cvv'], action: 'https://gateway.payment-example.com/charge' })] }));
  assert.strictEqual(r.level, 'none');
  assert.strictEqual(rules(r), 'crossDomainSubmit');
});

test('ニュース記事（見出しにブランド名・ページ内に自社会員ログイン）→ 偽装と判定しない', () => {
  const r = run(page({ url: 'https://news.example.jp/article/1', title: 'Amazon、新サービスを発表 | ニュース',
    headings: ['Amazon、新サービスを発表'], forms: [form({ contextText: 'ニュース会員ログイン パスワード' })] }));
  assert.ok(!r.reasons.some((x) => x.rule === 'brandImpersonation'), rules(r));
  assert.strictEqual(r.level, 'none');
});

test('ブランド名・ログイン欄・OTP 欄・緊急性の文章があるだけ（別ドメイン送信などなし）→ 警告なし', () => {
  const r = run(page({ url: 'https://portal.example.jp/verify', title: '本人確認',
    forms: [form({ fieldKinds: ['otp'], contextText: '認証コードを入力' })], threat: { threat: true, deadline: false } }));
  assert.strictEqual(r.level, 'none', rules(r));
});

test('HTTPS であることだけでは減点しない（点数は 0 未満にならない）', () => {
  const r = run(page({ url: 'https://member.example.jp/login', forms: [form({})] }));
  assert.strictEqual(r.score, 0);
});

test('ローカル（192.168.x.x のルーター管理画面）への HTTP 送信 → 警告なし', () => {
  const r = run(page({ url: 'http://192.168.0.1/login', forms: [form({ action: 'http://192.168.0.1/login' })] }));
  assert.strictEqual(r.level, 'none', rules(r));
});

test('短いブランド名（live）との偶然の類似は似せたドメインと判定しない', () => {
  const r = run(page({ url: 'https://www.lime.jp/login', title: 'ログイン', forms: [form({})] }));
  assert.ok(!r.reasons.some((x) => x.rule === 'lookalikeDomain'), rules(r));
});

test('共有ホスティング（github.io）の親ドメインで判定しない', () => {
  const r = run(page({ url: 'https://someone.github.io/login', title: 'ログイン', forms: [form({})] }));
  assert.strictEqual(r.reasons.length, 0, rules(r));
});

// ---- 検出すること ----
test('部分一致で公式を装う（amazon.co.jp.evil.example）→ 偽装・似せたドメインを検出', () => {
  const r = run(page({ url: 'https://amazon.co.jp.evil.example/signin', title: 'Amazon サインイン',
    forms: [form({ contextText: 'Amazon サインイン' })] }));
  assert.ok(r.reasons.some((x) => x.rule === 'brandImpersonation'), rules(r));
  assert.ok(r.reasons.some((x) => x.rule === 'lookalikeDomain'), rules(r));
  assert.strictEqual(r.score, 40, '1 と 2 は同じドメインの根拠として最大 40 点');
  assert.strictEqual(r.level, 'none', '根拠が1種類だけなので警告しない');
});

test('非公式ドメインでの偽装 + 別ドメインへの送信 → 注意', () => {
  const r = run(page({ url: 'https://secure-check.example.net/login', title: '楽天 ログイン',
    forms: [form({ action: 'https://collect.other-domain.example/p', contextText: '楽天会員 ログイン' })] }));
  assert.strictEqual(r.level, 'caution', `${r.score} ${rules(r)}`);
  assert.strictEqual(r.score, 65);
});

test('似せたドメイン（amaz0n-account.com）+ 過剰な要求 + 脅しと期限 → 危険', () => {
  const r = run(page({ url: 'https://amaz0n-account.com/verify', title: '本人確認',
    forms: [form({ fieldKinds: ['email', 'password', 'card', 'cvv'], contextText: 'お支払い情報の確認' })],
    threat: { threat: true, deadline: true } }));
  assert.ok(r.reasons.some((x) => x.rule === 'lookalikeDomain'), rules(r));
  assert.strictEqual(r.level, 'danger', `${r.score} ${rules(r)}`);
});

test('HTTP の送信先へ機密情報 → 単独でも注意', () => {
  const r = run(page({ url: 'https://member.example.jp/login', forms: [form({ action: 'http://member.example.jp/auth' })] }));
  assert.strictEqual(r.level, 'caution', rules(r));
});

test('送信ボタンの formaction も送信先として確認する', () => {
  const r = run(page({ url: 'https://shop.example.jp/login', forms: [form({ action: 'https://shop.example.jp/a', formActions: ['https://evil.example/collect'] })] }));
  assert.ok(r.reasons.some((x) => x.rule === 'crossDomainSubmit'), rules(r));
});

test('表示URLとリンク先の不一致・空の主要リンク（機密フォームなしでは警告に至らない）', () => {
  const r = run(page({ linkPairs: [{ shownHost: 'www.amazon.co.jp', actualHost: 'evil.example' }], legal: { total: 4, empty: 4 } }));
  assert.strictEqual(rules(r), 'emptyLegalLinks,linkTextMismatch');
  assert.strictEqual(r.level, 'none');
});

test('textSignals: 脅し文句と期限を判定する（本文は返さない）', () => {
  const s = textSignals('お客様のアカウントは停止されました。24時間以内にご確認ください。');
  assert.deepStrictEqual(s, { threat: true, deadline: true });
});

console.log(failed ? `\n${failed} 件失敗` : '\nすべて成功');
process.exit(failed ? 1 : 0);
