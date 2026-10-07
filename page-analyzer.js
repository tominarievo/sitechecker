/**
 * ページ本文の解析ロジック（純粋関数）。
 * content.js（コンテンツスクリプト）と tests/page-analyzer.test.js から読み込む。
 * 解析はブラウザ内で完結し、本文を外部へ送信することはない。
 */
(function (global) {
  'use strict';

  // 通販サイトらしさ（これがあるページだけ通販向けのチェックを行う）
  const SHOP_RE = /カート|買い物かご|ショッピングバッグ|購入手続き|今すぐ購入|ご注文手続き|add to cart|checkout/i;

  // フリマアプリの出品文（会社のショップに大量にあるのは、出品文をコピーした偽通販の特徴）
  const FLEA_RE = /新品タグ付き|新品未使用|\^\^|お申し付け|即購入|美品|送料込み/g;

  // タイトルが「人名＋ショップ名」（例: 酒井徳彦専門ショップ、浅野 政一株式会社、藤川 紘司E-Shop）
  const NAME_SHOP_TITLE_RE = /^[一-龥]{1,3}[ 　]?[一-龥ぁ-ん]{1,3}(?:株式会社|通販サイト|E-Shop|Shopping|販売ショップ|専門ショップ|専門店|市場店|販売店)/;

  // タイトルがホスト名の大文字表記（例: OVEN.HIKA-JP.CASA|【最安値に挑戦中!】…）
  const HOST_TITLE_RE = /^[A-Z0-9-]+\.[A-Z0-9.-]+[|｜]/;

  // 偽通販のタイトル・本文に多い煽り文句
  const HYPE_RE = /最安値(?:に)?挑戦|お見逃しなく|大放出|激安入荷|いち早く通販/g;

  // 特定商取引法に基づく表記へのリンク・本文
  const TOKUSHO_RE = /特定商取引|特商法|tokusho|tokutei|commercial[-_ ]?(?:transaction|law)|legal[-_ ]?notice/i;

  // 法人名義を示す表記（口座名義の「カ）」「(ｶ」等の略称を含む）
  const CORP_ACCOUNT_RE = /株式会社|有限会社|合同会社|一般社団|ｶ[)）]|[(（]ｶ|カ[)）]|[(（]カ|ﾕ[)）]|[(（]ﾕ|ユ[)）]|[(（]ユ|ﾄﾞ[)）]|ド[)）]|カブシキ|ｶﾌﾞｼｷ|ユウゲン|ﾕｳｹﾞﾝ|ゴウドウ|ｺﾞｳﾄﾞｳ/;

  // 口座名義の抽出（カナ氏名 / 漢字氏名）
  const ACCOUNT_NAME_RE = /(?:口座名義人?|名義人|受取人名?)\s*[:：】」]?\s*([ァ-ヶーｦ-ﾟ()（）\s　]{2,40}|[一-龥々]{1,4}[\s　]?[一-龥々]{1,4})/g;

  // 販売業者名の抽出
  const SELLER_RE = /(?:販売業者|販売事業者|事業者名|運営会社|会社名|運営者)\s*[:：】」]?\s*([^\n]{2,40})/;

  const FREEMAIL_CN = ['qq.com', '163.com', '126.com', 'sina.com', 'sina.cn', 'yeah.net', 'foxmail.com', 'aliyun.com', '139.com', 'sohu.com'];
  const FREEMAIL_GLOBAL = ['gmail.com', 'outlook.com', 'outlook.jp', 'hotmail.com', 'hotmail.co.jp', 'yahoo.com', 'icloud.com', 'aol.com', 'mail.ru', 'yandex.ru'];

  // 日本語では使わない簡体字（日本語の漢字と字形が異なるもの）
  const SIMPLIFIED_ONLY = '们这购买卖车优惠费运联说请钱选专现务发货时为订单销质码价开关门问题图书馆东报纸给软实际验';

  function countHiragana(text) {
    const m = text.match(/[ぁ-ゖ]/g);
    return m ? m.length : 0;
  }

  /**
   * @param {{text: string, title?: string, links?: {text: string, href: string}[]}} page
   * @returns {{isShop: boolean, signals: {category: string, detail: string, points: number}[]}}
   */
  function analyzePage(page) {
    const text = String(page.text || '').slice(0, 300000);
    const title = String(page.title || '').trim();
    const links = page.links || [];
    const signals = [];
    const add = (detail, points) => signals.push({ category: 'ページ内容', detail, points });

    const isShop = SHOP_RE.test(text) || links.some((l) => SHOP_RE.test(l.text || ''));
    const isJapanese = countHiragana(text) >= 30;

    // 1. 極端な割引率（70%OFF以上 / 7割引以上）
    let maxDiscount = 0;
    const discountRe = /(\d{2})\s*[%％]\s*(?:OFF|ＯＦＦ|オフ|引き|割引)/gi;
    let m;
    while ((m = discountRe.exec(text))) maxDiscount = Math.max(maxDiscount, Number(m[1]));
    const wariRe = /([7-9７-９])\s*割\s*(?:引き|引|OFF|オフ)/g;
    while ((m = wariRe.exec(text))) {
      const d = Number(String(m[1]).replace(/[７-９]/, (c) => String.fromCharCode(c.charCodeAt(0) - 0xfee0)));
      maxDiscount = Math.max(maxDiscount, d * 10);
    }
    // 大手の正規通販（zozo.jp, honto.jp 等）でも 90%OFF 以上の表示は珍しくないため、補助的な加点に留める
    if (maxDiscount >= 80 && maxDiscount < 100) add(`極端な割引率の表示（最大${maxDiscount}%OFF）`, 10);
    else if (maxDiscount >= 70 && maxDiscount < 100) add(`大幅な割引率の表示（最大${maxDiscount}%OFF）`, 5);

    // 2. 口座名義（個人名義・運営者との不一致）
    const accounts = [];
    ACCOUNT_NAME_RE.lastIndex = 0;
    while ((m = ACCOUNT_NAME_RE.exec(text))) {
      const name = m[1].trim();
      if (name.length >= 2) accounts.push(name);
    }
    const personal = accounts.find((name) => !CORP_ACCOUNT_RE.test(name));
    if (personal) {
      add(`振込先が個人名義の口座（${personal.slice(0, 20)}）`, 25);
      const seller = (text.match(SELLER_RE) || [])[1] || '';
      if (/株式会社|有限会社|合同会社|Co\.|Ltd|Inc/i.test(seller)) {
        add(`運営者（${seller.trim().slice(0, 20)}）と口座名義が一致しない`, 20);
      }
    }

    // 3. 連絡先がフリーメール
    const emails = (text.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || []).map((e) => e.toLowerCase());
    const domains = [...new Set(emails.map((e) => e.split('@')[1]))];
    const cn = domains.find((d) => FREEMAIL_CN.includes(d));
    const free = domains.find((d) => FREEMAIL_GLOBAL.includes(d));
    if (cn) add(`連絡先が中国系フリーメール（@${cn}）`, 25);
    else if (free && isShop) add(`通販サイトの連絡先がフリーメール（@${free}）`, 10);

    // 4. 日本語ページに簡体字が混在（機械翻訳・海外業者の特徴）
    if (isJapanese) {
      const found = [...new Set((title + '\n' + text).match(new RegExp(`[${SIMPLIFIED_ONLY}]`, 'g')) || [])];
      if (found.length >= 8) add(`日本語ページに簡体字が多数混在（${found.slice(0, 6).join('')}…）`, 30);
      else if (found.length >= 2) add(`日本語ページに簡体字が混在（${found.join('')}）`, 20);
    }

    // 5. 通販サイトなのに特定商取引法の表記が見当たらない
    if (isShop && isJapanese) {
      const hasTokusho = TOKUSHO_RE.test(text) ||
        links.some((l) => TOKUSHO_RE.test(l.text || '') || TOKUSHO_RE.test(l.href || ''));
      if (!hasTokusho) add('通販サイトだが「特定商取引法に基づく表記」が見当たらない', 15);
    }

    // 6. 偽通販のテンプレートに特徴的なタイトル・文言（urlscan.io で収集した実例から抽出）
    if (NAME_SHOP_TITLE_RE.test(title)) {
      add(`タイトルが「人名＋ショップ名」形式（${title.slice(0, 16)}…）`, 20);
    }
    if (HOST_TITLE_RE.test(title)) {
      add('タイトルがドメイン名の大文字表記で始まる（大量生成サイトの特徴）', 20);
    }
    if (isShop) {
      const flea = (text.match(FLEA_RE) || []).length;
      if (flea >= 3) add(`フリマの出品文のような文言が多い（${flea}件：新品タグ付き・美品・^^ 等）`, 25);
    }
    const hype = ((title + '\n' + text).match(HYPE_RE) || []).length;
    if (hype >= 2) add(`煽り文句が多い（最安値挑戦・お見逃しなく等 ${hype}件）`, 10);

    return { isShop, signals };
  }

  global.SiteRiskPageAnalyzer = { analyzePage };
})(typeof self !== 'undefined' ? self : globalThis);
