/**
 * 悪質ECサイト・詐欺サイト判定ロジック（共通モジュール）
 * background.js（importScripts）と tests/evaluate.js（require）から読み込む。
 * 外部ライブラリ不使用。
 */
(function (global) {
  'use strict';

  // ---- 設定値 -------------------------------------------------------------

  const THRESHOLD_DANGER = 80;
  const THRESHOLD_CAUTION = 40;

  // 偽通販チェックの判定除外リスト（ドメイン自身とサブドメインが対象。安全性の保証ではない）
  const WHITELIST_DOMAINS = [
    'amazon.co.jp', 'amazon.com',
    'rakuten.co.jp', 'rakuten.com',
    'yahoo.co.jp', 'yahoo.com', 'yimg.jp',
    'mercari.com', 'paypay.ne.jp',
  ];
  // 判定除外のサフィックス（公的機関・教育機関。安全性の保証ではない）
  const WHITELIST_SUFFIXES = ['.go.jp', '.ac.jp', '.lg.jp'];

  // 詐欺サイトで多用されるTLD（高リスク / 中リスク）
  const TLD_HIGH = {
    rest: 40, ltd: 40, xyz: 35, top: 35, icu: 40, cfd: 40, sbs: 40,
    bond: 40, buzz: 35, cyou: 40, monster: 35, quest: 35, cam: 35,
  };
  const TLD_MID = {
    site: 30, shop: 25, club: 25, work: 30, online: 30, store: 25,
    fun: 25, vip: 30, live: 20, life: 20, click: 25, link: 20,
    space: 25, website: 25, today: 20, asia: 20, tokyo: 15, cn: 20,
    // urlscan.io で収集した日本向け偽通販（2026年8〜10月）で多用されていた新gTLD
    luxe: 25, help: 25, yachts: 25, homes: 25, makeup: 25, yoga: 25, cards: 25, sale: 25,
    casa: 25, fashion: 25, beer: 25, best: 25, world: 20, hair: 25, skin: 25, autos: 25,
    motorcycles: 25, pics: 25, fit: 20, guru: 20, biz: 15,
  };

  // 民間の擬似サブドメインサービス（CentralNic等）。国のドメインに見せかけられる
  // 例: shop.jp.net, ksbxk.domshtor.sa.com, xsca.hansins.ru.com（消費者庁の公表事例）
  const PSEUDO_SLDS = [
    'jp.net', 'jpn.com', 'sa.com', 'ru.com', 'us.com', 'cn.com', 'de.com', 'eu.com',
    'uk.com', 'uk.net', 'gb.net', 'za.com', 'br.com', 'kr.com', 'mex.com', 'se.net',
    'hu.net', 'in.net', 'us.org', 'ae.org',
  ];

  // 2階層のパブリックサフィックス（登録ドメイン推定用の簡易リスト）
  const SECOND_LEVEL_SUFFIXES = new Set([
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'gr.jp', 'ed.jp', 'lg.jp', 'ad.jp',
    'co.uk', 'org.uk', 'com.cn', 'net.cn', 'com.hk', 'com.tw', 'co.kr',
    'com.au', 'com.sg', 'com.br', 'co.in',
    ...PSEUDO_SLDS,
  ]);

  // ドメイン年齢による加点・減点（RDAP の登録日から算出）
  const DOMAIN_AGE_RULES = [
    { maxDays: 30, points: 40, label: '登録から30日未満の新しいドメイン' },
    { maxDays: 90, points: 30, label: '登録から90日未満の新しいドメイン' },
    { maxDays: 180, points: 20, label: '登録から半年未満のドメイン' },
    { maxDays: 365, points: 10, label: '登録から1年未満のドメイン' },
  ];
  const DOMAIN_AGE_OLD = [
    { minDays: 365 * 5, points: -20, label: '5年以上運用されているドメイン' },
    { minDays: 365 * 2, points: -10, label: '2年以上運用されているドメイン' },
  ];

  // ランダム判定から除外する一般的なサブドメイン
  const COMMON_SUBDOMAINS = new Set([
    'www', 'www2', 'www3', 'm', 'sp', 'mobile', 'shop', 'store', 'mall', 'api',
    'cdn', 'img', 'static', 'assets', 'mail', 'blog', 'news', 'app', 'help',
    'support', 'secure', 'login', 'my', 'jp', 'en', 'ja', 'search', 'item', 'order',
  ]);

  // ブランド名を含む非公式ドメイン（なりすまし）
  const BRAND_KEYWORDS = ['amazon', 'rakuten', 'yahoo', 'mercari', 'paypay', 'uniqlo', 'zozo'];

  // 日本の属性型ドメイン（法人登記等が必要で、詐欺サイトが取得しにくい）
  const JP_ORG_SUFFIXES = ['.co.jp', '.ne.jp', '.or.jp', '.ad.jp'];

  // 誰でも無料でサイトを公開できるホスティング（フィッシングページの設置に多用される）
  const FREE_HOSTING = [
    'pages.dev', 'workers.dev', 'r2.dev', 'web.app', 'firebaseapp.com', 'netlify.app',
    'vercel.app', 'replit.app', 'repl.co', 'glitch.me', 'weebly.com', 'weeblysite.com',
    'wixsite.com', 'github.io', 'gitbook.io', 'ngrok-free.app', 'ngrok.io', 'amazonaws.com',
  ];

  // 偽通販キット特有のクエリパラメータ
  const KIT_SIGNATURES = [
    { re: /(?:^|[?&])main_page=product_info(?:&|$)/i, label: 'main_page=product_info（Zen Cart系偽通販テンプレート）', points: 40 },
    { re: /(?:^|[?&])main_page=(?:index|products_new|specials|shopping_cart)(?:&|$)/i, label: 'main_page=（Zen Cart系テンプレート）', points: 25 },
    { re: /(?:^|[?&])zenid=/i, label: 'zenid=（Zen Cartセッションパラメータ）', points: 30 },
    { re: /(?:^|[?&])products_id=/i, label: 'products_id=（osCommerce/Zen Cart系商品ID）', points: 25 },
    { re: /(?:^|[?&])cPath=/i, label: 'cPath=（osCommerce/Zen Cart系カテゴリパス）', points: 15 },
    { re: /(?:^|[?&])osCsid=/i, label: 'osCsid=（osCommerceセッションパラメータ）', points: 25 },
    { re: /(?:^|[?&])route=product\/product(?:&|$)/i, label: 'route=product/product（OpenCart系テンプレート）', points: 15 },
  ];

  // 大量生成サイト特有のパス
  const PATH_PATTERNS = [
    { re: /\/item-[a-z0-9]{5,}\.html?$/i, label: '/item-xxxxxx.html 形式' },
    { re: /-p-\d+\.html?$/i, label: '-p-数字.html 形式（Zen Cart SEO URL）' },
    { re: /\/(?:products?|goods|detail)[-_][a-z0-9]{6,}\.html?$/i, label: '/product-xxxxxx.html 形式' },
    { re: /\/[a-z]{1,4}\d{6,}\.html?$/i, label: '英字+長い数字の連番 .html' },
  ];

  // ---- ユーティリティ -------------------------------------------------------

  function normalizeInput(input) {
    let s = String(input || '').trim();
    if (!s) return null;
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s);
    if (!hasScheme) s = 'https://' + s;
    try {
      return { url: new URL(s), schemeGiven: hasScheme };
    } catch (_) {
      return null;
    }
  }

  function getRegistrableDomain(labels) {
    if (labels.length <= 2) return labels.join('.');
    const lastTwo = labels.slice(-2).join('.');
    return SECOND_LEVEL_SUFFIXES.has(lastTwo)
      ? labels.slice(-3).join('.')
      : lastTwo;
  }

  function isIpAddress(host) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.startsWith('[');
  }

  /** LAN内・ローカルホスト（ルーター管理画面等）は判定対象から外す */
  function isPrivateHost(host) {
    return host === 'localhost' || host === '[::1]' ||
      /^(?:10|127)\./.test(host) ||
      /^192\.168\./.test(host) ||
      /^172\.(?:1[6-9]|2\d|3[01])\./.test(host);
  }

  /** ランダム生成っぽい文字列かどうか */
  function looksRandom(label) {
    if (!label || COMMON_SUBDOMAINS.has(label)) return false;
    if (label.length < 4 || label.startsWith('xn--')) return false;

    const letters = label.replace(/[^a-z]/g, '');
    const digits = label.replace(/[^0-9]/g, '');
    const vowels = letters.replace(/[^aeiou]/g, '');

    // 数字だけの長い文字列（例: 0112532）
    if (/^\d{5,}$/.test(label)) return true;
    // 英字と数字が入り混じる（例: a8f3k2, x7k9q）
    if (letters.length >= 2 && digits.length >= 2 && label.length >= 5) {
      const switches = (label.match(/[a-z][0-9]|[0-9][a-z]/g) || []).length;
      if (switches >= 2) return true;
    }
    // 母音がほぼ無い（例: tkbsr, qwrtzx）
    if (letters.length >= 4 && vowels.length / letters.length < 0.15) return true;
    // 子音が5文字以上連続（例: xkcdmw）
    if (/[bcdfghjklmnpqrstvwxz]{5,}/.test(letters)) return true;
    return false;
  }

  function isWhitelisted(host) {
    if (WHITELIST_SUFFIXES.some((sfx) => host.endsWith(sfx))) return true;
    return WHITELIST_DOMAINS.some((d) => host === d || host.endsWith('.' + d));
  }

  function findFreeHosting(host) {
    return FREE_HOSTING.find((d) => host === d || host.endsWith('.' + d)) ||
      (/\.blogspot\.[a-z.]+$/.test(host) ? 'blogspot' : null);
  }

  /** ブラックリスト照合（ホスト自身または親ドメインが登録されていれば該当） */
  function findInBlocklist(host, blocklist) {
    if (!blocklist) return null;
    const labels = host.split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const candidate = labels.slice(i).join('.');
      if (blocklist.has(candidate)) return candidate;
    }
    return null;
  }

  function daysSince(isoDate, now) {
    const t = Date.parse(isoDate);
    return Number.isNaN(t) ? null : Math.floor((now - t) / 86400000);
  }

  function levelOf(score) {
    if (score >= THRESHOLD_DANGER) return 'danger';
    if (score >= THRESHOLD_CAUTION) return 'caution';
    return 'safe';
  }

  // ---- メイン判定 -----------------------------------------------------------

  /**
   * URLまたはドメイン文字列を解析してリスク判定結果を返す。
   * @param {string} input URL またはドメイン
   * @param {{
   *   blocklist?: Set<string>,                       // 既知の詐欺ドメイン
   *   domainInfo?: {status: string, registered?: string}, // RDAP の照会結果
   *   pageSignals?: {category: string, detail: string, points: number}[], // content.js の検出結果
   *   now?: number,
   * }} [ctx]
   * @returns {{
   *   input: string, url: string, hostname: string, domain: string, tld: string,
   *   score: number, level: 'safe'|'caution'|'danger'|'unsupported'|'invalid',
   *   whitelisted: boolean, blocklisted: string|null, rdapEligible: boolean,
   *   domainAgeDays: number|null, registered: string|null,
   *   reasons: {category: string, detail: string, points: number}[]
   * }}
   */
  function analyze(input, ctx) {
    ctx = ctx || {};
    const base = {
      input: String(input || ''), url: '', hostname: '', domain: '', tld: '',
      score: 0, level: 'invalid', whitelisted: false, blocklisted: null, knownThreats: [],
      rdapEligible: false, domainAgeDays: null, registered: null, reasons: [],
    };

    const parsed = normalizeInput(input);
    if (!parsed) return base;
    const { url, schemeGiven } = parsed;

    base.url = url.href;
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      base.level = 'unsupported';
      return base;
    }

    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    if (!host) return base;
    const labels = host.split('.');
    const tld = labels[labels.length - 1];
    const domain = isIpAddress(host) ? host : getRegistrableDomain(labels);
    Object.assign(base, { hostname: host, domain, tld });

    // 確認済みの公表履歴は、偽通販の判定除外より優先する（正規サイトの改ざんにも対応）。
    const knownThreats = global.SiteRiskThreatData?.lookup(ctx.threatHistory, url.href) || [];
    base.knownThreats = knownThreats;
    // ホワイトリスト
    if (isWhitelisted(host) && !knownThreats.length) {
      base.whitelisted = true;
      base.level = 'safe';
      base.reasons.push({ category: '判定除外', detail: `${domain} は偽通販チェックの判定除外リストに含まれます（安全性の保証ではありません）`, points: 0 });
      return base;
    }

    const reasons = [];
    const add = (category, detail, points) => reasons.push({ category, detail, points });

    if (knownThreats.length) {
      const latest = knownThreats.reduce((a, b) => a.date > b.date ? a : b);
      add('公表履歴', `${latest.source.name}: ${latest.description || 'フィッシング'}（${latest.date ? latest.date + '確認・公表' : '確認日不明'}）。` +
        (latest.status === 'closed_by_source' ? '公表元ではサイト閉鎖と記載されています。' : '') +
        '現在の稼働状況は本ツールでは確認していません', 40);
    }

    // 0. 既知の詐欺サイトリスト
    const blocked = findInBlocklist(host, ctx.blocklist);
    if (blocked) {
      base.blocklisted = blocked;
      add('ブラックリスト', `${blocked} は既知の詐欺・偽ショップリストに登録されています`, 100);
    }

    // 1. 危険・格安TLD
    if (TLD_HIGH[tld] != null) {
      add('危険TLD', `.${tld}（詐欺サイトで特に多用される格安TLD）`, TLD_HIGH[tld]);
    } else if (TLD_MID[tld] != null) {
      add('格安TLD', `.${tld}（詐欺サイトで多用される格安TLD）`, TLD_MID[tld]);
    }

    // 2. 擬似ドメイン・模倣構造
    const pseudo = PSEUDO_SLDS.find((s) => host.endsWith('.' + s));
    if (pseudo === 'jp.net' || pseudo === 'jpn.com') {
      add('擬似ドメイン', `.${pseudo}（公式の .jp に見せかけた民間サブドメイン）`, 45);
    } else if (pseudo) {
      add('擬似ドメイン', `.${pseudo}（国別ドメインに見せかけた民間サブドメイン）`, 35);
    }
    if (pseudo) {
      // 例: xsca.hansins.ru.com のように、擬似ドメイン配下にさらにサブドメインを重ねる構造（大量生成サイトの特徴）
      const extra = labels.slice(0, labels.length - domain.split('.').length).filter((l) => l !== 'www');
      if (extra.length) add('擬似ドメイン', `擬似ドメインの下にさらにサブドメイン（${extra.join('.')}.）を重ねた構造`, 10);
    } else if (/\.(?:co\.|ne\.|or\.)?jp\./.test(host)) {
      const m = host.match(/(?:co\.|ne\.|or\.)?jp\.[^.]+/);
      add('擬似ドメイン', `ドメイン途中に「.${m ? m[0] : 'jp.'}」を含む非公式ドメイン`, 45);
    }

    const hasRiskyTld = TLD_HIGH[tld] != null || TLD_MID[tld] != null;
    const hosting = findFreeHosting(host);
    if (hosting) {
      add('無料ホスティング', `誰でも無料で公開できるサービス上のページ（${hosting}）`, 20);
    }

    // ホスティング名自体（amazonaws.com 等）に含まれるブランド名は除いて判定
    const hostForBrand = hosting ? host.slice(0, -hosting.length) : host;
    const brand = BRAND_KEYWORDS.find((b) => hostForBrand.includes(b));
    // 属性型JPドメイン（rakuten-card.co.jp 等）や、各国の公式ドメイン（amazon.de 等）は除外
    const isJpOrg = JP_ORG_SUFFIXES.some((sfx) => domain.endsWith(sfx));
    const isBrandCcTld = brand && domain.split('.')[0] === brand && !hasRiskyTld;
    if (brand && !isJpOrg && !isBrandCcTld) {
      add('なりすまし', `大手ブランド名「${brand}」を含む非公式ドメイン`, 20);
    }

    if (isIpAddress(host) && !isPrivateHost(host)) {
      add('ドメイン構造', 'ドメイン名ではなくIPアドレスで直接アクセス', 30);
    }
    if (labels.some((l) => l.startsWith('xn--'))) {
      add('ドメイン構造', '国際化ドメイン（Punycode: xn--）による偽装の可能性', 15);
    }
    const hyphens = (domain.match(/-/g) || []).length;
    if (hyphens >= 3) {
      add('ドメイン構造', `ドメイン名にハイフンが多い（${hyphens}個）`, 10);
    }

    // 3. 無作為サブドメイン・パス
    if (!isIpAddress(host)) {
      const domainLabelCount = domain.split('.').length;
      const subLabels = labels.slice(0, labels.length - domainLabelCount);
      const randomSubs = subLabels.filter(looksRandom);
      if (randomSubs.length) {
        add('ランダムサブドメイン', `無作為な英数字のサブドメイン: ${randomSubs.join(', ')}`, 25);
      }
      const mainLabel = domain.split('.')[0];
      if (looksRandom(mainLabel)) {
        add('ランダムドメイン', `無作為な英数字のドメイン名: ${mainLabel}`, 15);
      }
    }

    const path = url.pathname;
    const pathHit = PATH_PATTERNS.find((p) => p.re.test(path));
    if (pathHit) {
      add('大量生成パス', `${pathHit.label}: ${path}`, 15);
    }

    // 4. EC詐欺キット・シグネチャ
    const search = url.search.replace(/^\?/, '');
    const kitHits = KIT_SIGNATURES.filter((k) => k.re.test(search));
    kitHits.forEach((k) => add('詐欺キット', k.label, k.points));

    // 5. 複合要因
    if (hasRiskyTld && kitHits.length) {
      add('複合要因', '格安TLD + 偽通販テンプレートの組み合わせ', 15);
    }
    if (schemeGiven && url.protocol === 'http:') {
      add('通信', '暗号化されていない http 接続', 10);
    }

    // 6. ドメイン年齢（RDAP）。無料ホスティング・擬似ドメインは親ドメインの年齢しか分からないため対象外
    base.rdapEligible = !isIpAddress(host) && labels.length >= 2 && !hosting && !pseudo &&
      !SECOND_LEVEL_SUFFIXES.has(domain);
    const info = ctx.domainInfo;
    if (base.rdapEligible && info && info.status === 'ok' && info.registered) {
      const age = daysSince(info.registered, ctx.now || Date.now());
      if (age != null && age >= 0) {
        base.domainAgeDays = age;
        base.registered = info.registered;
        const young = DOMAIN_AGE_RULES.find((r) => age < r.maxDays);
        const old = DOMAIN_AGE_OLD.find((r) => age >= r.minDays);
        if (young) add('ドメイン年齢', `${young.label}（${age}日前に登録）`, young.points);
        else if (old && !blocked && !knownThreats.length) add('ドメイン年齢', `${old.label}（減点）`, old.points);
      }
    }

    // 7. ページ内容（content.js）
    (ctx.pageSignals || []).forEach((s) => add(s.category, s.detail, s.points));

    const total = reasons.reduce((sum, r) => sum + r.points, 0);
    base.score = Math.max(knownThreats.length ? THRESHOLD_CAUTION : 0, Math.min(100, total));
    base.level = levelOf(base.score);
    base.reasons = reasons;
    return base;
  }

  global.SiteRiskDetector = {
    analyze,
    THRESHOLD_DANGER,
    THRESHOLD_CAUTION,
  };
})(typeof self !== 'undefined' ? self : globalThis);
