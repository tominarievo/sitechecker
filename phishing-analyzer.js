/**
 * フィッシングの追加チェック（利用者が有効にした場合のみ）の採点ロジック。純粋関数。
 *
 * 入力は content.js（phishing-dom.js）がページから抽出した「入力欄の種類・送信先・周辺の表示文言」で、
 * 利用者の入力値（パスワード・カード番号・OTP 等）は含まない。外部への通信は行わない。
 *
 * - textSignals(): ページ本文から脅し文句・期限の有無だけを判定（content.js 側で使用し、本文は送らない）
 * - analyze():     抽出結果を採点（background.js 側で使用。登録ドメインの判定に Public Suffix List を使う）
 *
 * 点数は暫定値（未検証）。実データでの検証後に調整する。
 */
(function (global) {
  'use strict';

  // ---- 点数（暫定値） ----------------------------------------------------------
  const POINTS = {
    brandImpersonation: 40, // 1. ブランド公式を装うが、公式・認可ドメイン以外で機密情報を要求
    lookalikeDomain: 30,    // 2. ブランドに似せたドメインで機密情報を要求（1 と同じ「ドメイン」の根拠として扱う）
    excessiveFields: 30,    // 3. 通常は別の場面で使う機密情報を同じフォームで過剰に要求
    crossDomainSubmit: 25,  // 4. 機密情報の送信先が、ページとは別の未確認ドメイン
    threatDeadline: 20,     // 5. 機密情報の入力要求に、停止・失効などの脅しと短い期限が伴う
    linkTextMismatch: 15,   // 6. URL として表示されたリンクと、実際のリンク先のドメインが異なる
    emptyLegalLinks: 5,     // 7. 利用規約・会社概要などの主要リンクの多くが空・「#」
    insecureSubmit: 40,     // 8. 機密情報を HTTP の送信先へ送る
  };
  const THRESHOLD_CAUTION = 40;
  const THRESHOLD_DANGER = 80;

  // 機密情報（認証・決済）とみなす入力欄の種類
  const SENSITIVE = ['password', 'card', 'cvv', 'pin', 'otp'];

  const LOGIN_WORDS = /ログイン|サインイン|sign\s?-?in|log\s?-?in|本人確認|認証|アカウント|account|verify|verification|お支払い情報|支払い方法|payment/i;
  const THREAT_RE = /停止|凍結|失効|無効化|利用制限|制限され|ロックされ|ロック中|削除され|閉鎖|suspend|locked|disabled|terminated|deactivat/i;
  const DEADLINE_RE = /\d+\s*時間以内|\d+\s*日以内|本日中|今日中|期限まで|期日まで|within\s+\d+\s*(?:hours?|days?)|\d+\s*hours?/i;
  const LEGAL_LINK_RE = /利用規約|会社概要|プライバシー|個人情報|特定商取引|お問い合わせ|terms|privacy|about\s?us|contact/i;

  // 似せた文字（ホモグリフ）の正規化
  const HOMOGLYPHS = [[/0/g, 'o'], [/1/g, 'l'], [/3/g, 'e'], [/5/g, 's'], [/rn/g, 'm'], [/vv/g, 'w']];

  // ---- ユーティリティ ------------------------------------------------------------

  function hostOf(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch (_) { return ''; }
  }
  function protocolOf(url) {
    try { return new URL(url).protocol; } catch (_) { return ''; }
  }
  function isPrivateHost(host) {
    return host === 'localhost' || host === '[::1]' || /^(?:10|127)\./.test(host) ||
      /^192\.168\./.test(host) || /^172\.(?:1[6-9]|2\d|3[01])\./.test(host);
  }
  function escapeRe(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
  /** ブランド名の出現（英字は単語境界つき。日本語はそのまま） */
  function mentions(text, keyword) {
    const t = String(text || '');
    return /^[\x00-\x7f]+$/.test(keyword)
      ? new RegExp(`(?:^|[^a-z0-9])${escapeRe(keyword)}(?:$|[^a-z0-9])`, 'i').test(t)
      : t.includes(keyword);
  }
  /** 制限付きの編集距離（隣接文字の入れ替えも1とみなす） */
  function editDistance(a, b) {
    const d = [];
    for (let i = 0; i <= a.length; i++) { d[i] = [i]; }
    for (let j = 0; j <= b.length; j++) { d[0][j] = j; }
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
    return d[a.length][b.length];
  }

  /** content.js 側で使う: 本文から脅し文句・期限の有無だけを判定する（本文そのものは送らない） */
  function textSignals(text) {
    const t = String(text || '').slice(0, 50000);
    return { threat: THREAT_RE.test(t), deadline: DEADLINE_RE.test(t) };
  }

  /** 登録ドメインの主要ラベル（例: amazon.co.jp → amazon） */
  function mainLabel(registrable) {
    return String(registrable || '').split('.')[0];
  }

  /**
   * ブランドに似せたドメインか。公式ドメインの主要ラベルと比較する。
   * 5文字未満の主要ラベル（例: live）は偶然の一致が多いため対象外。
   */
  function lookalikeOf(host, registrable, brand, psl) {
    const label = mainLabel(registrable);
    const subdomain = host.slice(0, Math.max(0, host.length - registrable.length - 1));
    for (const official of brand.officialDomains) {
      const target = mainLabel(official);
      if (target.length < 5) continue;
      // 公式ドメインそのものをサブドメインに含める（例: amazon.co.jp.evil.example）
      if (subdomain && (subdomain + '.').includes(official + '.')) {
        return `公式ドメイン（${official}）を含むサブドメインで偽装`;
      }
      if (label === target) continue;
      const unglyph = (s) => HOMOGLYPHS.reduce((x, [re, to]) => x.replace(re, to), s);
      const normalized = unglyph(label).replace(/-/g, '');
      if (normalized === target) return `似せた文字で「${target}」に見せかけたドメイン（${registrable}）`;
      // ブランド名（似せた文字を含む）にハイフン区切りの語を付け足したドメイン（例: amazon-security, amaz0n-account）
      const tokens = label.split('-').map(unglyph);
      if (tokens.length >= 2 && tokens.includes(target)) return `ブランド名「${target}」に語を付け足したドメイン（${registrable}）`;
      const limit = target.length >= 8 ? 2 : 1;
      if (Math.abs(label.length - target.length) <= limit && editDistance(label, target) <= limit) {
        return `「${target}」と1〜2文字だけ違うドメイン（${registrable}）`;
      }
    }
    return null;
  }

  /**
   * @param {object} desc  phishing-dom.js の抽出結果
   * @param {{psl: object, brands: object[]}} ctx
   * @returns {{score: number, level: 'none'|'caution'|'danger', reasons: {rule: string, points: number, detail: string}[]}}
   */
  function analyze(desc, ctx) {
    const { psl, brands } = ctx;
    const reg = (h) => (h ? psl.getRegistrableDomain(h) || h : '');
    const pageHost = hostOf(desc.url);
    const pageReg = reg(pageHost);
    const reasons = [];
    const add = (rule, group, points, detail) => reasons.push({ rule, group, points, detail });

    const forms = (desc.forms || []).filter((f) => (f.fieldKinds || []).some((k) => SENSITIVE.includes(k)));
    const sensitiveKinds = (f) => (f.fieldKinds || []).filter((k) => SENSITIVE.includes(k));
    const targetsOf = (f) => [f.action || desc.url, ...(f.formActions || [])].filter(Boolean);

    if (forms.length) {
      // ---- 1・2. ブランドの偽装・似せたドメイン（同じ「ドメイン」の根拠） ----
      const loginTitle = LOGIN_WORDS.test(desc.title || '');
      for (const brand of brands) {
        const official = brand.officialDomains.includes(pageReg);
        if (official) continue;
        const kw = brand.keywords;
        const titleClaim = loginTitle && kw.some((k) => mentions(desc.title, k));
        const headingClaim = (desc.headings || []).some((h) => LOGIN_WORDS.test(h) && kw.some((k) => mentions(h, k)));
        const formClaim = forms.some((f) => kw.some((k) => mentions(f.contextText, k) ||
          (f.logoAlts || []).some((a) => mentions(a, k))));
        // フォームの送信先がすべてそのブランドの公式ドメインなら、正規の埋め込み等として扱う
        const allToOfficial = forms.every((f) => targetsOf(f).every((t) => brand.officialDomains.includes(reg(hostOf(t)))));
        if ((titleClaim || headingClaim || formClaim) && !allToOfficial) {
          const where = [titleClaim && 'タイトル', headingClaim && '見出し', formClaim && '入力フォーム'].filter(Boolean).join('・');
          add('brandImpersonation', 'domain', POINTS.brandImpersonation,
            `「${brand.name}」のログイン・決済を装っている（${where}）が、公式ドメイン（${brand.officialDomains.join(', ')}）ではない: ${pageReg}`);
        }
        const look = lookalikeOf(pageHost, pageReg, brand, psl);
        if (look) add('lookalikeDomain', 'domain', POINTS.lookalikeDomain, `${brand.name}: ${look}`);
      }

      // ---- 3. 過剰な要求 ----
      const excessive = forms.find((f) => {
        const k = new Set(sensitiveKinds(f));
        const pay = k.has('card') || k.has('cvv');
        return (k.has('password') && pay) || (pay && k.has('pin'));
      });
      if (excessive) {
        add('excessiveFields', 'fields', POINTS.excessiveFields,
          `同じフォームで通常は別の場面で使う情報をまとめて要求（${[...new Set(sensitiveKinds(excessive))].join('・')}）`);
      }

      // ---- 4. 別の未確認ドメインへの送信 / 8. HTTP への送信 ----
      const officialOfClaimed = new Set(brands.flatMap((b) => b.officialDomains));
      for (const f of forms) {
        for (const t of targetsOf(f)) {
          const th = hostOf(t);
          if (!th) continue;
          if (protocolOf(t) === 'http:' && !isPrivateHost(th) && !isPrivateHost(pageHost)) {
            if (!reasons.some((r) => r.rule === 'insecureSubmit')) {
              add('insecureSubmit', 'transport', POINTS.insecureSubmit, `機密情報を暗号化されていない HTTP で送信するフォーム（送信先: ${th}）`);
            }
          }
          const treg = reg(th);
          if (treg && treg !== pageReg && !officialOfClaimed.has(treg) && !reasons.some((r) => r.rule === 'crossDomainSubmit')) {
            add('crossDomainSubmit', 'target', POINTS.crossDomainSubmit, `機密情報の送信先がページとは別のドメイン（${treg}）`);
          }
        }
      }

      // ---- 5. 脅しと期限 ----
      if (desc.threat && desc.threat.threat && desc.threat.deadline) {
        add('threatDeadline', 'pressure', POINTS.threatDeadline, '機密情報の入力を、アカウントの停止・失効などの脅しと期限つきで求めている');
      }
    }

    // ---- 6. 表示 URL と実際のリンク先の不一致 ----
    const mismatch = (desc.linkPairs || []).find((p) => {
      const a = reg(p.shownHost); const b = reg(p.actualHost);
      return a && b && a !== b;
    });
    if (mismatch) {
      add('linkTextMismatch', 'links', POINTS.linkTextMismatch, `表示されたURL（${mismatch.shownHost}）と実際のリンク先（${mismatch.actualHost}）が異なる`);
    }

    // ---- 7. 主要リンクが空 ----
    const legal = desc.legal || { total: 0, empty: 0 };
    if (legal.total >= 3 && legal.empty / legal.total >= 0.6) {
      add('emptyLegalLinks', 'legal', POINTS.emptyLegalLinks, `利用規約・会社概要などのリンク ${legal.total} 件中 ${legal.empty} 件が空・「#」`);
    }

    // ---- 集計: 同じ根拠（group）からは最大の点数だけを数える ----
    const byGroup = new Map();
    reasons.forEach((r) => { if (!byGroup.has(r.group) || byGroup.get(r.group) < r.points) byGroup.set(r.group, r.points); });
    const score = [...byGroup.values()].reduce((s, p) => s + p, 0);
    const kinds = byGroup.size;
    let level = 'none';
    if (kinds >= 2 && score >= THRESHOLD_DANGER) level = 'danger';
    else if (kinds >= 2 && score >= THRESHOLD_CAUTION) level = 'caution';
    if (level === 'none' && byGroup.has('transport')) level = 'caution'; // HTTP への機密情報送信は単独でも「注意」

    return { score, level, reasons: reasons.map(({ rule, points, detail }) => ({ rule, points, detail })) };
  }

  global.SiteRiskPhishing = { analyze, textSignals, POINTS, THRESHOLD_CAUTION, THRESHOLD_DANGER, LEGAL_LINK_RE, SENSITIVE };
})(typeof self !== 'undefined' ? self : globalThis);
