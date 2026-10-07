/**
 * フィッシングの追加チェック用に、ページから「入力欄の種類・送信先・周辺の表示文言」を抽出する（コンテンツスクリプト）。
 *
 * - 利用者の入力値（value）は一切読まない。入力欄の種類は type / name / id / autocomplete /
 *   placeholder / aria-label / ラベルの文言だけから判断する
 * - 表示中の入力欄だけを数える（type=hidden、非表示要素、<template> 内は除外）
 * - 送信先は form の action 属性と、送信ボタンの formaction 属性を、<base> を考慮して解決する。
 *   JavaScript で別の送信先に送るページの実際の送信先は、この静的な解析では確認できない
 * - リンクのクリック、フォームの送信、リンク先への通信は行わない
 */
(function (global) {
  'use strict';

  const MAX_FORMS = 10;
  const MAX_CONTEXT = 600;

  // 入力欄の種類の判定（属性・ラベルの文言から。値は見ない）
  const KIND_RULES = [
    ['password', (a) => a.type === 'password' || /current-password|new-password/.test(a.autocomplete)],
    ['cvv', (a) => /cc-csc/.test(a.autocomplete) || /\b(cvv2?|cvc2?|csc)\b|security.?code|セキュリティ.?コード/i.test(a.text)],
    ['card', (a) => /cc-number/.test(a.autocomplete) || /card.?(num|no)|cc.?num|cardnumber|カード番号/i.test(a.text)],
    ['expiry', (a) => /cc-exp/.test(a.autocomplete) || /exp(iry|iration)?.?(date|month|year|mm|yy)|有効期限/i.test(a.text)],
    ['pin', (a) => /\bpin\b|暗証番号/i.test(a.text)],
    ['otp', (a) => /one-time-code/.test(a.autocomplete) || /\botp\b|one.?time|ワンタイム|認証コード|確認コード|verification.?code/i.test(a.text)],
    ['email', (a) => a.type === 'email' || /\bemail\b/.test(a.autocomplete) || /e-?mail|メールアドレス/i.test(a.text)],
    ['username', (a) => /username/.test(a.autocomplete) || /user.?(name|id)|login.?id|ログインid|ユーザー/i.test(a.text)],
  ];

  function isVisible(el) {
    if (!el || el.type === 'hidden' || el.closest('template')) return false;
    if (typeof el.checkVisibility === 'function') {
      return el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true });
    }
    const style = getComputedStyle(el);
    return el.getClientRects().length > 0 && style.visibility !== 'hidden' && style.display !== 'none';
  }

  function labelText(el) {
    const parts = [];
    if (el.labels) Array.from(el.labels).forEach((l) => parts.push(l.textContent || ''));
    const by = el.getAttribute('aria-labelledby');
    if (by) by.split(/\s+/).forEach((id) => { const t = document.getElementById(id); if (t) parts.push(t.textContent || ''); });
    return parts.join(' ').slice(0, 200);
  }

  function kindOf(el) {
    const tag = el.tagName.toLowerCase();
    if (tag !== 'input' && tag !== 'select' && tag !== 'textarea') return null;
    const type = (el.getAttribute('type') || (tag === 'input' ? 'text' : tag)).toLowerCase();
    if (['submit', 'button', 'reset', 'image', 'checkbox', 'radio', 'file', 'hidden', 'range', 'color'].includes(type)) return null;
    const attrs = {
      type,
      autocomplete: (el.getAttribute('autocomplete') || '').toLowerCase(),
      text: [el.getAttribute('name'), el.id, el.getAttribute('placeholder'), el.getAttribute('aria-label'), labelText(el)]
        .filter(Boolean).join(' '),
    };
    const hit = KIND_RULES.find(([, test]) => test(attrs));
    return hit ? hit[0] : 'other';
  }

  function resolve(url) {
    try { return new URL(url, document.baseURI).href; } catch (_) { return ''; }
  }

  function describeForm(container, formEl) {
    const fields = Array.from(container.querySelectorAll('input, select, textarea'))
      .filter((el) => (formEl ? el.form === formEl : !el.form) && isVisible(el));
    const fieldKinds = fields.map(kindOf).filter(Boolean);
    // action 属性が無い・空のときは、現在のページへ送信される
    const actionAttr = formEl ? formEl.getAttribute('action') : null;
    const action = formEl ? resolve(actionAttr && actionAttr.trim() ? actionAttr : document.URL) : '';
    const formActions = formEl
      ? Array.from(formEl.elements).filter((el) => el.hasAttribute && el.hasAttribute('formaction'))
        .map((el) => resolve(el.getAttribute('formaction'))).filter(Boolean)
      : [];
    // 周辺の表示文言: フォーム内の文言と、同じ親要素内の見出し
    const parent = container.parentElement || container;
    const headings = Array.from(parent.querySelectorAll('h1, h2, h3, legend')).slice(0, 3).map((h) => h.textContent || '');
    const contextText = [container.innerText || '', ...headings].join(' ').replace(/\s+/g, ' ').slice(0, MAX_CONTEXT);
    const logoAlts = Array.from(parent.querySelectorAll('img[alt], svg[aria-label]')).slice(0, 5)
      .map((i) => (i.getAttribute('alt') || i.getAttribute('aria-label') || '').slice(0, 60));
    return { fieldKinds, action, formActions, method: formEl ? (formEl.getAttribute('method') || 'get').toLowerCase() : '', contextText, logoAlts };
  }

  function describePage() {
    const forms = [];
    Array.from(document.forms).slice(0, MAX_FORMS).forEach((f) => {
      if (f.closest('template')) return;
      const d = describeForm(f, f);
      if (d.fieldKinds.length) forms.push(d);
    });
    // <form> に属さない入力欄（JavaScript で送信するページ）。送信先は静的には分からない。
    // 周辺の文言は、ページ全体ではなく、それらの入力欄をまとめて含む最小の要素から取る
    const orphanFields = Array.from(document.querySelectorAll('input, select, textarea'))
      .filter((el) => !el.form && isVisible(el) && kindOf(el));
    if (orphanFields.length) {
      let container = orphanFields[0].parentElement;
      while (container && container !== document.body && !orphanFields.every((el) => container.contains(el))) {
        container = container.parentElement;
      }
      if (!container || container === document.body || container === document.documentElement) {
        container = orphanFields[0].parentElement;
      }
      const orphan = describeForm(container, null);
      if (orphan.fieldKinds.length) forms.push({ ...orphan, action: '', jsSubmit: true });
    }

    const headings = Array.from(document.querySelectorAll('h1, h2')).filter(isVisible).slice(0, 5)
      .map((h) => (h.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 100));

    // URL として表示されたリンクと実際のリンク先
    const linkPairs = [];
    const legal = { total: 0, empty: 0 };
    Array.from(document.links).slice(0, 3000).forEach((a) => {
      const text = (a.textContent || '').trim();
      if (linkPairs.length < 20 && /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i.test(text)) {
        try {
          const shown = new URL(/^https?:\/\//i.test(text) ? text : 'https://' + text).hostname;
          const actual = new URL(a.href).hostname;
          if (/^https?:$/.test(new URL(a.href).protocol) && shown !== actual) linkPairs.push({ shownHost: shown, actualHost: actual });
        } catch (_) { /* 解釈できないものは無視 */ }
      }
      if (global.SiteRiskPhishing.LEGAL_LINK_RE.test(text) && text.length <= 30) {
        legal.total++;
        const href = (a.getAttribute('href') || '').trim();
        if (!href || href === '#' || /^javascript:/i.test(href)) legal.empty++;
      }
    });

    return {
      url: location.href,
      title: (document.title || '').slice(0, 200),
      headings,
      forms,
      threat: global.SiteRiskPhishing.textSignals(document.body ? document.body.innerText : ''),
      linkPairs,
      legal,
    };
  }

  global.SiteRiskPhishingDom = { describePage };
})(typeof self !== 'undefined' ? self : globalThis);
