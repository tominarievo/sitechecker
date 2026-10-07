/**
 * ポップアップ制御：現在のタブの判定結果表示と、手動チェックフォーム。
 */
(function () {
  'use strict';

  const LEVEL_TEXT = {
    danger: { label: '危険', verdict: '⚠ 詐欺サイトの可能性が高いです。個人情報や支払い情報を入力しないでください。' },
    caution: { label: '注意', verdict: '⚠ 不審な要素があります。運営者情報や口コミを確認してください。' },
    minor: { label: '低リスク', verdict: '軽微なリスク要因があります。念のため運営者情報を確認してください。' },
    safe: { label: '低リスク', verdict: '✓ 目立ったリスク要因は検出されませんでした。' },
    whitelist: { label: '安全', verdict: '✓ 信頼済みドメインです。' },
    blocklist: { label: '危険', verdict: '⛔ 既知の詐欺・偽ショップリストに登録されているサイトです。利用しないでください。' },
  };

  const RDAP_TEXT = {
    notfound: '未登録（RDAPに登録情報なし）',
    unsupported: 'このTLDはRDAP非対応のため確認できません（.jp 等）',
    nodate: '登録日の情報がありません',
    error: '照会に失敗しました（通信エラー）',
    disabled: '確認オフ（設定で有効にできます）',
    skipped: null,
  };

  function send(msg) {
    return chrome.runtime.sendMessage(msg);
  }

  function formatDate(iso) {
    const d = new Date(iso);
    return `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, '0')}/${String(d.getDate()).padStart(2, '0')}`;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  function renderMessage(container, message) {
    container.replaceChildren();
    const card = el('div', 'card result');
    card.appendChild(el('div', 'empty', message));
    container.appendChild(card);
  }

  function renderResult(container, result) {
    container.replaceChildren();

    if (result.level === 'invalid') {
      renderMessage(container, 'URLまたはドメインの形式が正しくありません。');
      return;
    }
    if (result.level === 'unsupported') {
      renderMessage(container, 'このページ（ブラウザの内部ページ等）は診断対象外です。');
      return;
    }

    let key = result.whitelisted ? 'whitelist' : result.blocklisted ? 'blocklist' : result.level;
    if (key === 'safe' && result.reasons.length) key = 'minor';
    const text = LEVEL_TEXT[key];

    const card = el('div', 'card result');
    card.dataset.level = result.level;

    // スコア + ドメイン
    const head = el('div', 'head');
    const score = el('div', 'score');
    const num = el('div', 'num', String(result.score));
    num.appendChild(el('small', null, '%'));
    score.append(num, el('div', 'lbl', text.label));

    const meta = el('div', 'meta');
    meta.append(
      el('div', 'domain', result.hostname),
      el('div', 'url', result.url),
    );
    if (result.registered) {
      meta.appendChild(el('div', 'age', `ドメイン登録日: ${formatDate(result.registered)}（${result.domainAgeDays}日前）`));
    } else if (RDAP_TEXT[result.rdapStatus]) {
      meta.appendChild(el('div', 'age', `ドメイン登録日: ${RDAP_TEXT[result.rdapStatus]}`));
    }
    head.append(score, meta);
    card.appendChild(head);

    card.appendChild(el('div', 'verdict', text.verdict));

    // 判定根拠
    if (result.reasons.length) {
      const list = el('ul', 'reasons');
      result.reasons.forEach((r) => {
        const li = el('li');
        li.append(
          el('span', 'cat', r.category),
          el('span', 'detail', r.detail),
          el('span', r.points < 0 ? 'pts neg' : 'pts', r.points > 0 ? `+${r.points}` : r.points < 0 ? String(r.points) : ''),
        );
        list.appendChild(li);
      });
      card.appendChild(list);
    } else {
      card.appendChild(el('div', 'empty', '検出されたリスク要因はありません。'));
    }

    container.appendChild(card);
  }

  async function showCurrentTab() {
    const container = document.getElementById('currentResult');
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab || !tab.url) {
        renderMessage(container, 'タブのURLを取得できませんでした。');
        return;
      }
      renderMessage(container, '判定中…');
      renderResult(container, await send({ type: 'analyze', url: tab.url, tabId: tab.id }));
    } catch (e) {
      renderMessage(container, 'タブ情報の取得に失敗しました: ' + e.message);
    }
  }

  function setupForm() {
    const form = document.getElementById('checkForm');
    const input = document.getElementById('checkInput');
    const output = document.getElementById('manualResult');
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      renderMessage(output, '判定中…');
      renderResult(output, await send({ type: 'analyze', url: input.value }));
    });
  }

  async function setupSettings() {
    const rdap = document.getElementById('rdapToggle');
    const settings = await send({ type: 'getSettings' });
    rdap.checked = !!settings.rdap;
    rdap.addEventListener('change', async () => {
      await send({ type: 'setSettings', settings: { rdap: rdap.checked } });
      showCurrentTab();
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    showCurrentTab();
    setupForm();
    setupSettings();
  });
})();
