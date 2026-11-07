/**
 * ポップアップ制御：現在のタブの判定結果表示と、手動チェックフォーム。
 */
(function () {
  'use strict';

  const LEVEL_TEXT = {
    danger: { label: '危険', verdict: '⚠ 強いリスク要因が検出されました。個人情報や支払い情報を入力しないでください。' },
    caution: { label: '注意', verdict: '⚠ 不審な要素があります。運営者情報や口コミを確認してください。' },
    minor: { label: '低リスク', verdict: '軽微なリスク要因があります。念のため運営者情報を確認してください。' },
    safe: { label: '低リスク', verdict: '✓ 目立ったリスク要因は検出されませんでした。' },
    whitelist: { label: '判定除外', verdict: 'このドメインは偽通販チェックの判定除外リストに含まれています。安全性を保証するものではありません。' },
    blocklist: { label: '危険', verdict: '⛔ 既知の詐欺・偽ショップリストに登録されているサイトです。利用しないでください。' },
    history: { label: '注意', verdict: '⚠ 過去のフィッシング・悪質通販の公表情報に一致しました。現在の状態は未確認です。出典を確認し、個人情報や支払い情報の入力を控えてください。' },
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

    let key = result.blocklisted ? 'blocklist' : result.knownThreats?.length ? 'history' : result.whitelisted ? 'whitelist' : result.level;
    if (key === 'safe' && result.reasons.some((reason) => reason.points > 0)) key = 'minor';
    const text = LEVEL_TEXT[key];

    const card = el('div', 'card result');
    card.dataset.level = result.level;

    // スコア + ドメイン
    const head = el('div', 'head');
    const score = el('div', 'score');
    const num = el('div', 'num', String(result.score));
    num.appendChild(el('small', null, '点'));
    score.append(el('div', 'lbl', 'リスクスコア'), num,
      el('div', 'lbl', key === 'history' && result.level === 'danger' ? '危険' : text.label));

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
    if (result.blocklistDataDate) {
      const source = result.blocklistDataSource === 'dynamic' ? '自動更新' : '同梱データ';
      meta.appendChild(el('div', 'age', `ブラックリスト: ${source}（${formatDate(result.blocklistDataDate)}）`));
    }
    head.append(score, meta);
    card.appendChild(head);

    card.appendChild(el('div', 'verdict', text.verdict));

    if (result.threatDataStatus === 'unavailable') {
      card.appendChild(el('div', 'age', '公表履歴データを読み込めませんでした。この照合は実施できていません。'));
    } else if (result.threatDataDate) {
      card.appendChild(el('div', 'age', `公表履歴データ作成日: ${formatDate(result.threatDataDate)}`));
    }
    if (result.knownThreats?.length) {
      const sources = el('ul', 'reasons');
      for (const match of result.knownThreats) {
        const item = el('li');
        const link = el('a', 'detail', `${match.source.name} — ${match.date || '確認日不明'} — ${match.description || 'フィッシング'}`);
        // 公表元のURLだけを開く。対象サイトのリンクは生成しない。
        const sourceUrl = new URL(match.source.url);
        if (sourceUrl.protocol !== 'https:') continue;
        link.href = sourceUrl.href; link.target = '_blank'; link.rel = 'noopener noreferrer';
        item.appendChild(link); sources.appendChild(item);
      }
      card.appendChild(sources);
    }

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
    renderPhishing(container, result, card);
  }

  const PHISHING_LEVEL = { danger: '危険', caution: '注意', none: '警告なし' };

  /** フィッシングの追加チェック（有効な場合のみ）。偽通販チェックとは別のスコアとして表示する */
  function renderPhishing(container, result, mainCard) {
    if (!result.phishingEnabled) return;
    if (result.badgeSource === 'phishing') {
      mainCard.appendChild(el('div', 'source', '※ ツールバーの警告は「フィッシングの追加チェック」によるものです（下記）'));
    }
    const card = el('div', 'card result phishing');
    card.dataset.level = result.phishing ? (result.phishing.level === 'none' ? 'safe' : result.phishing.level) : '';
    card.appendChild(el('h3', null, 'フィッシングの追加チェック'));
    const p = result.phishing;
    if (!p) {
      card.appendChild(el('div', 'empty', result.manual
        ? '手動診断では行いません（ページの入力フォームを調べるため、開いているタブが対象です）。'
        : 'このページの解析結果はまだありません（読み込み中の可能性があります）。'));
      container.appendChild(card);
      return;
    }
    const head = el('div');
    head.append(el('span', 'points', `${p.score}点`), document.createTextNode(`（${PHISHING_LEVEL[p.level]}）`));
    card.appendChild(head);
    if (p.reasons.length) {
      const list = el('ul', 'reasons');
      p.reasons.forEach((r) => {
        const li = el('li');
        li.append(el('span', 'detail', r.detail), el('span', 'pts', `+${r.points}点`));
        list.appendChild(li);
      });
      card.appendChild(list);
    }
    card.appendChild(el('div', 'empty', p.level === 'none'
      ? '警告に至る根拠は見つかりませんでした。安全を保証するものではありません。'
      : '点数は暫定の基準による目安で、詐欺である確率ではありません。'));
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
      renderResult(output, { ...(await send({ type: 'analyze', url: input.value })), manual: true });
    });
  }

  async function setupSettings() {
    const rdap = document.getElementById('rdapToggle');
    const phishing = document.getElementById('phishingToggle');
    const settings = await send({ type: 'getSettings' });
    rdap.checked = !!settings.rdap;
    phishing.checked = !!settings.phishing;
    rdap.addEventListener('change', async () => {
      await send({ type: 'setSettings', settings: { rdap: rdap.checked } });
      showCurrentTab();
    });
    phishing.addEventListener('change', async () => {
      await send({ type: 'setSettings', settings: { phishing: phishing.checked } });
      showCurrentTab();
      // 有効化した場合、開いているページの解析結果が届くまで少し待って表示を更新する
      if (phishing.checked) setTimeout(showCurrentTab, 1500);
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    showCurrentTab();
    setupForm();
    setupSettings();
  });
})();
