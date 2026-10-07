/**
 * コンテンツスクリプト：ページ本文を解析し、検出結果だけを background.js に渡す。
 * 本文そのものは送らず、外部への送信も行わない。
 *
 * - 初回の解析に加え、遅れて描画される内容（DOM の変化）にも追随する
 * - SPA（ページを再読み込みせずに URL が変わるサイト）では、URL が変わるたびに解析し直す
 * - フィッシングの追加チェックは、設定で有効にした場合だけ行う（設定の変更は開いているタブにも即時に反映）
 */
(function () {
  'use strict';

  const URL_CHECK_MS = 1000;       // URL 変化の確認間隔
  const MUTATION_DELAY_MS = 1500;  // DOM 変化から解析までの待ち時間（変化をまとめて1回にする）
  const URL_CHANGE_DELAY_MS = 800; // URL 変化から解析までの待ち時間（新しい内容の描画待ち）
  const MAX_RUNS_PER_URL = 10;     // 1つの URL で解析する回数の上限（常に変化し続けるページ対策）

  let lastSent = '';
  let lastPhishingSent = '';
  let phishingEnabled = false;
  let currentUrl = location.href;
  let runsForUrl = 0;
  let timer = null;

  function send(message) {
    try {
      chrome.runtime.sendMessage(message);
    } catch (_) {
      // 拡張機能の再読み込み直後など、接続できない場合は無視
    }
  }

  function collect() {
    timer = null;
    if (!document.body) return;
    runsForUrl++;
    const text = document.body.innerText || '';
    const links = Array.from(document.links).slice(0, 3000).map((a) => ({
      text: (a.textContent || '').trim().slice(0, 100),
      href: a.getAttribute('href') || '',
    }));
    const result = SiteRiskPageAnalyzer.analyzePage({ text, title: document.title, links });
    // URL も含めて比較し、URL が変わったら検出内容が同じでも送り直す
    const key = location.href + '\n' + JSON.stringify(result.signals);
    if (key !== lastSent) {
      lastSent = key;
      send({ type: 'pageSignals', url: location.href, signals: result.signals });
    }

    // フィッシングの追加チェック（有効な場合のみ）。入力欄の種類・送信先・周辺の文言だけを渡し、入力値は読まない
    if (phishingEnabled) {
      const desc = SiteRiskPhishingDom.describePage();
      const pkey = JSON.stringify(desc);
      if (pkey !== lastPhishingSent) {
        lastPhishingSent = pkey;
        send({ type: 'phishingScan', url: location.href, desc });
      }
    }
  }

  function schedule(delay, replace) {
    if (timer && !replace) return;
    clearTimeout(timer);
    timer = setTimeout(collect, delay);
  }

  // SPA の URL 変化（history.pushState 等はページ側の世界で呼ばれるため、URL を定期的に確認する）
  setInterval(() => {
    if (location.href !== currentUrl) {
      currentUrl = location.href;
      runsForUrl = 0;
      schedule(URL_CHANGE_DELAY_MS, true);
    }
  }, URL_CHECK_MS);

  // 遅れて描画される内容
  new MutationObserver(() => {
    if (runsForUrl < MAX_RUNS_PER_URL) schedule(MUTATION_DELAY_MS, false);
  }).observe(document.documentElement, { childList: true, subtree: true, characterData: true });

  // 設定（フィッシングの追加チェック）の読み込みと、変更への追随
  function applySettings(settings) {
    const enabled = !!(settings && settings.phishing);
    if (enabled === phishingEnabled) return;
    phishingEnabled = enabled;
    lastPhishingSent = '';
    if (enabled) {
      runsForUrl = 0;
      schedule(0, true); // 有効化されたら、開いているページもすぐに解析する
    }
  }
  try {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes.settings) applySettings(changes.settings.newValue);
    });
    chrome.storage.local.get('settings').then(({ settings }) => applySettings(settings)).catch(() => {});
  } catch (_) {
    // 拡張機能のコンテキストが無効になった場合は無視
  }

  collect();
})();
