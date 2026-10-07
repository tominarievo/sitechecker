/**
 * コンテンツスクリプト：ページ本文を解析し、検出結果だけを background.js に渡す。
 * 本文そのものは送らず、外部への送信も行わない。
 *
 * - 初回の解析に加え、遅れて描画される内容（DOM の変化）にも追随する
 * - SPA（ページを再読み込みせずに URL が変わるサイト）では、URL が変わるたびに解析し直す
 */
(function () {
  'use strict';

  const URL_CHECK_MS = 1000;       // URL 変化の確認間隔
  const MUTATION_DELAY_MS = 1500;  // DOM 変化から解析までの待ち時間（変化をまとめて1回にする）
  const URL_CHANGE_DELAY_MS = 800; // URL 変化から解析までの待ち時間（新しい内容の描画待ち）
  const MAX_RUNS_PER_URL = 10;     // 1つの URL で解析する回数の上限（常に変化し続けるページ対策）

  let lastSent = '';
  let currentUrl = location.href;
  let runsForUrl = 0;
  let timer = null;

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
    if (key === lastSent) return;
    lastSent = key;
    try {
      chrome.runtime.sendMessage({ type: 'pageSignals', url: location.href, signals: result.signals });
    } catch (_) {
      // 拡張機能の再読み込み直後など、接続できない場合は無視
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

  collect();
})();
