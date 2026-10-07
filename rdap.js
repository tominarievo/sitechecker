/**
 * RDAP（ドメイン登録情報の公式照会プロトコル）でドメインの登録日を調べる。
 * IANA が公開している TLD ごとの RDAP サーバー一覧（ブートストラップ）を使い、
 * そのTLDを管理するレジストリに直接問い合わせる（第三者の中継サービスを経由しない）。
 * 送信するのは登録ドメイン名だけで、URLのパスやCookieは送らない。
 * background.js（importScripts）と tests/evaluate.js（require）から読み込む。
 */
(function (global) {
  'use strict';

  const BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

  /** IANA ブートストラップ（{services: [[tlds], [urls]][]}）を { tld: baseUrl } に変換 */
  function parseBootstrap(json) {
    const map = {};
    (json.services || []).forEach(([tlds, urls]) => {
      const url = (urls || []).find((u) => u.startsWith('https://')) || (urls || [])[0];
      if (url) tlds.forEach((t) => { map[t.toLowerCase()] = url.endsWith('/') ? url : url + '/'; });
    });
    return map;
  }

  async function fetchBootstrap(options) {
    const { fetchImpl = fetch, timeoutMs = 10000 } = options || {};
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetchImpl(BOOTSTRAP_URL, { signal: ctrl.signal, credentials: 'omit' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return parseBootstrap(await res.json());
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * @param {string} domain 登録ドメイン（例: example.com）
   * @param {{bootstrap: Object<string,string>, fetchImpl?: Function, timeoutMs?: number}} options
   * @returns {Promise<{status: 'ok'|'nodate'|'notfound'|'unsupported'|'error', registered?: string, error?: string}>}
   *   ok: 登録日を取得 / nodate: 応答に登録日なし / notfound: 未登録
   *   unsupported: RDAP 非対応のTLD（.jp, .de など）/ error: 通信エラー・タイムアウト
   */
  async function lookupRegistration(domain, options) {
    const { bootstrap, fetchImpl = fetch, timeoutMs = 6000 } = options || {};
    const tld = domain.split('.').pop().toLowerCase();
    const base = bootstrap && bootstrap[tld];
    if (!base) return { status: 'unsupported' };

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetchImpl(base + 'domain/' + encodeURIComponent(domain), {
        signal: ctrl.signal,
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        headers: { Accept: 'application/rdap+json, application/json' },
      });
      if (res.status === 404) return { status: 'notfound' };
      if (!res.ok) return { status: 'error', error: `HTTP ${res.status}` };
      const json = await res.json();
      const ev = (json.events || []).find((e) => e.eventAction === 'registration');
      return ev && ev.eventDate ? { status: 'ok', registered: ev.eventDate } : { status: 'nodate' };
    } catch (e) {
      return { status: 'error', error: e && e.name === 'AbortError' ? 'timeout' : String((e && e.message) || e) };
    } finally {
      clearTimeout(timer);
    }
  }

  global.SiteRiskRdap = { fetchBootstrap, lookupRegistration };
})(typeof self !== 'undefined' ? self : globalThis);
