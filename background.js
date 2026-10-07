/**
 * Service Worker：タブの切り替え・更新を監視し、ツールバーアイコンのバッジを更新する。
 * 判定に必要な情報（ブラックリスト・RDAP・ページ内容・フィッシングの追加チェック）をここで集約し、popup にも結果を返す。
 */
importScripts('detector.js', 'rdap.js', 'psl.js', 'phishing-analyzer.js');

const BADGE = {
  danger: { text: '危険', color: '#dc2626' },
  caution: { text: '注意', color: '#f59e0b' },
};

// rdap: 外部への送信を伴うため、利用者が有効にしたときだけ使う
// phishing: フィッシングの追加チェック（端末内で解析）。利用者が有効にしたときだけ使う
const DEFAULT_SETTINGS = { rdap: false, phishing: false };
const RDAP_TTL_OK = 7 * 86400000;      // 登録日が取れた結果は7日間キャッシュ
const RDAP_TTL_FAIL = 6 * 3600000;     // 失敗・非対応は6時間キャッシュ
const RDAP_TTL_ERROR = 10 * 60000;     // 通信エラーは10分

// ---- ブラックリスト（data/blocklist.txt を同梱） ------------------------------

let blocklistPromise = null;
function getBlocklist() {
  if (!blocklistPromise) {
    blocklistPromise = fetch(chrome.runtime.getURL('data/blocklist.txt'))
      .then((res) => res.text())
      .then((text) => new Set(text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))))
      .catch(() => new Set());
  }
  return blocklistPromise;
}

// ---- フィッシングの追加チェック用のデータ（Public Suffix List・ブランド対応表を同梱） ----------

let pslPromise = null;
function getPsl() {
  if (!pslPromise) {
    pslPromise = fetch(chrome.runtime.getURL('data/public_suffix_list.dat'))
      .then((res) => res.text())
      .then((text) => SiteRiskPsl.parse(text));
  }
  return pslPromise;
}

let brandsPromise = null;
function getBrands() {
  if (!brandsPromise) {
    brandsPromise = fetch(chrome.runtime.getURL('data/brands.json'))
      .then((res) => res.json())
      .then((json) => json.brands || []);
  }
  return brandsPromise;
}

// ---- 設定 -------------------------------------------------------------------

async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

// ---- RDAP（キャッシュ付き） ----------------------------------------------------

// IANA ブートストラップ（TLD → RDAPサーバー）は1日キャッシュ
let bootstrapPromise = null;
function getBootstrap() {
  if (!bootstrapPromise) {
    bootstrapPromise = (async () => {
      const { rdapBootstrap } = await chrome.storage.local.get('rdapBootstrap');
      if (rdapBootstrap && rdapBootstrap.expires > Date.now()) return rdapBootstrap.map;
      const map = await SiteRiskRdap.fetchBootstrap();
      await chrome.storage.local.set({ rdapBootstrap: { map, expires: Date.now() + 86400000 } });
      return map;
    })().catch((e) => {
      bootstrapPromise = null; // 次回やり直す
      throw e;
    });
  }
  return bootstrapPromise;
}

const rdapInflight = new Map();
// キャッシュの世代。RDAP を無効化するたびに進め、無効化前に始まった照会の応答を保存しないために使う
let rdapGeneration = 0;

async function getDomainInfo(domain) {
  const key = 'rdap:' + domain;
  const cached = (await chrome.storage.local.get(key))[key];
  if (cached && cached.expires > Date.now()) return cached.info;

  if (!rdapInflight.has(domain)) {
    const generation = rdapGeneration;
    const promise = (async () => {
      let info;
      try {
        info = await SiteRiskRdap.lookupRegistration(domain, { bootstrap: await getBootstrap() });
      } catch (e) {
        info = { status: 'error', error: 'bootstrap: ' + e.message };
      }
      // 照会中に RDAP が無効化された場合は保存しない（世代の変化と、保存直前の設定の両方を確認）
      if (generation === rdapGeneration && (await getSettings()).rdap) {
        const ttl = info.status === 'ok' ? RDAP_TTL_OK : info.status === 'error' ? RDAP_TTL_ERROR : RDAP_TTL_FAIL;
        await chrome.storage.local.set({ [key]: { info, expires: Date.now() + ttl } });
      }
      return info;
    })().finally(() => {
      if (rdapInflight.get(domain) === promise) rdapInflight.delete(domain);
    });
    rdapInflight.set(domain, promise);
  }
  return rdapInflight.get(domain);
}

// 保存期限を過ぎた RDAP の照会結果を削除する（ブラウザ起動時・拡張機能の動作時。1時間に1回まで）
const PURGE_INTERVAL = 3600000;
async function purgeExpiredRdap(force) {
  const { lastPurge } = await chrome.storage.session.get('lastPurge');
  if (!force && lastPurge && Date.now() - lastPurge < PURGE_INTERVAL) return 0;
  await chrome.storage.session.set({ lastPurge: Date.now() });
  const all = await chrome.storage.local.get(null);
  const now = Date.now();
  const expired = Object.keys(all).filter((k) =>
    (k.startsWith('rdap:') || k === 'rdapBootstrap') && !(all[k] && all[k].expires > now));
  if (expired.length) await chrome.storage.local.remove(expired);
  return expired.length;
}

/** RDAP を無効にしたときは、保存済みの照会結果をすべて削除する */
async function clearRdapCache() {
  rdapGeneration++;      // 照会中の応答を、この後に保存させない
  rdapInflight.clear();  // 照会中の結果を、再び有効化した後に使い回さない
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith('rdap:') || k === 'rdapBootstrap');
  if (keys.length) await chrome.storage.local.remove(keys);
  bootstrapPromise = null;
  return keys.length;
}

// ---- ページ内容（content.js から受け取った検出結果） -----------------------------

async function getPageSignals(tabId, url) {
  if (tabId == null) return [];
  const key = 'page:' + tabId;
  const entry = (await chrome.storage.session.get(key))[key];
  if (!entry) return [];
  // 同じページ（オリジン+パス）の結果だけを使う
  const same = (a, b) => {
    try {
      const x = new URL(a); const y = new URL(b);
      return x.origin === y.origin && x.pathname === y.pathname;
    } catch (_) { return false; }
  };
  return same(entry.url, url) ? entry.signals : [];
}

// ---- 判定 -------------------------------------------------------------------

// 既存の判定（URL・ドメイン・ブラックリスト・RDAP・偽通販のページ内容）
async function evaluateBase(url, tabId) {
  const first = SiteRiskDetector.analyze(url);
  if (first.level === 'invalid' || first.level === 'unsupported' || first.whitelisted) {
    return { ...first, rdapStatus: 'skipped' };
  }

  const [blocklist, settings, pageSignals] = await Promise.all([
    getBlocklist(), getSettings(), getPageSignals(tabId, url),
  ]);

  let domainInfo = null;
  let rdapStatus = 'disabled';
  if (settings.rdap && first.rdapEligible) {
    domainInfo = await getDomainInfo(first.domain);
    rdapStatus = domainInfo.status;
  } else if (!first.rdapEligible) {
    rdapStatus = 'skipped';
  }

  const result = SiteRiskDetector.analyze(url, { blocklist, domainInfo, pageSignals });
  return { ...result, rdapStatus };
}

const LEVEL_ORDER = { safe: 0, none: 0, caution: 1, danger: 2 };

/**
 * 既存の判定に、フィッシングの追加チェック（有効な場合のみ）の結果を添える。
 * 2つの点数は足し合わせず、バッジには強い方の警告を出す。
 * ホワイトリストで既存の判定が早期終了した場合も、追加チェックの結果は省略しない。
 */
async function evaluate(url, tabId) {
  const base = await evaluateBase(url, tabId);
  const settings = await getSettings();
  const out = { ...base, phishingEnabled: !!settings.phishing, phishing: null, badgeLevel: base.level, badgeSource: 'base' };
  if (!settings.phishing || tabId == null || base.level === 'invalid' || base.level === 'unsupported') return out;
  const phishing = await getPhishingResult(tabId, url);
  out.phishing = phishing;
  if (phishing && LEVEL_ORDER[phishing.level] > LEVEL_ORDER[base.level]) {
    out.badgeLevel = phishing.level;
    out.badgeSource = 'phishing';
  }
  return out;
}

// ---- フィッシングの追加チェックの結果（タブごと。content.js の抽出結果を採点したもの） ----------

// 世代番号。追加チェックを無効化するたびに進め、無効化前に始まった処理の結果を反映・保存しないために使う
let phishingGeneration = 0;

async function getPhishingResult(tabId, url) {
  const key = 'phish:' + tabId;
  const entry = (await chrome.storage.session.get(key))[key];
  return entry && sameDocument(entry.url, url) ? entry.result : null;
}

/** 抽出結果を採点する（テストで遅延させられるよう関数として分けている） */
async function scorePhishing(desc) {
  const [psl, brands] = await Promise.all([getPsl(), getBrands()]);
  return SiteRiskPhishing.analyze(desc, { psl, brands });
}

async function handlePhishingScan(tabId, url, desc) {
  const generation = phishingGeneration;
  if (!(await getSettings()).phishing) return;
  const result = await scorePhishing({ ...desc, url });
  // 採点中に無効化された場合は保存・反映しない
  if (generation !== phishingGeneration || !(await getSettings()).phishing) return;
  await chrome.storage.session.set({ ['phish:' + tabId]: { url, result } });
  if (generation !== phishingGeneration) {
    await chrome.storage.session.remove('phish:' + tabId);
    return;
  }
  updateBadge(tabId, url);
}

/** 追加チェックを無効化: 進行中の処理を無効にし、結果を削除して、既存の判定だけでバッジを更新し直す */
async function disablePhishing() {
  phishingGeneration++;
  const all = await chrome.storage.session.get(null);
  const keys = Object.keys(all).filter((k) => k.startsWith('phish:'));
  if (keys.length) await chrome.storage.session.remove(keys);
  await scanAllTabs();
}

// 同じ文書か（# 以降の違いは同じページとみなす）
function sameDocument(a, b) {
  return String(a || '').split('#')[0] === String(b || '').split('#')[0];
}

// タブごとの最新の判定番号と URL。判定中にページが変わった場合、古い結果でバッジを上書きしないために使う
const badgeSeq = new Map();
const badgeUrl = new Map();

async function updateBadge(tabId, url) {
  const seq = (badgeSeq.get(tabId) || 0) + 1;
  badgeSeq.set(tabId, seq);
  if (!sameDocument(badgeUrl.get(tabId), url)) {
    // ページが変わったら、新しい判定が出るまで前のページの表示を消す
    badgeUrl.set(tabId, url);
    try { await chrome.action.setBadgeText({ tabId, text: '' }); } catch (_) {}
  }

  const result = await evaluate(url || '', tabId);

  // 判定中に、より新しい判定が始まった・タブが別のページに移った場合は反映しない
  if (badgeSeq.get(tabId) !== seq) return result;
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!sameDocument(tab.url, url)) return result;
  } catch (_) {
    return result; // タブが閉じられた
  }

  const badge = BADGE[result.badgeLevel || result.level];
  try {
    await chrome.action.setBadgeText({ tabId, text: badge ? badge.text : '' });
    if (badge) {
      await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
      if (chrome.action.setBadgeTextColor) {
        await chrome.action.setBadgeTextColor({ tabId, color: '#ffffff' });
      }
    }
    const phishingNote = result.phishing && result.phishing.level !== 'none'
      ? ` ／ フィッシングの追加チェック ${result.phishing.score}点` : '';
    await chrome.action.setTitle({
      tabId,
      title: result.hostname
        ? `詐欺サイトチェッカー: ${result.hostname}（偽通販判定 ${result.score}%${phishingNote}）`
        : '詐欺サイトチェッカー',
    });
  } catch (_) {
    // 判定中にタブが閉じられた場合などは無視
  }
  return result;
}

// ---- イベント ------------------------------------------------------------------

// タブ切り替え時
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try {
    const tab = await chrome.tabs.get(tabId);
    updateBadge(tabId, tab.url);
  } catch (_) {}
});

// タブ更新（ページ遷移・リロード）時
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || changeInfo.status === 'loading' || changeInfo.status === 'complete') {
    updateBadge(tabId, changeInfo.url || tab.url);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  badgeSeq.delete(tabId);
  badgeUrl.delete(tabId);
  chrome.storage.session.remove(['page:' + tabId, 'phish:' + tabId]);
});

// content.js / popup.js からのメッセージ
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'pageSignals' && sender.tab) {
    const tabId = sender.tab.id;
    chrome.storage.session.set({ ['page:' + tabId]: { url: msg.url, signals: msg.signals || [] } })
      .then(() => updateBadge(tabId, msg.url));
    return false;
  }
  if (msg.type === 'phishingScan' && sender.tab && msg.desc) {
    handlePhishingScan(sender.tab.id, msg.url, msg.desc);
    return false;
  }
  if (msg.type === 'analyze') {
    evaluate(msg.url, msg.tabId).then(sendResponse);
    return true;
  }
  if (msg.type === 'getSettings') {
    getSettings().then(sendResponse);
    return true;
  }
  if (msg.type === 'setSettings') {
    const turningOffPhishing = msg.settings && msg.settings.phishing === false;
    if (turningOffPhishing) phishingGeneration++; // 進行中の採点を、この時点で無効にする
    getSettings()
      .then((s) => chrome.storage.local.set({ settings: { ...s, ...msg.settings } }))
      .then(() => (msg.settings && msg.settings.rdap === false ? clearRdapCache() : 0))
      .then(() => (turningOffPhishing ? disablePhishing() : 0))
      .then(() => sendResponse({ ok: true }));
    return true;
  }
  return false;
});

// インストール・起動時に既存タブをまとめて判定
async function scanAllTabs() {
  const tabs = await chrome.tabs.query({});
  tabs.forEach((tab) => updateBadge(tab.id, tab.url));
}
chrome.runtime.onInstalled.addListener(() => { purgeExpiredRdap(true); scanAllTabs(); });
chrome.runtime.onStartup.addListener(() => { purgeExpiredRdap(true); scanAllTabs(); });
// Service Worker が起動するたびに（1時間に1回まで）期限切れの照会結果を削除
purgeExpiredRdap(false);
