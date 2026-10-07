/**
 * 実ブラウザ（Edge / Chrome）で拡張機能を読み込み、ローカルの模擬ページで動作を確認する E2E テスト。
 * - 閲覧するのは 127.0.0.1 上の tests/fixtures/ のページだけ（外部サイトには接続しない）
 * - 普段のブラウザとは別の一時プロファイルで起動し、終了後に削除する
 *
 * 使い方: node tests/e2e.js [ブラウザのexeパス]
 */
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const EXT_DIR = process.env.SITECHECKER_EXT_DIR || path.join(__dirname, '..'); // 配布用ZIPの展開先を試す場合に指定
const FIXTURES = path.join(__dirname, 'fixtures');
const BROWSER = process.argv[2] || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const DEBUG_PORT = 9333;
const FIXTURE_PORT = 8787;
const SLOW_HOST = 'slowshop.top'; // 判定（RDAP）を遅延させる遷移テスト用の名前
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- 模擬ページ配信（127.0.0.1 のみ） -------------------------------------------
const server = http.createServer((req, res) => {
  const file = path.join(FIXTURES, path.basename(new URL(req.url, 'http://x').pathname));
  if (!fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  fs.createReadStream(file).pipe(res);
});

// ---- CDP（Chrome DevTools Protocol） ---------------------------------------------
async function getJson(p, method = 'GET') {
  const res = await fetch(`http://127.0.0.1:${DEBUG_PORT}${p}`, { method });
  return res.json();
}

function cdp(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0;
  const pending = new Map();
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  };
  const ready = new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  return {
    ready,
    send: (method, params) => new Promise((resolve) => {
      const n = ++id;
      pending.set(n, resolve);
      ws.send(JSON.stringify({ id: n, method, params }));
    }),
    close: () => ws.close(),
  };
}

async function evalInWorker(worker, expression) {
  const r = await worker.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
  if (r.result && r.result.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails));
  return r.result && r.result.result && r.result.result.value;
}

// ---- 本体 -------------------------------------------------------------------
(async () => {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'sitechecker-e2e-'));
  await new Promise((r) => server.listen(FIXTURE_PORT, '127.0.0.1', r));

  // Chrome（137 以降）はコマンドラインでの拡張読み込みを受け付けないため、
  // DevTools プロトコル（パイプ接続）の Extensions.loadUnpacked で読み込む
  const usePipe = /chrome\.exe$/i.test(BROWSER);
  const browser = spawn(BROWSER, [
    ...(usePipe
      ? ['--remote-debugging-pipe', '--enable-unsafe-extension-debugging']
      : [`--load-extension=${EXT_DIR}`, `--disable-extensions-except=${EXT_DIR}`]),
    `--user-data-dir=${profile}`,
    `--remote-debugging-port=${DEBUG_PORT}`,
    '--headless=new',
    '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-sync',
    '--disable-features=msEdgeSidebarV2',
    // テスト用のドメイン名をローカル（127.0.0.1）に向ける。外部のサーバーには接続しない
    `--host-resolver-rules=MAP ${SLOW_HOST} 127.0.0.1`,
    'about:blank',
  ], { stdio: usePipe ? ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] : 'ignore' });

  if (usePipe) {
    const result = await new Promise((resolve, reject) => {
      let buf = '';
      const timer = setTimeout(() => reject(new Error('Extensions.loadUnpacked の応答がありません')), 20000);
      browser.stdio[4].on('data', (chunk) => {
        buf += chunk.toString('utf8');
        let i;
        while ((i = buf.indexOf('\0')) >= 0) {
          const msg = JSON.parse(buf.slice(0, i));
          buf = buf.slice(i + 1);
          if (msg.id === 1) { clearTimeout(timer); resolve(msg); }
        }
      });
      browser.stdio[3].write(JSON.stringify({ id: 1, method: 'Extensions.loadUnpacked', params: { path: EXT_DIR } }) + '\0');
    }).catch((e) => ({ error: { message: e.message } }));
    if (result.error) console.error('拡張機能の読み込みに失敗: ' + result.error.message);
  }

  let exitCode = 1;
  try {
    // 拡張機能の Service Worker を探す
    let swTarget = null;
    for (let i = 0; i < 40 && !swTarget; i++) {
      await sleep(500);
      try {
        const targets = await getJson('/json/list');
        swTarget = targets.find((t) => t.type === 'service_worker' && /background\.js$/.test(t.url));
      } catch (_) { /* 起動待ち */ }
    }
    if (!swTarget) throw new Error('拡張機能の Service Worker が見つかりません（--load-extension が無効なブラウザの可能性）');
    console.log('拡張機能を読み込みました: ' + swTarget.url.split('/')[2]);

    const worker = cdp(swTarget.webSocketDebuggerUrl);
    await worker.ready;

    let ok = true;
    const check = (cond, label) => { console.log(`${cond ? '✓' : '✗'} ${label}`); if (!cond) ok = false; };
    const base = `http://127.0.0.1:${FIXTURE_PORT}`;
    const badgeOf = (pred) => evalInWorker(worker, `
      chrome.tabs.query({}).then(async (tabs) => {
        const t = tabs.find((t) => (${pred})(t.url || ''));
        return t ? { url: t.url, badge: await chrome.action.getBadgeText({ tabId: t.id }) } : null;
      })`);
    const step = async (label, fn) => {
      try { await fn(); } catch (e) { check(false, `${label}: ${e.message.slice(0, 120)}`); }
    };

    // ---- 1. 基本: 模擬ページの判定とバッジ ----
    await step('基本', async () => {
      for (const p of ['fake-shop.html', 'legit-shop.html']) await getJson(`/json/new?${base}/${p}`, 'PUT');
      await sleep(5000);
      const rows = await evalInWorker(worker, `
        chrome.tabs.query({}).then((tabs) => Promise.all(tabs
          .filter((t) => /(fake|legit)-shop\\.html$/.test(t.url || ''))
          .map(async (t) => {
            const r = await evaluate(t.url, t.id);
            return { url: t.url, badge: await chrome.action.getBadgeText({ tabId: t.id }), score: r.score, level: r.level };
          })))`);
      const fake = rows.find((r) => r.url.includes('fake-shop'));
      const legit = rows.find((r) => r.url.includes('legit-shop'));
      check(fake && fake.level === 'danger' && fake.badge === '危険', `偽通販の模擬ページ → 危険バッジ（${fake && fake.score}%, バッジ「${fake && fake.badge}」）`);
      check(legit && legit.level === 'safe' && legit.badge === '', `正規通販の模擬ページ → バッジなし（${legit && legit.score}%）`);
    });

    // ---- 2. 手動チェック（popup → background の 'analyze' と同じ経路） ----
    await step('手動チェック', async () => {
      const manual = await evalInWorker(worker, `
        Promise.all(['https://xqzvt.rest/index.php?main_page=product_info&zenid=abc', 'https://www.amazon.co.jp/']
          .map((u) => evaluate(u).then((r) => ({ url: u, score: r.score, level: r.level, rdap: r.rdapStatus }))))`);
      check(manual[0].level === 'danger', `手動チェック: 詐欺キットURL → 危険（${manual[0].score}%）`);
      check(manual[1].score === 0, '手動チェック: amazon.co.jp → 0%');
      check(manual[0].rdap === 'disabled', `RDAP は初期設定でオフ（${manual[0].rdap}）`);
    });

    // ---- 3. RDAP がブラウザ内（CORS 制約下）で動くか。照会先は IANA と .com のレジストリのみ ----
    await step('RDAP', async () => {
      const rdap = await evalInWorker(worker, `
        getBootstrap().then((b) => SiteRiskRdap.lookupRegistration('google.com', { bootstrap: b }))`);
      check(rdap && rdap.status === 'ok' && /^1997-09-15/.test(rdap.registered), `RDAP（ブラウザ内）: google.com の登録日 ${rdap && (rdap.registered || rdap.status)}`);
    });

    // ---- 4. 回帰: 判定中に別ページへ移っても、前のページの結果でバッジを上書きしない ----
    await step('回帰: 遷移中の判定', async () => {
      // RDAP を有効にし、照会を「5秒遅れて『登録5日前』と返す」偽物に差し替える（外部には問い合わせない）
      await evalInWorker(worker, `
        chrome.storage.local.set({ settings: { rdap: true } }).then(() => {
          self.__realGetDomainInfo = getDomainInfo; // 後で元に戻す
          getDomainInfo = () => new Promise((r) => setTimeout(() => r({ status: 'ok', registered: new Date(Date.now() - 5 * 86400000).toISOString() }), 5000));
          return true;
        })`);
      await getJson(`/json/new?http://${SLOW_HOST}:${FIXTURE_PORT}/fake-shop.html`, 'PUT');
      await sleep(1500);
      await evalInWorker(worker, `
        chrome.tabs.query({}).then((tabs) => {
          const t = tabs.find((t) => (t.url || '').includes('${SLOW_HOST}'));
          return chrome.tabs.update(t.id, { url: '${base}/legit-shop.html?after-slow' });
        }).then(() => true)`);
      await sleep(8000); // 遅延させた判定（5秒）が終わるのを待つ
      const race = await badgeOf("(u) => u.includes('after-slow')");
      check(race && race.badge === '', `回帰: 判定中に正規ページへ移動 → 前のページの「危険」が残らない（バッジ「${race && race.badge}」）`);
      await evalInWorker(worker, `chrome.storage.local.set({ settings: { rdap: false } }).then(() => { getDomainInfo = self.__realGetDomainInfo; return true; })`);
    });

    // ---- 5. 回帰: SPA（再読み込みなしの URL 変更）と、遅れて描画される内容への追随 ----
    await step('回帰: SPA', async () => {
      await getJson(`/json/new?${base}/spa-shop.html`, 'PUT');
      await sleep(3500);
      const early = await badgeOf("(u) => u.includes('spa-item.html')");
      check(early && early.badge === '', `回帰: SPA の URL 変更直後（偽の内容の描画前）→ バッジなし（バッジ「${early && early.badge}」）`);
      await sleep(9000); // 7.5秒後の描画 + 解析待ち
      const spa = await badgeOf("(u) => u.includes('spa-item.html')");
      check(spa && spa.badge === '危険', `回帰: SPA で URL 変更後に遅れて描画された偽通販 → 危険バッジ（バッジ「${spa && spa.badge}」）`);
    });

    // ---- 6. 保存期限: 期限切れの照会結果の削除と、RDAP 無効化時の全削除 ----
    await step('保存期限', async () => {
      const purge = await evalInWorker(worker, `
        (async () => {
          await chrome.storage.local.set({
            'rdap:expired.example': { info: { status: 'ok', registered: '2020-01-01T00:00:00Z' }, expires: Date.now() - 1000 },
            'rdap:fresh.example': { info: { status: 'ok', registered: '2020-01-01T00:00:00Z' }, expires: Date.now() + 3600000 },
          });
          const removed = await purgeExpiredRdap(true);
          const left = Object.keys(await chrome.storage.local.get(null)).filter((k) => k.startsWith('rdap:'));
          return { removed, left };
        })()`);
      check(purge && !purge.left.includes('rdap:expired.example') && purge.left.includes('rdap:fresh.example'),
        `保存期限: 期限切れの記録だけを削除（残り: ${purge && purge.left.join(', ')}）`);
    });

    await step('RDAP 無効化', async () => {
      // ポップアップと同じ経路（runtime.sendMessage）で RDAP をオフにする
      await getJson(`/json/new?chrome-extension://${swTarget.url.split('/')[2]}/popup.html`, 'PUT');
      await sleep(1500);
      const popupTarget = (await getJson('/json/list')).find((t) => t.type === 'page' && t.url.endsWith('/popup.html'));
      const popup = cdp(popupTarget.webSocketDebuggerUrl);
      await popup.ready;
      await popup.send('Runtime.evaluate', {
        expression: `chrome.runtime.sendMessage({ type: 'setSettings', settings: { rdap: false } })`, awaitPromise: true,
      });
      popup.close();
      const afterOff = await evalInWorker(worker, `
        chrome.storage.local.get(null).then((all) => Object.keys(all).filter((k) => k.startsWith('rdap')))`);
      check(afterOff && afterOff.length === 0, `RDAP をオフにすると照会結果をすべて削除（残り ${afterOff && afterOff.length} 件）`);
    });

    // ---- 7. 回帰: 照会中に RDAP をオフにした場合、遅れて届いた応答をキャッシュに保存しない ----
    // 「照会開始 → 設定オフ（キャッシュ削除）→ 遅延応答」の順。照会は偽物に差し替え、外部には問い合わせない
    await step('回帰: 照会中の無効化', async () => {
      await evalInWorker(worker, `
        (async () => {
          await chrome.storage.local.set({ settings: { rdap: true } });
          getBootstrap = async () => ({ example: 'https://rdap.invalid/' });
          SiteRiskRdap.lookupRegistration = () => new Promise((r) =>
            setTimeout(() => r({ status: 'ok', registered: '2026-10-01T00:00:00Z' }), 3000));
          getDomainInfo('inflight.example'); // 応答を待たずに次へ（照会中の状態を作る）
          return true;
        })()`);
      await sleep(500);
      const popupTarget = (await getJson('/json/list')).find((t) => t.type === 'page' && t.url.endsWith('/popup.html'));
      const popup = cdp(popupTarget.webSocketDebuggerUrl);
      await popup.ready;
      await popup.send('Runtime.evaluate', {
        expression: `chrome.runtime.sendMessage({ type: 'setSettings', settings: { rdap: false } })`, awaitPromise: true,
      });
      popup.close();
      await sleep(4000); // 遅延応答（3秒）が届くのを待つ
      const left = await evalInWorker(worker, `
        chrome.storage.local.get(null).then((all) => Object.keys(all).filter((k) => k.startsWith('rdap')))`);
      check(left && left.length === 0, `回帰: 照会中に RDAP をオフ → 遅れて届いた応答を保存しない（残り: ${left && (left.join(', ') || 'なし')}）`);
    });

    worker.close();
    exitCode = ok ? 0 : 1;
    console.log(ok ? '\nE2E: すべて成功' : '\nE2E: 失敗あり');
  } catch (e) {
    console.error('E2E エラー: ' + e.message);
  } finally {
    browser.kill();
    server.close();
    await sleep(1500);
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch (_) {}
    process.exit(exitCode);
  }
})();
