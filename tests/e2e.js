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
const PHISH_HOST = 'portal.sitechecker-test.net'; // 模擬フィッシングページ用の名前（ブラウザ内で 127.0.0.1 に向ける）
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
    `--host-resolver-rules=MAP ${SLOW_HOST} 127.0.0.1,MAP ${PHISH_HOST} 127.0.0.1`,
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
            return { url: t.url, badge: await chrome.action.getBadgeText({ tabId: t.id }), title: await chrome.action.getTitle({ tabId: t.id }), score: r.score, level: r.level };
          })))`);
      const fake = rows.find((r) => r.url.includes('fake-shop'));
      const legit = rows.find((r) => r.url.includes('legit-shop'));
      check(fake && fake.level === 'danger' && fake.badge === '危険', `偽通販の模擬ページ → 危険バッジ（${fake && fake.score}点、バッジ「${fake && fake.badge}」）`);
      check(fake && fake.title.includes(`リスクスコア ${fake.score}点`) && !fake.title.includes('%'), 'ツールバーの説明をリスクスコア・点で表示');
      check(legit && legit.level === 'safe' && legit.badge === '', `正規通販の模擬ページ → バッジなし（${legit && legit.score}点）`);
    });

    await step('動的ブラックリスト', async () => {
      const feed = fs.readFileSync(path.join(__dirname, '..', 'docs', 'feed', 'blocklist.json'), 'utf8');
      const result = await evalInWorker(worker, `(async () => {
        const originalFetch = self.fetch;
        const body = ${JSON.stringify(feed)};
        self.fetch = (input, options) => String(input) === BLOCKLIST_FEED_URL
          ? Promise.resolve(new Response(body, { headers: { 'Content-Type': 'application/json' } }))
          : originalFetch(input, options);
        try {
          await refreshDynamicBlocklist(true);
          return { count: blocklistSet.size, source: blocklistInfo.source, generatedAt: blocklistInfo.generatedAt };
        } finally { self.fetch = originalFetch; }
      })()`);
      const expected = JSON.parse(feed);
      check(result && result.count === expected.count && result.source === 'dynamic' &&
        result.generatedAt === expected.generatedAt, '配信フィードを検証・保存して、動的ブラックリストへ切り替える');
    });

    // ---- 2. 手動チェック（popup → background の 'analyze' と同じ経路） ----
    await step('手動チェック', async () => {
      const manual = await evalInWorker(worker, `
        Promise.all(['https://xqzvt.rest/index.php?main_page=product_info&zenid=abc', 'https://www.amazon.co.jp/']
          .map((u) => evaluate(u).then((r) => ({ url: u, score: r.score, level: r.level, rdap: r.rdapStatus,
            blocklistSource: r.blocklistDataSource, blocklistDate: r.blocklistDataDate }))))`);
      check(manual[0].level === 'danger', `手動チェック: 詐欺キットURL → 危険（${manual[0].score}点）`);
      check(manual[1].score === 0, '手動チェック: amazon.co.jp → 0点');
      check(manual[0].rdap === 'disabled', `RDAP は初期設定でオフ（${manual[0].rdap}）`);
      check(['bundled', 'dynamic'].includes(manual[0].blocklistSource) && !!manual[0].blocklistDate,
        'ブラックリストの適用元と更新日を判定結果に含める');
    });

    await step('公表履歴の照合', async () => {
      const history = await evalInWorker(worker, `(async () => {
        const catalog = await getThreatCatalog();
        const sample = 'https://inuclo.com/wp-includes/assets/netflix/login.html';
        const matched = await evaluate(sample);
        const unrelated = await evaluate(new URL('/sitechecker-unrelated-fixture', sample).href);
        const ccj = await evaluate('https://cpi.reduceee.ink/product');
        const caa = await evaluate('https://fest.andster.rest/product');
        return { total: catalog.recordCount, sample, status: matched.threatDataStatus,
          count: matched.knownThreats.length, source: matched.knownThreats[0]?.source.name,
          score: matched.score, unrelated: unrelated.knownThreats.length,
          ccj: ccj.knownThreats.some((m) => m.source.id.startsWith('ccj:')),
          caa: caa.knownThreats.some((m) => m.source.id.startsWith('caa:')) };
      })()`);
      check(history && history.total > 100000 && history.status === 'ok' && history.count > 0 &&
        history.source.includes('JPCERT') && history.score >= 40, '同梱JPCERT URLを端末内で照合（対象サイトへのアクセスなし）');
      check(history && history.unrelated === 0, '同じホストの別ページにはJPCERT履歴を適用しない');
      check(history && history.ccj && history.caa, 'CCJ・消費者庁の掲載ホストを照合');
    });

    await step('公表履歴の破損時', async () => {
      const unavailable = await evalInWorker(worker, `(async () => {
        const originalFetch = self.fetch;
        threatShardCache.clear();
        self.fetch = (input, options) => String(input).includes('/threat-shards/')
          ? Promise.resolve(new Response('{}')) : originalFetch(input, options);
        try { return (await evaluate('https://cpi.reduceee.ink/product')).threatDataStatus; }
        finally { self.fetch = originalFetch; threatShardCache.clear(); }
      })()`);
      check(unavailable === 'unavailable', '分割データの破損は照合不能として扱う');
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
      const display = await popup.send('Runtime.evaluate', {
        expression: `(async () => {
          document.getElementById('checkInput').value = 'https://www.amazon.co.jp/';
          document.getElementById('checkForm').requestSubmit();
          for (let i = 0; i < 30; i++) {
            if (document.querySelector('#manualResult .score')) break;
            await new Promise((r) => setTimeout(r, 100));
          }
          return {
            unit: document.querySelector('#manualResult .num small')?.textContent,
            text: document.getElementById('manualResult').innerText,
            note: document.querySelector('.note').innerText,
          };
        })()`, awaitPromise: true, returnByValue: true,
      });
      const ui = display.result && display.result.result && display.result.result.value;
      check(ui && ui.unit === '点' && ui.text.includes('リスクスコア') && ui.text.includes('判定除外') && !ui.text.includes('信頼済み') && ui.note.includes('詐欺である確率ではありません'),
        'ポップアップ: 点数・判定除外・確率ではない旨を表示');
      // RDAPの減点だけを「軽微なリスク」と表示しない。対象サイトは開かない。
      await evalInWorker(worker, `(async () => {
        self.__displayGetDomainInfo = getDomainInfo;
        getDomainInfo = async () => ({ status: 'ok', registered: '1997-09-15T00:00:00Z' });
        await chrome.storage.local.set({ settings: { rdap: true, phishing: false } });
      })()`);
      try {
        const riskDisplay = await popup.send('Runtime.evaluate', {
          expression: `(async () => {
            const results = [];
            for (const url of ['https://www.google.com/search?q=fixture', 'http://www.google.com/search?q=fixture']) {
              document.getElementById('manualResult').replaceChildren();
              document.getElementById('checkInput').value = url;
              document.getElementById('checkForm').requestSubmit();
              for (let i = 0; i < 50; i++) {
                if (document.querySelector('#manualResult .score')) break;
                await new Promise((r) => setTimeout(r, 100));
              }
              results.push({ score: document.querySelector('#manualResult .num')?.firstChild?.textContent,
                verdict: document.querySelector('#manualResult .verdict')?.textContent,
                reasons: document.querySelector('#manualResult .reasons')?.innerText });
            }
            return results;
          })()`, awaitPromise: true, returnByValue: true,
        });
        const displays = riskDisplay.result?.result?.value;
        check(displays?.[0]?.score === '0' && displays[0].verdict.includes('目立ったリスク要因は検出されませんでした') &&
          displays[0].reasons.includes('-20'), '回帰: 減点だけのGoogle検索URLは0点・リスク要因なしと表示');
        check(displays?.[1]?.score === '0' && displays[1].verdict.includes('軽微なリスク要因') &&
          displays[1].reasons.includes('http'), '回帰: 減点で0点になっても実際の加点要因は表示');
      } finally {
        await evalInWorker(worker, `(async () => {
          getDomainInfo = self.__displayGetDomainInfo;
          await chrome.storage.local.set({ settings: { rdap: false, phishing: false } });
        })()`);
      }
      const historyDisplay = await popup.send('Runtime.evaluate', {
        expression: `(async () => {
          document.getElementById('manualResult').replaceChildren();
          document.getElementById('checkInput').value = 'https://cpi.reduceee.ink/product';
          document.getElementById('checkForm').requestSubmit();
          for (let i = 0; i < 50; i++) {
            if (document.querySelector('#manualResult .score')) break;
            await new Promise((r) => setTimeout(r, 100));
          }
          return { text: document.getElementById('manualResult').innerText,
            links: [...document.querySelectorAll('#manualResult a')].map((a) => a.href) };
        })()`, awaitPromise: true, returnByValue: true,
      });
      const historyUi = historyDisplay.result?.result?.value;
      check(historyUi && historyUi.text.includes('現在の状態は未確認') && historyUi.text.includes('商品未着') &&
        historyUi.links.some((href) => href.startsWith('https://www.kokusen.go.jp/')) &&
        historyUi.links.every((href) => !href.includes('cpi.reduceee.ink')), 'ポップアップ: 公表履歴・区分・公表元リンクを表示');
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
          self.__realGetBootstrap = getBootstrap; // 後で元に戻す
          self.__realLookup = SiteRiskRdap.lookupRegistration;
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
      await evalInWorker(worker, `getBootstrap = self.__realGetBootstrap; SiteRiskRdap.lookupRegistration = self.__realLookup; bootstrapPromise = null; true`);
    });

    // ======== フィッシングの追加チェック ========
    // 模擬フィッシングページは PHISH_HOST（ブラウザ内で 127.0.0.1 に向けた名前）で配信する
    const phishUrl = `http://${PHISH_HOST}:${FIXTURE_PORT}/phish-login.html`;
    const popupPage = async () => {
      const t = (await getJson('/json/list')).find((x) => x.type === 'page' && x.url.endsWith('/popup.html'));
      const c = cdp(t.webSocketDebuggerUrl);
      await c.ready;
      return c;
    };
    const setSetting = async (settings) => {
      const c = await popupPage();
      await c.send('Runtime.evaluate', {
        expression: `chrome.runtime.sendMessage({ type: 'setSettings', settings: ${JSON.stringify(settings)} })`, awaitPromise: true,
      });
      c.close();
    };
    const pageTarget = async (pred) => {
      const t = (await getJson('/json/list')).find((x) => x.type === 'page' && pred(x.url));
      const c = cdp(t.webSocketDebuggerUrl);
      await c.ready;
      return c;
    };
    const phishState = (match) => evalInWorker(worker, `
      (async () => {
        const tabs = await chrome.tabs.query({});
        const t = tabs.find((t) => (t.url || '').includes('${match}'));
        if (!t) return null;
        const r = await evaluate(t.url, t.id);
        const keys = Object.keys(await chrome.storage.session.get(null)).filter((k) => k.startsWith('phish:'));
        return { badge: await chrome.action.getBadgeText({ tabId: t.id }), base: r.level, phishing: r.phishing, keys };
      })()`);

    await step('フィッシング: 初期状態はオフ', async () => {
      const s = await evalInWorker(worker, `getSettings()`);
      check(s.phishing === false, `初期設定でオフ（phishing=${s.phishing}）`);
      await getJson(`/json/new?${phishUrl}`, 'PUT');
      await sleep(4000);
      const st = await phishState('phish-login');
      check(st && st.badge === '' && st.phishing === null && st.keys.length === 0,
        `オフ: 模擬フィッシングページでも追加解析をしない（バッジ「${st && st.badge}」、保存 ${st && st.keys.length} 件）`);
    });

    await step('フィッシング: オンにすると開いているタブに反映', async () => {
      await setSetting({ phishing: true });
      await sleep(4000);
      const st = await phishState('phish-login');
      check(st && st.badge === '危険' && st.phishing && st.phishing.level === 'danger',
        `オン: 再読み込みなしで既存タブが「危険」（${st && st.phishing && st.phishing.score}点、バッジ「${st && st.badge}」）`);
      const rules = st && st.phishing ? st.phishing.reasons.map((r) => r.detail.slice(0, 20)).join(' / ') : '';
      check(st && st.phishing && st.phishing.reasons.length >= 3, `根拠を表示: ${rules}`);
      check(st && st.base === 'safe', `既存の偽通販判定とは別に採点（既存判定: ${st && st.base}）`);
    });

    await step('フィッシング: 正規ページを誤検知しない', async () => {
      for (const p of ['legit-login.html', 'legit-checkout.html', 'news-article.html']) await getJson(`/json/new?${base}/${p}`, 'PUT');
      await sleep(4500);
      for (const p of ['legit-login', 'legit-checkout', 'news-article']) {
        const st = await phishState(p);
        check(st && st.badge === '' && st.phishing && st.phishing.level === 'none',
          `誤検知なし: ${p}（${st && st.phishing ? st.phishing.score + '点' : '結果なし'}、バッジ「${st && st.badge}」）`);
      }
    });

    await step('フィッシング: 入力値を取得・保存しない', async () => {
      await evalInWorker(worker, `
        self.__lastPhishingDesc = '';
        self.__realHandlePhishingScan = handlePhishingScan;
        handlePhishingScan = (tabId, url, desc) => { self.__lastPhishingDesc += JSON.stringify(desc); return self.__realHandlePhishingScan(tabId, url, desc); };
        true`);
      const pg = await pageTarget((u) => u.includes('phish-login'));
      await pg.send('Runtime.evaluate', { expression: `
        document.querySelector('input[name=userid]').value = 'SECRET-USER-777';
        document.querySelector('input[type=password]').value = 'SECRET-PW-123';
        document.querySelector('input[name=cardnumber]').value = '4111111111111111';
        document.body.appendChild(document.createElement('h2')).textContent = '再解析のきっかけ（見出しを追加）';
        true` });
      pg.close();
      await sleep(3000);
      const leaked = await evalInWorker(worker, `
        (async () => {
          const stored = JSON.stringify(await chrome.storage.session.get(null)) + JSON.stringify(await chrome.storage.local.get(null));
          const seen = self.__lastPhishingDesc;
          handlePhishingScan = self.__realHandlePhishingScan;
          return { received: seen.length, hit: ['SECRET-USER-777', 'SECRET-PW-123', '4111111111111111'].filter((s) => stored.includes(s) || seen.includes(s)) };
        })()`);
      check(leaked && leaked.received > 0 && leaked.hit.length === 0,
        `入力値を拡張機能に渡さず保存もしない（受信した抽出結果 ${leaked && leaked.received} 文字、入力値の混入 ${leaked && leaked.hit.length} 件）`);
    });

    await step('フィッシング: オフにすると追加警告が消え、既存の警告は残る', async () => {
      await setSetting({ phishing: false });
      await sleep(2500);
      const st = await phishState('phish-login');
      const fakeShop = await badgeOf("(u) => /127\\.0\\.0\\.1:8787\\/fake-shop\\.html$/.test(u)");
      check(st && st.badge === '' && st.keys.length === 0, `オフ: 追加警告と保存結果を削除（バッジ「${st && st.badge}」、保存 ${st && st.keys.length} 件）`);
      check(fakeShop && fakeShop.badge === '危険', `オフ: 既存の偽通販警告は保持（バッジ「${fakeShop && fakeShop.badge}」）`);
    });

    await step('フィッシング: 処理中にオフにした結果を反映しない', async () => {
      await evalInWorker(worker, `
        self.__realScorePhishing = scorePhishing;
        scorePhishing = (desc) => new Promise((r) => setTimeout(() => r(self.__realScorePhishing(desc)), 3000));
        true`);
      await setSetting({ phishing: true }); // 有効化 → 開いているタブが抽出結果を送る（採点は3秒遅延）
      await sleep(800);
      await setSetting({ phishing: false }); // 採点の途中で無効化
      await sleep(4000);
      const st = await phishState('phish-login');
      check(st && st.badge === '' && st.keys.length === 0, `処理中にオフ → 遅れた結果を反映・保存しない（バッジ「${st && st.badge}」、保存 ${st && st.keys.length} 件）`);
      await evalInWorker(worker, `scorePhishing = self.__realScorePhishing; true`);
    });

    await step('フィッシング: オン→オフ→オンの切り替え', async () => {
      await setSetting({ phishing: true });
      await setSetting({ phishing: false });
      await setSetting({ phishing: true });
      await sleep(4000);
      const st = await phishState('phish-login');
      check(st && st.badge === '危険' && st.phishing && st.phishing.level === 'danger', `最終状態（オン）の結果だけを表示（バッジ「${st && st.badge}」）`);
    });

    await step('フィッシング: ページ遷移後に古い結果を反映しない', async () => {
      await evalInWorker(worker, `
        chrome.tabs.query({}).then((tabs) => {
          const t = tabs.find((t) => (t.url || '').includes('phish-login'));
          return chrome.tabs.update(t.id, { url: '${base}/legit-login.html?navigated' });
        }).then(() => true)`);
      await sleep(4000);
      const st = await phishState('legit-login.html?navigated');
      check(st && st.badge === '' && st.phishing && st.phishing.level === 'none', `遷移後のページには遷移前の結果を使わない（バッジ「${st && st.badge}」）`);
    });

    await step('フィッシング: SPA と遅延描画に追随', async () => {
      await getJson(`/json/new?http://${PHISH_HOST}:${FIXTURE_PORT}/spa-phish.html`, 'PUT');
      await sleep(4000);
      const early = await phishState('spa-signin.html');
      check(early && early.badge === '', `URL 変更直後（フォーム描画前）→ 警告なし（バッジ「${early && early.badge}」）`);
      await sleep(7000);
      const st = await phishState('spa-signin.html');
      check(st && st.badge === '危険', `URL 変更後に遅れて描画されたフォーム → 危険（${st && st.phishing && st.phishing.score}点、バッジ「${st && st.badge}」）`);
      await setSetting({ phishing: false });
    });

    // ---- 回帰: 追加チェックの採点の完了順が逆転しても、古い結果で新しい結果を上書きしない ----
    await step('回帰: 採点の完了順の逆転', async () => {
      await setSetting({ phishing: true });
      await sleep(2500);
      const r = await evalInWorker(worker, `
        (async () => {
          const tabs = await chrome.tabs.query({});
          const t = tabs.find((t) => (t.url || '').includes('spa-signin.html'));
          self.__realScorePhishing2 = scorePhishing;
          // 古い抽出結果（OLD）の採点だけを3秒遅らせ、新しい抽出結果（NEW）より後に完了させる
          scorePhishing = (desc) => new Promise((res) => setTimeout(() => res(self.__realScorePhishing2(desc)), desc.title === 'OLD' ? 3000 : 100));
          const sensitive = { fieldKinds: ['password', 'card'], action: 'http://harvest.other-domain.example/x', formActions: [], contextText: 'Microsoft サインイン', logoAlts: [] };
          handlePhishingScan(t.id, t.url, { title: 'OLD', headings: [], forms: [sensitive], threat: { threat: true, deadline: true }, linkPairs: [], legal: { total: 0, empty: 0 } });
          await new Promise((s) => setTimeout(s, 50));
          handlePhishingScan(t.id, t.url, { title: 'NEW', headings: [], forms: [], threat: { threat: false, deadline: false }, linkPairs: [], legal: { total: 0, empty: 0 } });
          await new Promise((s) => setTimeout(s, 4000));
          scorePhishing = self.__realScorePhishing2;
          const stored = (await chrome.storage.session.get('phish:' + t.id))['phish:' + t.id];
          return { level: stored && stored.result.level, score: stored && stored.result.score, badge: await chrome.action.getBadgeText({ tabId: t.id }) };
        })()`);
      check(r && r.level === 'none' && r.badge === '',
        `回帰: 後から完了した古い採点で、新しい結果を上書きしない（保存: ${r && r.level} ${r && r.score}点、バッジ「${r && r.badge}」）`);
      await setSetting({ phishing: false });
    });

    // ---- 回帰: IANA の RDAP サーバー一覧の取得中に RDAP をオフにした場合、一覧を保存しない ----
    await step('回帰: RDAP 一覧の取得中の無効化', async () => {
      await evalInWorker(worker, `
        (async () => {
          await chrome.storage.local.set({ settings: { rdap: true } });
          await chrome.storage.local.remove('rdapBootstrap');
          bootstrapPromise = null;
          self.__realFetchBootstrap = SiteRiskRdap.fetchBootstrap;
          SiteRiskRdap.fetchBootstrap = () => new Promise((r) => setTimeout(() => r({ com: 'https://rdap.invalid/' }), 3000));
          getBootstrap().catch(() => {}); // 取得を開始し、完了を待たずに次へ
          return true;
        })()`);
      await sleep(500);
      await setSetting({ rdap: false });
      await sleep(4000);
      const left = await evalInWorker(worker, `
        (async () => {
          SiteRiskRdap.fetchBootstrap = self.__realFetchBootstrap;
          return Object.keys(await chrome.storage.local.get(null)).filter((k) => k.startsWith('rdap'));
        })()`);
      check(left && left.length === 0, `回帰: 一覧の取得中に RDAP をオフ → 遅れて届いた一覧を保存しない（残り: ${left && (left.join(', ') || 'なし')}）`);
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
