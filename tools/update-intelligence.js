/** 定期データ生成。Node 22.16以降 + Python/pypdf。掲載された危険サイト自体には接続しない。 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
require('../threat-data.js');
require('../detector.js');
const ROOT = path.join(__dirname, '..');
const WORK = path.join(ROOT, 'dist', 'intelligence');
const CACHE = path.join(WORK, 'cache');
const OFFLINE = process.argv.includes('--offline');
const HAGEZI = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt';
const TREE = 'https://api.github.com/repos/JPCERTCC/phishurl-list/git/trees/main?recursive=1';
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function isValidIsoDate(value) {
  const match = typeof value === 'string' && value.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return false;
  const year = Number(match[1]), month = Number(match[2]), day = Number(match[3]);
  const date = new Date(0);
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCFullYear(year, month - 1, day);
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function parseCsv(text) {
  const rows = []; let row = [], field = '', quoted = false;
  text = text.replace(/^\uFEFF/, '');
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      if (quoted && text[i + 1] === '"') { field += '"'; i++; }
      else if (quoted || field === '') quoted = !quoted;
      else throw new Error('CSVの引用符が不正です');
    } else if (c === ',' && !quoted) { row.push(field); field = ''; }
    else if ((c === '\n' || c === '\r') && !quoted) {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); if (row.some((value) => value.trim())) rows.push(row); row = []; field = '';
    } else field += c;
  }
  if (quoted) throw new Error('CSVの引用符が閉じていません');
  if (field || row.length) { row.push(field); if (row.some((value) => value.trim())) rows.push(row); }
  return rows;
}

function parseJpcert(text) {
  const rows = parseCsv(text);
  if (rows.shift()?.join(',') !== 'date,URL,description') throw new Error('JPCERTのCSVヘッダーが変わりました');
  return rows.map((row) => {
    if (row.length !== 3) throw new Error('JPCERTのCSV列数が不正です');
    const date = row[0].match(/^(\d{4})\/(\d{2})\/(\d{2})(?:\s|$)/);
    if (!date && row[0].trim()) throw new Error('JPCERTの確認日が不正です');
    if (date && !isValidIsoDate(`${date[1]}-${date[2]}-${date[3]}`)) throw new Error('JPCERTの確認日が不正です');
    // 元データに確認日が空欄のレコードがある。推測の日付を補わず空欄のまま保存する。
    return { scope: 'url', target: row[1], date: date ? `${date[1]}-${date[2]}-${date[3]}` : '',
      description: row[2], status: 'not_checked' };
  });
}

function validateRecord(record) {
  const canonical = SiteRiskThreatData.canonicalUrl(record.target);
  if (!canonical) throw new Error(`不正な対象URL: ${String(record.target).slice(0, 120)}`);
  const u = new URL(canonical);
  if ((!u.hostname.includes('.') && !u.hostname.startsWith('[')) || /^(localhost|127\.|10\.|192\.168\.)/.test(u.hostname)) throw new Error('対象ホストが不正です');
  const key = record.scope === 'host' ? u.hostname : canonical;
  if (!['host', 'url'].includes(record.scope) || !(record.date === '' ||
      isValidIsoDate(record.date)) ||
      !['not_checked', 'closed_by_source'].includes(record.status)) {
    throw new Error('対象レコードの形式が不正です');
  }
  return { ...record, key };
}

async function download(url, expectedGitSha) {
  const prefix = path.join(CACHE, sha256(url));
  const bodyPath = prefix + '.bin', metaPath = prefix + '.json';
  let previous = null;
  if (fs.existsSync(metaPath) && !fs.existsSync(bodyPath)) {
    const error = new Error(`取得キャッシュが削除・隔離されています。自動で復元しません: ${bodyPath}`);
    error.code = 'CACHE_REMOVED'; throw error;
  }
  if (fs.existsSync(bodyPath) && fs.existsSync(metaPath)) {
    previous = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    let cachedBytes;
    try { cachedBytes = fs.readFileSync(bodyPath); }
    catch (cause) {
      const error = new Error(`取得キャッシュを読み取れません。再取得しません: ${bodyPath} (${cause.code})`);
      error.code = 'CACHE_UNREADABLE'; throw error;
    }
    if (sha256(cachedBytes) !== previous.sha256) throw new Error('取得キャッシュのハッシュが一致しません');
  }
  if (OFFLINE || (expectedGitSha && previous?.gitSha === expectedGitSha)) {
    if (!previous) throw new Error(`オフライン用キャッシュがありません: ${url}`);
    return { bytes: fs.readFileSync(bodyPath), path: bodyPath, meta: previous };
  }
  let response;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      response = await fetch(url, { headers: { 'User-Agent': 'SiteChecker-data-builder',
        ...(previous?.etag ? { 'If-None-Match': previous.etag } : {}) }, signal: AbortSignal.timeout(60000) });
      if (response.status === 304 && previous) {
        if (expectedGitSha && previous.gitSha !== expectedGitSha) throw new Error('GitHubの公開SHAとキャッシュが一致しません');
        return { bytes: fs.readFileSync(bodyPath), path: bodyPath, meta: previous };
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      break;
    } catch (e) {
      if (attempt === 2) throw new Error(`${url}: ${e.message}`);
      await new Promise((resolve) => setTimeout(resolve, 1000 * (attempt + 1)));
    }
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > 40 * 1024 * 1024) throw new Error('取得サイズが不正です');
  if (expectedGitSha) {
    const gitSha = crypto.createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    if (gitSha !== expectedGitSha) throw new Error('GitHubの公開SHAと取得内容が一致しません。再実行してください');
  }
  const meta = { url, sha256: sha256(bytes), gitSha: expectedGitSha || null,
    fetchedAt: new Date().toISOString(), etag: response.headers.get('etag') };
  fs.writeFileSync(bodyPath, bytes);
  fs.writeFileSync(metaPath, JSON.stringify(meta));
  return { bytes, path: bodyPath, meta };
}

function pdfLinks(html, pageUrl) {
  const links = [];
  for (const match of html.matchAll(/href\s*=\s*["']([^"']+)["']/gi)) {
    const url = new URL(match[1].trim().replace(/&amp;/g, '&'), pageUrl);
    if (url.hostname === new URL(pageUrl).hostname && url.pathname.endsWith('.pdf')) links.push(url.href);
  }
  return [...new Set(links)];
}

async function officialSource(pageUrl, kind) {
  const page = await download(pageUrl);
  const links = pdfLinks(page.bytes.toString('utf8'), pageUrl);
  if (links.length !== 1) throw new Error(`${kind}: 対象PDFを一意に特定できません`);
  const pdf = await download(links[0]);
  const records = JSON.parse(execFileSync(process.env.SITECHECKER_PYTHON || 'python',
    [path.join(__dirname, 'extract-official.py'), kind, pdf.path], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }));
  return { id: kind + ':' + pageUrl, group: kind, name: kind === 'ccj' ? '国民生活センター CCJ' : '消費者庁',
    url: pageUrl, documentUrl: links[0], license: 'see_source_terms',
    sha256: pdf.meta.sha256, fetchedAt: pdf.meta.fetchedAt, records };
}

async function collectSources() {
  const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'intelligence-sources.json'), 'utf8'));
  const sources = [];
  const excludedCsvs = [];
  const fake = await download(HAGEZI);
  const domains = [...new Set(fake.bytes.toString('utf8').split(/\r?\n/).map((s) => s.trim().toLowerCase())
    .filter((s) => s && !s.startsWith('#') && /^(?:[a-z0-9-]+\.)+[a-z0-9-]+$/.test(s)))];
  if (domains.length < 1000) throw new Error('HaGeZiの件数が少なすぎます');
  sources.push({ id: 'hagezi', group: 'hagezi', name: 'HaGeZi Fake', url: HAGEZI, license: 'GPL-3.0',
    sha256: fake.meta.sha256, fetchedAt: fake.meta.fetchedAt, records: domains.map((host) => ({ scope: 'host',
      target: 'https://' + host, date: fake.meta.fetchedAt.slice(0, 10), description: '偽ショップ・詐欺サイト', status: 'not_checked' })) });
  const tree = JSON.parse((await download(TREE)).bytes.toString('utf8'));
  if (tree.truncated || !Array.isArray(tree.tree)) throw new Error('GitHubの一覧が不完全です');
  const csvs = tree.tree.filter((item) => /^\d{4}\/\d{6}\.csv$/.test(item.path));
  if (csvs.length < 12) throw new Error('JPCERTのCSV一覧が少なすぎます');
  console.log(`JPCERT: ${csvs.length} CSVを取得（変更のないファイルはキャッシュを使用）`);
  // 最大4並列。各ファイルのSHAを検証してから解析する。
  let cursor = 0;
  const downloads = await Promise.allSettled(Array.from({ length: 4 }, async () => {
    while (cursor < csvs.length) {
      const item = csvs[cursor++];
      const url = 'https://raw.githubusercontent.com/JPCERTCC/phishurl-list/main/' + item.path;
      let csv;
      try { csv = await download(url, item.sha); }
      catch (error) {
        if (!['CACHE_REMOVED', 'CACHE_UNREADABLE'].includes(error.code)) throw error;
        excludedCsvs.push({ path: item.path, reason: error.code });
        console.warn(`JPCERT ${item.path}: 削除・隔離されたキャッシュを除外（再取得なし）`);
        continue;
      }
      sources.push({ id: 'jpcert:' + item.path, group: 'jpcert', name: 'JPCERT/CC phishurl-list',
        url: 'https://github.com/JPCERTCC/phishurl-list/blob/main/' + item.path,
        license: 'not_specified', sha256: csv.meta.sha256, fetchedAt: csv.meta.fetchedAt,
        records: parseJpcert(csv.bytes.toString('utf8')) });
    }
  }));
  for (const result of downloads) if (result.status === 'rejected') throw result.reason;
  sources.push(await officialSource(config.ccjPage, 'ccj'));
  for (const pageUrl of config.caaNotices) sources.push(await officialSource(pageUrl, 'caa'));
  if (!sources.some((s) => s.group === 'jpcert')) throw new Error('JPCERTの全CSVが除外されたため更新を中止します');
  return { sources: sources.sort((a, b) => a.id.localeCompare(b.id)), excludedCsvs: excludedCsvs.sort((a, b) => a.path.localeCompare(b.path)) };
}

function buildDatabase(sources, destination, now) {
  const db = new DatabaseSync(destination);
  try {
    db.exec(`CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, source_group TEXT NOT NULL,
      name TEXT NOT NULL, url TEXT NOT NULL, license TEXT NOT NULL, sha256 TEXT NOT NULL,
      fetched_at TEXT NOT NULL, checked_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS records (source_id TEXT NOT NULL, scope TEXT NOT NULL, target TEXT NOT NULL,
      match_key TEXT NOT NULL, confirmed_date TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL,
      first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, active INTEGER NOT NULL,
      PRIMARY KEY(source_id,scope,match_key,confirmed_date));
      CREATE TABLE IF NOT EXISTS rejected_records (source_id TEXT NOT NULL, target TEXT NOT NULL,
      confirmed_date TEXT NOT NULL, description TEXT NOT NULL, error TEXT NOT NULL, last_seen TEXT NOT NULL,
      PRIMARY KEY(source_id,target,confirmed_date));
      CREATE INDEX IF NOT EXISTS records_match ON records(scope,match_key);`);
    db.exec('BEGIN; UPDATE records SET active=0;');
    const sourceStmt = db.prepare('INSERT OR REPLACE INTO sources VALUES(?,?,?,?,?,?,?,?)');
    const rejectedStmt = db.prepare('INSERT OR REPLACE INTO rejected_records VALUES(?,?,?,?,?,?)');
    let rejected = 0, total = 0;
    const recordStmt = db.prepare(`INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?,1)
      ON CONFLICT(source_id,scope,match_key,confirmed_date) DO UPDATE SET
      target=excluded.target, description=excluded.description,status=excluded.status,last_seen=excluded.last_seen,active=1`);
    for (const source of sources) {
      sourceStmt.run(source.id, source.group, source.name, source.url, source.license, source.sha256, source.fetchedAt, now);
      for (const raw of source.records) {
        total++;
        let r;
        try { r = validateRecord(raw); }
        catch (error) {
          if (source.group !== 'jpcert') throw error;
          // 元CSVのURL誤記等は補正せず隔離保存し、配布用の照合から外す。
          rejectedStmt.run(source.id, raw.target, raw.date, raw.description, error.message, now);
          rejected++; continue;
        }
        recordStmt.run(source.id, r.scope, r.target, r.key, r.date, r.description, r.status, now, now);
      }
    }
    if (rejected > Math.max(10, total * 0.01)) throw new Error('不正レコードが多いため更新を中止します');
    db.exec('COMMIT;');
  } finally { db.close(); }
}

function createExports(dbPath, now) {
  const db = new DatabaseSync(dbPath);
  try {
    const sourceRows = db.prepare(`SELECT DISTINCT s.* FROM sources s JOIN records r ON r.source_id=s.id
      WHERE r.active=1 ORDER BY s.id`).all();
    const sources = sourceRows.filter((s) => s.source_group !== 'hagezi').map((s) => ({ id: s.id, name: s.name,
      url: s.url, license: s.license, fetchedAt: s.fetched_at }));
    const sourceIndex = new Map(sources.map((s, i) => [s.id, i]));
    // 同じ情報源・照合キーは最新の確認日と出典文書を配布。全履歴はSQLiteに保持。
    const records = db.prepare(`SELECT r.*,s.source_group FROM records r JOIN sources s ON r.source_id=s.id
      WHERE r.active=1 AND s.source_group<>'hagezi'
      ORDER BY s.source_group,r.scope,r.match_key,r.confirmed_date DESC,r.source_id DESC`).all();
    const exported = [], seen = new Set();
    for (const r of records) {
      const key = JSON.stringify([r.source_group, r.scope, r.match_key]);
      if (seen.has(key)) continue;
      seen.add(key);
      exported.push([r.scope, r.match_key, r.confirmed_date, sourceIndex.get(r.source_id), r.description, r.status]);
    }
    const domainRows = db.prepare(`SELECT DISTINCT match_key FROM records WHERE source_id='hagezi' AND active=1 ORDER BY match_key`).all();
    const domains = domainRows.map((r) => r.match_key).filter((d) => !SiteRiskDetector.analyze(d).whitelisted);
    const blocklist = [`# 詐欺サイトチェッカー 同梱ブラックリスト`, `# 出典: HaGeZi DNS Blocklists - Fake (${HAGEZI})`,
      '# ライセンス: GPL-3.0 (https://github.com/hagezi/dns-blocklists/blob/main/LICENSE)',
      `# 更新日: ${now.slice(0, 10)} 件数: ${domains.length}`, ...domains].join('\n') + '\n';
    const data = { schemaVersion: 1, generatedAt: now, sources, records: exported };
    SiteRiskThreatData.parse(data); // 実行時と同じスキーマ検証
    const hosts = new Set(), buckets = new Map();
    for (const row of exported) {
      const host = row[0] === 'host' ? row[1] : new URL(row[1]).hostname;
      const bucket = sha256(host).slice(0, 2);
      hosts.add(host);
      if (!buckets.has(bucket)) buckets.set(bucket, []);
      buckets.get(bucket).push(row);
    }
    const shards = [...buckets].sort(([a], [b]) => a.localeCompare(b)).map(([bucket, records]) =>
      [bucket, JSON.stringify({ generatedAt: now, records })]);
    const catalog = { schemaVersion: 1, generatedAt: now, sources, recordCount: exported.length, bucketHash: 'sha256-host-8bit',
      shards: Object.fromEntries(shards.map(([bucket, text]) => [bucket, { bytes: Buffer.byteLength(text), sha256: sha256(text) }])) };
    const counts = db.prepare(`SELECT s.source_group AS source,COUNT(*) AS records,MAX(r.confirmed_date) AS latestDate,
      SUM(r.confirmed_date='') AS missingDates,SUM(r.status='closed_by_source') AS closedBySource
      FROM records r JOIN sources s ON s.id=r.source_id WHERE r.active=1 GROUP BY s.source_group`).all();
    return { blocklist, json: JSON.stringify(data), catalog: JSON.stringify(catalog), shards,
      report: { generatedAt: now, offline: OFFLINE, counts,
      runtimeRecords: exported.length, hageziDomains: domains.length,
      runtimeHosts: hosts.size, shardCount: shards.length,
      rejectedRecords: db.prepare('SELECT COUNT(*) AS n FROM rejected_records WHERE last_seen=?').get(now).n,
      reachability: 'not_checked; closed_by_source is preserved', jpcertLicense: 'not_specified' } };
  } finally { db.close(); }
}

// 出力を一式準備してから置換。途中失敗時は既存データを復元する。
function publishFiles(files) {
  const backups = files.map(([target]) => [target, fs.existsSync(target) ? fs.readFileSync(target) : null]);
  try {
    for (const [target, bytes] of files) { fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target + '.tmp', bytes); }
    for (const [target] of files) fs.renameSync(target + '.tmp', target);
  } catch (error) {
    for (const [target, bytes] of backups) {
      if (bytes === null) { if (fs.existsSync(target)) fs.unlinkSync(target); }
      else fs.writeFileSync(target, bytes);
    }
    throw error;
  } finally {
    for (const [target] of files) if (fs.existsSync(target + '.tmp')) fs.unlinkSync(target + '.tmp');
  }
}

async function main() {
  fs.mkdirSync(CACHE, { recursive: true });
  const lock = path.join(WORK, 'update.lock');
  const fd = fs.openSync(lock, 'wx');
  const stage = path.join(WORK, 'staged.sqlite');
  try {
    const { sources, excludedCsvs } = await collectSources();
    console.log('情報源の取得・抽出が完了。SQLiteと配布用データを生成します');
    const destination = path.join(WORK, 'intelligence.sqlite');
    if (fs.existsSync(stage)) fs.unlinkSync(stage);
    if (fs.existsSync(destination)) fs.copyFileSync(destination, stage);
    const now = new Date().toISOString();
    buildDatabase(sources, stage, now);
    const result = createExports(stage, now);
    result.report.excludedCsvs = excludedCsvs;
    result.report.runtimeBytes = Buffer.byteLength(result.json);
    result.report.runtimeSha256 = sha256(result.json);
    result.report.catalogBytes = Buffer.byteLength(result.catalog);
    result.report.largestShardBytes = Math.max(...result.shards.map(([, text]) => Buffer.byteLength(text)));
    publishFiles([[destination, fs.readFileSync(stage)], [path.join(ROOT, 'data', 'blocklist.txt'), result.blocklist],
      [path.join(WORK, 'threat-history.json'), result.json],
      ...result.shards.map(([bucket, text]) => [path.join(ROOT, 'data', 'threat-shards', bucket + '.json'), text]),
      [path.join(ROOT, 'data', 'threat-catalog.json'), result.catalog],
      [path.join(WORK, 'report.json'), JSON.stringify(result.report, null, 2) + '\n']]);
    console.log(JSON.stringify(result.report, null, 2));
  } finally {
    if (fs.existsSync(stage)) fs.unlinkSync(stage);
    fs.closeSync(fd); fs.unlinkSync(lock);
  }
}

module.exports = { parseCsv, parseJpcert, validateRecord, pdfLinks, buildDatabase, createExports, publishFiles };
if (require.main === module) main().catch((e) => { console.error(e.message); process.exitCode = 1; });
