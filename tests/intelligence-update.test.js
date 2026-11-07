'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { parseJpcert, validateRecord, pdfLinks, buildDatabase, createExports, publishFiles } = require('../tools/update-intelligence.js');

test('CSVのカンマ・引用符・改行・欠損日付を正しく取り込む', () => {
  const rows = parseJpcert('date,URL,description\r\n2026/05/01 09:00:00,https://shop.example/login,"Brand, ""A""\nBank"\r\n ,https://shop.example/unknown,Other\r\n');
  assert.equal(rows.length, 2); assert.equal(rows[0].description, 'Brand, "A"\nBank');
  assert.equal(rows[1].date, '');
  assert.throws(() => parseJpcert('date,URL,description\nBAD,https://shop.example/,X'));
  for (const date of ['2026/02/29', '2026/02/31', '2026/04/31']) {
    assert.throws(() => parseJpcert(`date,URL,description\n${date},https://shop.example/,X`), /確認日/);
  }
  assert.equal(parseJpcert('date,URL,description\n2024/02/29,https://shop.example/,X')[0].date, '2024-02-29');
});
test('レコードの日付は実在する日付だけを受け付ける', () => {
  const record = { scope: 'url', target: 'https://shop.example/', date: '2026-02-31',
    description: 'test', status: 'not_checked' };
  assert.throws(() => validateRecord(record), /形式/);
  assert.equal(validateRecord({ ...record, date: '2024-02-29' }).date, '2024-02-29');
});
test('PDF取得は同じ公表元のリンクだけ。他サイトやナビゲーションを混ぜない', () => {
  assert.deepEqual(pdfLinks('<a href="../pdf/list.pdf">list</a><a href="https://evil.example/trap.pdf">x</a><a href="/help">help</a>',
    'https://www.kokusen.go.jp/data/page.html'), ['https://www.kokusen.go.jp/pdf/list.pdf']);
});
test('更新で削除された掲載は履歴を残して照合対象から外す。最新版だけを配布', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sitechecker-data-test-'));
  try {
    const dbPath = path.join(dir, 'test.sqlite');
    const source = { id: 'jpcert:202605', group: 'jpcert', name: 'JPCERT', url: 'https://github.com/JPCERTCC/phishurl-list',
      license: 'not_specified', sha256: 'test', fetchedAt: '2026-10-10', records: [
        { scope: 'url', target: 'https://shared.example/login', date: '2026-05-01', description: 'A', status: 'not_checked' },
        { scope: 'url', target: 'https://shared.example/login', date: '2026-05-02', description: 'A', status: 'not_checked' },
      ] };
    buildDatabase([source], dbPath, '2026-10-10');
    assert.equal(JSON.parse(createExports(dbPath, '2026-10-10').json).records[0][2], '2026-05-02');
    buildDatabase([{ ...source, records: [] }], dbPath, '2026-10-11');
    assert.equal(JSON.parse(createExports(dbPath, '2026-10-11').json).records.length, 0);
    const db = new DatabaseSync(dbPath);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM records').get().n, 2); db.close();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('誤記URLは隔離し、共有ホストに対する危険ドメインを推測で作らない', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sitechecker-rejected-test-'));
  try {
    const dbPath = path.join(dir, 'test.sqlite');
    buildDatabase([{ id: 'jpcert:test', group: 'jpcert', name: 'JPCERT', url: 'https://github.com/JPCERTCC/phishurl-list',
      license: 'not_specified', sha256: 'test', fetchedAt: '2026-10-10', records: [
        { scope: 'url', target: 'htps://137.220.233.40/', date: '2026-05-01', description: 'A', status: 'not_checked' },
      ] }], dbPath, '2026-10-10');
    const result = createExports(dbPath, '2026-10-10');
    assert.equal(result.report.rejectedRecords, 1);
    assert.equal(JSON.parse(result.json).records.length, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
test('出力の置換失敗時に既存データを復元する', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sitechecker-export-test-'));
  try {
    const good = path.join(dir, 'good.json'), bad = path.join(dir, 'directory');
    fs.writeFileSync(good, 'old'); fs.mkdirSync(bad);
    assert.throws(() => publishFiles([[good, 'new'], [path.join(bad, 'child'), Buffer.from('x')], [path.join(good, 'child'), 'fail']]));
    assert.equal(fs.readFileSync(good, 'utf8'), 'old');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
