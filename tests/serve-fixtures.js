/**
 * テスト用の模擬ページ（tests/fixtures/）をローカルでのみ配信する簡易サーバー。
 * 127.0.0.1 にだけ待ち受けるので、外部からはアクセスできない。
 *
 * 使い方: node tests/serve-fixtures.js [port]
 *   → http://127.0.0.1:8787/fake-shop.html / http://127.0.0.1:8787/legit-shop.html
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, 'fixtures');
const PORT = Number(process.argv[2]) || 8787;

const server = http.createServer((req, res) => {
  const name = path.basename(decodeURIComponent(new URL(req.url, 'http://x').pathname)) || 'index.html';
  const file = path.join(ROOT, name);
  if (!file.startsWith(ROOT) || !fs.existsSync(file)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('not found');
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  fs.createReadStream(file).pipe(res);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`http://127.0.0.1:${PORT}/fake-shop.html`);
  console.log(`http://127.0.0.1:${PORT}/legit-shop.html`);
});
