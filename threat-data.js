/* 公表履歴の照合。共有ホストの他ページや親ドメインへ照合範囲を広げない。 */
(function (global) {
  'use strict';
  function canonicalUrl(input) {
    try {
      const url = new URL(input);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
      url.hostname = url.hostname.toLowerCase().replace(/\.$/, '');
      return url.href; // パス、クエリ、SPAのフラグメントを保持する
    } catch { return null; }
  }
  function parse(data) {
    if (data.schemaVersion !== 1 || !Array.isArray(data.sources) || !Array.isArray(data.records)) {
      throw new Error('公表履歴データの形式が不正です');
    }
    const urls = [], hosts = [];
    for (const row of data.records) {
      const [scope, key, date, sourceIndex, description, status] = row;
      const source = data.sources[sourceIndex];
      if (!source || !['url', 'host'].includes(scope) || typeof key !== 'string' ||
          !(date === '' || /^\d{4}-\d{2}-\d{2}$/.test(date)) || typeof description !== 'string' ||
          !['not_checked', 'closed_by_source'].includes(status)) throw new Error('公表履歴のレコードが不正です');
      if (scope === 'url' && canonicalUrl(key) !== key) throw new Error('URLが正規化されていません');
      (scope === 'url' ? urls : hosts).push(row);
    }
    const compare = (a, b) => a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;
    urls.sort(compare); hosts.sort(compare);
    return { generatedAt: data.generatedAt, sources: data.sources, urls, hosts };
  }
  function matchingRows(rows, key) {
    let low = 0, high = rows.length;
    while (low < high) {
      const mid = Math.floor((low + high) / 2);
      if (rows[mid][1] < key) low = mid + 1;
      else high = mid;
    }
    const matches = [];
    while (low < rows.length && rows[low][1] === key) matches.push(rows[low++]);
    return matches;
  }
  function lookup(index, input) {
    const key = canonicalUrl(input);
    if (!index || !key) return [];
    const host = new URL(key).hostname;
    return [...matchingRows(index.urls, key), ...matchingRows(index.hosts, host)].map((row) => ({
      scope: row[0], key: row[1], date: row[2], source: index.sources[row[3]], description: row[4], status: row[5],
    }));
  }
  global.SiteRiskThreatData = { canonicalUrl, parse, lookup };
})(typeof self !== 'undefined' ? self : globalThis);
