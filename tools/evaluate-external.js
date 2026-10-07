// Offline evaluation of frozen, third-party labels. Never visits listed URLs.
// Usage: node tools/evaluate-external.js [dataset directory]
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('../detector.js');
const { analyze } = globalThis.SiteRiskDetector;
const root = path.resolve(__dirname, '..');
const dir = path.resolve(process.argv[2] || path.join(root, 'tests/data/external-2026-10-08'));
const blocklist = new Set(fs.readFileSync(path.join(root, 'data/blocklist.txt'), 'utf8')
  .split(/\r?\n/).map(x => x.trim()).filter(x => x && !x.startsWith('#')));
// Exclude related registrable domains too, using the project's domain estimator.
const knownDomains = new Set([...blocklist].map(x => analyze(x).domain));
const inputs = JSON.parse(fs.readFileSync(path.join(dir, 'inputs.json'), 'utf8'));
const groups = new Map();
const evaluated = [];
function stats(rows) {
  const detected = rows.filter(r => r.score >= 40).length;
  const danger = rows.filter(r => r.score >= 80).length;
  return { total: rows.length, detected, missed: rows.length - detected, danger,
    cautionOrAbovePercent: rows.length ? +(detected / rows.length * 100).toFixed(2) : null,
    dangerPercent: rows.length ? +(danger / rows.length * 100).toFixed(2) : null,
    uniqueHosts: new Set(rows.map(r => r.hostname)).size,
    whitelisted: rows.filter(r => r.whitelisted).length };
}
for (const input of inputs) {
  if (!groups.has(input.source)) groups.set(input.source, { raw: 0, invalid: 0, duplicate: 0, overlap: 0, seen: new Set(), rows: [] });
  const g = groups.get(input.source); g.raw++;
  const r = analyze(input.url, { blocklist });
  if (r.level === 'invalid' || r.level === 'unsupported') { g.invalid++; continue; }
  if (g.seen.has(r.url)) { g.duplicate++; continue; }
  g.seen.add(r.url);
  const labels = r.hostname.split('.');
  const hostOverlap = labels.some((_, i) => blocklist.has(labels.slice(i).join('.')));
  if (hostOverlap || knownDomains.has(r.domain)) { g.overlap++; continue; }
  const row = { source: input.source, url: r.url, hostname: r.hostname, domain: r.domain,
    score: r.score, level: r.level, whitelisted: r.whitelisted,
    reasons: r.reasons.map(x => `${x.category}: ${x.detail}`).join(' / ') };
  g.rows.push(row); evaluated.push(row);
}
const unique = [...new Map(evaluated.map(r => [r.url, r])).values()];
// Host-weighted statistic: one median score per hostname (not dominated by many paths).
const hostGroups = new Map();
for (const r of unique) {
  if (!hostGroups.has(r.hostname)) hostGroups.set(r.hostname, []);
  hostGroups.get(r.hostname).push(r);
}
const hostMedians = [...hostGroups.values()].map(rows => rows.sort((a, b) => a.score - b.score)[Math.floor((rows.length - 1) / 2)]);
const white = [...new Set(['legit_jp_shops.txt', 'legit_jp_shops2.txt'].flatMap(name =>
  fs.readFileSync(path.join(root, 'tests/data', name), 'utf8').split(/\r?\n/)
    .map(x => x.trim()).filter(x => x && !x.startsWith('#'))))]
  .map(url => analyze(url, { blocklist }));
const summary = {
  clientDate: '2026-10-08', version: JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'))).version,
  evaluatedAtUtc: new Date().toISOString(),
  detectorSha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'detector.js'))).digest('hex'),
  sources: JSON.parse(fs.readFileSync(path.join(dir, 'sources.json'), 'utf8')),
  conditions: 'URL only; no page text or RDAP; no phishing URLs visited; blocklist host/parent and estimated registrable-domain overlaps excluded; thresholds 40/80',
  limitations: 'Third-party phishing labels, not fake-shop-specific. Historical development-data overlap is unknown. Legitimate controls are existing project fixtures, not a newly independent sample. No pre-agreed acceptance threshold.',
  datasets: [...groups].map(([source, g]) => ({ source, raw: g.raw, invalid: g.invalid,
    duplicate: g.duplicate, excludedOverlap: g.overlap, ...stats(g.rows) })),
  combinedUniqueUrls: stats(unique), hostMedianScores: stats(hostMedians),
  legitimateControls: { ...stats(white), meaning: 'detected means false positive for these legitimate controls' },
};
fs.writeFileSync(path.join(dir, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
const columns = ['source', 'url', 'hostname', 'domain', 'score', 'level', 'whitelisted', 'reasons'];
const quote = x => '"' + String(x).replace(/"/g, '""') + '"';
fs.writeFileSync(path.join(dir, 'results.csv'), '\ufeff' + [columns, ...unique.map(r => columns.map(c => r[c]))].map(r => r.map(quote).join(',')).join('\r\n'));
console.log(JSON.stringify({ datasets: summary.datasets, combined: summary.combinedUniqueUrls,
  hostMedians: summary.hostMedianScores, white: summary.legitimateControls }, null, 2));
