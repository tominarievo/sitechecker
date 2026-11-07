(function (global) {
  'use strict';

  const SOURCE = 'hagezi-fake';
  const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

  function parse(data) {
    if (!data || data.schemaVersion !== 1 || data.source !== SOURCE ||
        typeof data.generatedAt !== 'string' || !Number.isFinite(Date.parse(data.generatedAt)) ||
        new Date(data.generatedAt).toISOString() !== data.generatedAt ||
        !Number.isSafeInteger(data.count) || !Array.isArray(data.domains) ||
        data.count !== data.domains.length || data.count < 1000 || data.count > 50000 ||
        typeof data.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(data.sha256)) {
      throw new Error('動的ブラックリストの形式が不正です');
    }

    let previous = '';
    for (const domain of data.domains) {
      const labels = typeof domain === 'string' ? domain.split('.') : [];
      if (labels.length < 2 || domain.length > 253 ||
          labels.some((label) => label.length > 63 || !LABEL.test(label)) ||
          labels[labels.length - 1].length < 2 || !/[a-z]/.test(labels[labels.length - 1]) ||
          domain <= previous) {
        throw new Error('動的ブラックリストのドメイン一覧が不正です');
      }
      previous = domain;
    }

    return data;
  }

  async function verify(data) {
    const feed = parse(data);
    const canonical = feed.domains.join('\n') + '\n';
    const bytes = await global.crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
    const digest = [...new Uint8Array(bytes)].map((n) => n.toString(16).padStart(2, '0')).join('');
    if (digest !== feed.sha256) throw new Error('動的ブラックリストのSHA-256が一致しません');
    return feed;
  }

  global.SiteRiskBlocklistData = { parse, verify };
  if (typeof module !== 'undefined' && module.exports) module.exports = global.SiteRiskBlocklistData;
})(typeof self !== 'undefined' ? self : globalThis);
