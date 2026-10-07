/**
 * Public Suffix List（https://publicsuffix.org/）による登録ドメインの判定。
 * データは data/public_suffix_list.dat を同梱（MPL-2.0、tools/update-psl.js で更新）。
 * ICANN と PRIVATE の両方のルールを使う（github.io や s3.amazonaws.com のような共有ホスティングでは、
 * 利用者ごとのサブドメインが登録ドメインとして扱われる）。
 * background.js（importScripts）と tests（require）から読み込む。
 */
(function (global) {
  'use strict';

  /** 国際化ドメインのルールを、URL と同じ Punycode 表記にそろえる */
  function toAscii(label) {
    if (/^[\x00-\x7f]*$/.test(label)) return label.toLowerCase();
    try {
      return new URL('http://' + label).hostname;
    } catch (_) {
      return label.toLowerCase();
    }
  }

  /**
   * @param {string} text public_suffix_list.dat の内容
   * @returns {{getRegistrableDomain: (host: string) => string|null, getPublicSuffix: (host: string) => string}}
   */
  function parse(text) {
    const rules = new Set();
    const wildcards = new Set();   // "*.foo.bar" の "foo.bar"
    const exceptions = new Set();  // "!city.kawasaki.jp" の "city.kawasaki.jp"
    String(text).split(/\r?\n/).forEach((raw) => {
      const line = raw.trim().split(/\s/)[0];
      if (!line || line.startsWith('//')) return;
      if (line.startsWith('!')) exceptions.add(toAscii(line.slice(1)));
      else if (line.startsWith('*.')) wildcards.add(toAscii(line.slice(2)));
      else rules.add(toAscii(line));
    });

    /** 公開サフィックス（例: co.jp, github.io）を返す。ルールに無い TLD は暗黙のルール "*" として扱う */
    function getPublicSuffix(host) {
      const labels = String(host || '').toLowerCase().replace(/\.$/, '').split('.');
      for (let i = 0; i < labels.length; i++) {
        const candidate = labels.slice(i).join('.');
        if (exceptions.has(candidate)) return labels.slice(i + 1).join('.');
        const parent = labels.slice(i + 1).join('.');
        if (i < labels.length - 1 && wildcards.has(parent)) return candidate;
        if (rules.has(candidate)) return candidate;
      }
      return labels[labels.length - 1];
    }

    /** 登録ドメイン（公開サフィックス + 1ラベル）。ホスト自体が公開サフィックスなら null */
    function getRegistrableDomain(host) {
      const h = String(host || '').toLowerCase().replace(/\.$/, '');
      if (!h || /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith('[')) return null;
      const suffix = getPublicSuffix(h);
      if (h === suffix) return null;
      const rest = h.slice(0, h.length - suffix.length - 1).split('.');
      return rest[rest.length - 1] + '.' + suffix;
    }

    return { getPublicSuffix, getRegistrableDomain, size: rules.size + wildcards.size + exceptions.size };
  }

  global.SiteRiskPsl = { parse };
})(typeof self !== 'undefined' ? self : globalThis);
