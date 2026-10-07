/**
 * HTML 文字列をテキストに変換する（ブラウザの innerText の簡易版）。
 * DOM を使わず文字列処理だけで行うため、HTML内のスクリプト等が実行されることはない。
 */
'use strict';

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', yen: '¥', copy: '©' };

function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const code = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : '';
    }
    return ENTITIES[e.toLowerCase()] != null ? ENTITIES[e.toLowerCase()] : m;
  });
}

/**
 * @param {string} html
 * @returns {{text: string, links: {text: string, href: string}[], title: string}}
 */
function htmlToText(html) {
  let s = String(html || '');
  s = s.replace(/<!--[\s\S]*?-->/g, ' ');
  s = s.replace(/<(script|style|noscript|template|svg|iframe|object)\b[\s\S]*?<\/\1\s*>/gi, ' ');

  const title = decodeEntities(((s.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '').replace(/\s+/g, ' ').trim());

  const links = [];
  const linkRe = /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi;
  let m;
  while ((m = linkRe.exec(s)) && links.length < 3000) {
    const href = (m[1].match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i) || []).slice(1).find((x) => x != null) || '';
    const text = decodeEntities(m[2].replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim().slice(0, 100);
    links.push({ text, href: decodeEntities(href) });
  }

  s = s.replace(/<head\b[\s\S]*?<\/head\s*>/i, ' ');
  s = s.replace(/<(br|hr)\b[^>]*>/gi, '\n');
  s = s.replace(/<\/(p|div|li|tr|h[1-6]|section|article|header|footer|dt|dd|table|ul|ol|form|label|option)\s*>/gi, '\n');
  s = s.replace(/<\/(td|th)\s*>/gi, '\t');
  s = s.replace(/<[^>]+>/g, ' ');
  s = decodeEntities(s);
  const text = s.split('\n').map((l) => l.replace(/[ \t 　]+/g, ' ').trim()).filter(Boolean).join('\n');

  return { text, links, title };
}

module.exports = { htmlToText };
