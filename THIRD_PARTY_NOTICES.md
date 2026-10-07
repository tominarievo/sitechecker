# Third-party notices / 第三者のデータ・ライセンス

## HaGeZi DNS Blocklists — Fake

- 同梱ファイル: `data/blocklist.txt`
- 出典: https://github.com/hagezi/dns-blocklists （`wildcard/fake-onlydomains.txt`）
- ライセンス: GNU General Public License v3.0（GPL-3.0）
- 用途: 既知の偽ショップ・詐欺サイトのドメインとの照合（拡張機能内でのみ参照し、外部には送信しません）

`tools/update-blocklist.js` で最新版に更新できます。ホワイトリスト（`detector.js` の `WHITELIST_DOMAINS` 等）に該当するドメインは除外しています。

## IANA RDAP Bootstrap

- 参照先: https://data.iana.org/rdap/dns.json （RDAP 機能を有効にした場合のみ、実行時に取得）
- 用途: TLD ごとの RDAP サーバーの特定
