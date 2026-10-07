# Third-party notices / 第三者のデータ・ライセンス

## HaGeZi DNS Blocklists — Fake

- 同梱ファイル: `data/blocklist.txt`
- 出典: https://github.com/hagezi/dns-blocklists （`wildcard/fake-onlydomains.txt`）
- ライセンス: GNU General Public License v3.0（GPL-3.0）
- 用途: 既知の偽ショップ・詐欺サイトのドメインとの照合（拡張機能内でのみ参照し、外部には送信しません）

`tools/update-blocklist.js` で最新版に更新できます。ホワイトリスト（`detector.js` の `WHITELIST_DOMAINS` 等）に該当するドメインは除外しています。

## Public Suffix List

- 同梱ファイル: `data/public_suffix_list.dat`
- 出典: https://publicsuffix.org/list/public_suffix_list.dat
- ライセンス: Mozilla Public License 2.0（MPL-2.0）
- 用途: フィッシングの追加チェックで、登録ドメイン（例: `www.amazon.co.jp` → `amazon.co.jp`）を判定するため（ICANN・PRIVATE の両セクションを使用）。処理は `psl.js`（独自実装）
- 更新方法: `node tools/update-psl.js`

## ブランドと公式ドメインの対応表

- 同梱ファイル: `data/brands.json`（本プロジェクトで作成）
- 各ブランドの公式ログインページ等が、登録したドメインで応答することを確認した根拠を `evidence` に記載しています（確認日は `checkedAt`）。根拠を確認できないブランドは登録していません。

## IANA RDAP Bootstrap

- 参照先: https://data.iana.org/rdap/dns.json （RDAP 機能を有効にした場合のみ、実行時に取得）
- 用途: TLD ごとの RDAP サーバーの特定
