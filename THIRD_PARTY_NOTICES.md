# Third-party notices / 第三者のデータ・ライセンス

## HaGeZi DNS Blocklists — Fake

- 同梱ファイル: `data/blocklist.txt`
- 出典: https://github.com/hagezi/dns-blocklists （`wildcard/fake-onlydomains.txt`）
- ライセンス: GNU General Public License v3.0（GPL-3.0）
- 用途: 既知の偽ショップ・詐欺サイトのドメインとの照合。拡張機能は同梱リストに加え、GitHub Pages から同じリストを定期取得します。閲覧先URLは送信しませんが、リスト取得時の接続情報は GitHub Pages 側に伝わります。

`tools/update-blocklist.js` で `data/blocklist.txt` と配信用 `docs/feed/blocklist.json` を更新します。GitHub Actions が毎日実行します。ホワイトリスト（`detector.js` の `WHITELIST_DOMAINS` 等）に該当するドメインは除外しています。

## JPCERT/CC phishurl-list・CCJ・消費者庁の公表履歴

- 同梱ファイル: `data/threat-catalog.json`、`data/threat-shards/*.json`
- JPCERT/CC: https://github.com/JPCERTCC/phishurl-list 。確認日・URL・騙られたブランドのCSV。明示的なライセンスは未確認です（`not_specified`）。JPCERT/CCのウェブサイト利用案内がGitHubデータの再配布・商用利用まで許可しているとは解釈していません。
- 国民生活センター CCJ: https://www.kokusen.go.jp/soudan_now/data/online-shopping-scams.html 。悪質通販サイト一覧に掲載されたURL・区分・日付・閉鎖記載を抽出しています。模倣品販売等も含み、全件をフィッシングと分類しません。
- 消費者庁: https://www.caa.go.jp/notice/entry/047056/ 。注意喚起の対象ドメイン表からホスト名と公表日を抽出しています。
- 出典と取得日は同梱カタログ、確認・公表日は各照合レコードに保存しています。公表元のPDF・スクリーンショット・本文全体は同梱しません。元情報を照合用形式に加工したもので、公表元が本拡張機能を承認したことを示しません。
- 用途: 過去の公表情報への端末内照合。対象サイトの現在の状態は本ツールでは確認していません。閉鎖と記載された履歴も残します。
- 更新方法: `node tools/update-intelligence.js`。再配布・商用利用は公表元の利用条件・個別条件を確認してください。

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
