# 詐欺サイトチェッカー（Chrome / Edge 拡張機能・Manifest V3）

閲覧中のURL・ドメイン・ページ内容を解析し、悪質ECサイト・詐欺サイトの危険度（0〜100%）を判定します。
外部ライブラリ不使用・ビルド不要です。

## ファイル構成

| ファイル | 役割 |
|---|---|
| `manifest.json` | Manifest V3 設定（権限: `tabs`, `storage`、コンテンツスクリプト: http/https の全ページ） |
| `detector.js` | URL・ドメインの判定ロジック本体 |
| `rdap.js` | RDAP によるドメイン登録日の照会 |
| `page-analyzer.js` | ページ本文の解析ロジック |
| `content.js` | コンテンツスクリプト。本文を解析し、検出結果だけを background に渡す |
| `phishing-dom.js` / `phishing-analyzer.js` | フィッシングの追加チェック（入力フォームの抽出と採点。初期設定オフ） |
| `psl.js` / `data/public_suffix_list.dat` | Public Suffix List による登録ドメインの判定 |
| `data/brands.json` | ブランドと公式ドメインの対応表（根拠つき） |
| `background.js` | Service Worker。判定の集約、バッジ更新、RDAP キャッシュ |
| `popup.html` / `popup.js` | ポップアップUI（現在のタブ・手動チェック・設定） |
| `data/blocklist.txt` | 同梱ブラックリスト（既知の偽ショップ・詐欺ドメイン） |
| `tools/update-blocklist.js` | 同梱ブラックリストの更新スクリプト |
| `tools/urlscan-collect.js` | urlscan.io から日本語通販ページを収集（ルール改善用） |
| `tools/auto-label.js` | 収集したページに URL の特徴で仮ラベルを付ける |
| `tools/periodic-check.js` / `tools/register-task.ps1` | 定期評価とタスクスケジューラへの登録 |
| `tests/` | オフライン評価・単体テスト・E2E テスト・urlscan.io を使った評価 |
| `icons/` | ツールバーアイコン |

## インストール手順

### Google Chrome
1. アドレスバーに `chrome://extensions` と入力して開く
2. 右上の **「デベロッパー モード」** をオンにする
3. **「パッケージ化されていない拡張機能を読み込む」** をクリック
4. このフォルダ（`manifest.json` があるフォルダ）を選択
5. ツールバーのパズルアイコンから「詐欺サイトチェッカー」をピン留めすると常時表示されます

### Microsoft Edge
1. アドレスバーに `edge://extensions` と入力して開く
2. 左下（または左メニュー）の **「開発者モード」** をオンにする
3. **「展開して読み込み」** をクリック
4. このフォルダを選択
5. ツールバーの拡張機能アイコンから「詐欺サイトチェッカー」を「ツールバーに表示」にする

コードを編集した後は、拡張機能一覧画面で本拡張の **再読み込み（↻）** ボタンを押すと反映されます。

## 判定ルール（加点方式・0〜100%）

### URL・ドメイン（detector.js）

| 区分 | 内容 | 点数 |
|---|---|---|
| ブラックリスト | 同梱リスト（HaGeZi Fake、約1.7万件）に登録済み | +100 |
| 危険TLD | `.rest` `.ltd` `.icu` `.cfd` `.sbs` `.bond` `.cyou` `.xyz` `.top` など | +35〜40 |
| 格安TLD | `.site` `.shop` `.club` `.work` `.online` `.store` `.vip` など | +15〜30 |
| 擬似ドメイン | `.jp.net` `.jpn.com`、ドメイン途中の `.jp.` / `.co.jp.` | +45 |
| 擬似ドメイン | `.sa.com` `.ru.com` `.us.com` など民間の国別風サブドメイン | +35 |
| 擬似ドメイン | 擬似ドメインの下にさらにサブドメイン（例: `xsca.hansins.ru.com`） | +10 |
| なりすまし | 非公式ドメインに amazon / rakuten / yahoo 等のブランド名 | +20 |
| 無料ホスティング | `pages.dev` `netlify.app` `weebly.com` `amazonaws.com` など | +20 |
| ランダムサブドメイン | `tkbsr.` `a8f3k2.` のような無作為文字列 | +25 |
| ランダムドメイン | 登録ドメイン名自体が無作為文字列・数字のみ | +15 |
| 大量生成パス | `/item-xxxxxx.html`、`-p-123.html` など | +15 |
| 詐欺キット | `main_page=product_info` `zenid=` `products_id=` `osCsid=` `cPath=` など | +15〜40 |
| 複合要因 | 格安TLD ＋ 詐欺キットの組み合わせ | +15 |
| その他 | IPアドレス直打ち、Punycode、ハイフン過多、http接続 | +10〜30 |

### ドメイン年齢（rdap.js）

| 登録からの期間 | 点数 |
|---|---|
| 30日未満 / 90日未満 / 半年未満 / 1年未満 | +40 / +30 / +20 / +10 |
| 2年以上 / 5年以上 | −10 / −20 |

IANA の一覧（ブートストラップ）で TLD ごとの RDAP サーバーを調べ、そのレジストリに**登録ドメイン名だけ**を直接問い合わせます。結果は7日間キャッシュします。`.jp` `.de` など RDAP 非対応の TLD は確認できません（通信もしません）。初期設定はオフで、ポップアップの設定から有効にできます。

### ページ内容（page-analyzer.js / content.js）

| 内容 | 点数 |
|---|---|
| 80%OFF以上 / 70%OFF以上（「9割引」等も含む。正規サイトでも多いため補助的） | +10 / +5 |
| 振込先が個人名義の口座 | +25 |
| 運営者（株式会社〜）と口座名義が一致しない | +20 |
| 連絡先が中国系フリーメール（qq.com, 163.com 等） | +25 |
| 通販サイトの連絡先がフリーメール（gmail.com 等） | +10 |
| 日本語ページに簡体字が混在（3字以上 / 8字以上） | +20 / +30 |
| 通販サイトだが「特定商取引法に基づく表記」が見当たらない | +15 |
| フリマの出品文のような文言が多い（新品タグ付き・美品・^^ 等が3件以上） | +25 |
| タイトルが「人名＋ショップ名」形式（例: 酒井徳彦専門ショップ、浅野 政一株式会社） | +20 |
| タイトルがドメイン名の大文字表記で始まる（例: OVEN.HIKA-JP.CASA\|…） | +20 |
| 煽り文句が多い（最安値挑戦・お見逃しなく・大放出 等が2件以上） | +10 |

下の4つは、urlscan.io で収集した日本向け偽通販の実例（2026年8〜10月、154件）と正規通販（88件）を比較して、詐欺側でだけ多く現れた特徴です。

本文の解析はブラウザ内で完結し、本文を外部に送信することはありません。

### フィッシングの追加チェック（phishing-dom.js / phishing-analyzer.js・初期設定オフ）

ポップアップの設定で有効にした場合だけ動作します。ページの入力欄の種類（type・name・autocomplete・ラベル等）、フォームの送信先、周辺の表示文言から、認証・決済情報を求めるページかを判断し、次の組み合わせを採点します。**解析は端末内で完結し、外部への通信は行いません。利用者の入力値（パスワード・カード番号・OTP 等）は読み取りません。**

| # | 内容 | 点数（暫定値） |
|---|---|---|
| 1 | ブランド（`data/brands.json`）の公式を装い、公式ドメイン以外で機密情報を要求 | 40 |
| 2 | ブランドに似せたドメイン（公式ドメインを含むサブドメイン、似せた文字、語の付け足し、1〜2文字違い）で機密情報を要求 | 30 |
| 3 | パスワードとカード情報、カード情報と暗証番号など、通常は別の場面で使う情報を同じフォームで要求 | 30 |
| 4 | 機密情報の送信先が、ページとは別の未確認ドメイン | 25 |
| 5 | 機密情報の入力を、停止・失効などの脅しと期限つきで要求 | 20 |
| 6 | URL として表示されたリンクと実際のリンク先のドメインが異なる | 15 |
| 7 | 利用規約・会社概要などの主要リンクの多くが空・「#」 | 5 |
| 8 | 機密情報を HTTP の送信先へ送るフォーム（LAN 内のアドレスは除く） | 40 |

- 1 と 2 は同じ「ドメイン」の根拠として、高い方だけを数えます。
- **異なる種類の根拠が2つ以上**そろい、合計 **40点以上で「注意」、80点以上で「危険」**。8（HTTP への送信）だけは単独でも「注意」にします。
- 偽通販判定（%）とは別に「点」で表示し、足し合わせません。バッジには強い方の警告を出し、ポップアップにどちらのチェックによる警告かを表示します。
- 登録ドメインの判定には Public Suffix List を使い、公式ドメインとの比較は登録ドメインの完全一致で行います（`amazon.co.jp.evil.example` は公式とみなしません）。
- 表示中の入力欄だけを数え、`<template>` 内や非表示の欄は除外します。送信先は `form` の `action` と送信ボタンの `formaction` を `<base>` を考慮して解決します。**JavaScript で別の送信先に送るページの実際の送信先は、この静的な解析では確認できません。**
- メール・SMS・QR コードなど、ページに至る前の情報は扱いません。
- 点数は**未検証の暫定値**です。模擬ページでのテストの成功は、実際の検知率を示すものではありません。

### 判定

- **80%以上**: 赤バッジ「危険」
- **40〜79%**: 橙バッジ「注意」
- **40%未満**: バッジ非表示

**ホワイトリスト**（常に0%）: `amazon.co.jp` `rakuten.co.jp` `yahoo.co.jp` などの大手モールと、`.go.jp` `.ac.jp` `.lg.jp`。

ルールの追加・調整は `detector.js` / `page-analyzer.js` 冒頭の定数を編集してください。

## 外部への通信

| 通信先 | 内容 | 条件 |
|---|---|---|
| `data.iana.org` | TLD ごとの RDAP サーバー一覧（1日1回） | RDAP 設定がオン |
| 各TLDのレジストリの RDAP サーバー | 閲覧中サイトの登録ドメイン名 | RDAP 設定がオン、未キャッシュ時のみ |

上記以外への通信はありません（ブラックリストは同梱ファイルを参照します）。

## Public Suffix List の更新

```sh
node tools/update-psl.js
```

## ブラックリストの更新

```sh
node tools/update-blocklist.js
```

HaGeZi のリストをダウンロードして `data/blocklist.txt` を作り直します（リスト内のサイトにはアクセスしません）。更新後、拡張機能を再読み込みしてください。

出典: [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists)（Fake）— ライセンス GPL-3.0。拡張機能をストアで配布する場合は、GPL-3.0 の条件（ライセンス表示・ソースの提供）に従ってください。

## テスト

いずれも、リストや事例に載っている危険なサイトには**一切アクセスしません**。

### オフライン評価（URL・ドメイン）

```sh
node tests/evaluate.js \
  --black fake.txt --black openphish.txt --black jpcert-202605.csv \
  --white top-1m.csv:head --white top-1m.csv:jp:head \
  --sample 1000 --out results/
```

- `--black` / `--white`: 1行1ドメイン・1行1URL・hosts形式・Tranco の csv・JPCERT/CC phishurl-list の csv に対応
- `:head` は先頭から抽出（省略時は無作為抽出）、`:jp` は `.jp` ドメインのみ抽出
- `--out`: 全件の判定結果を CSV で出力
- `--no-blocklist`: 同梱ブラックリストを使わずに評価
- `--rdap N`: 各リストの先頭N件について RDAP で登録日を照会（レジストリにのみ問い合わせ、1件ずつ間隔を空けて実行、結果はキャッシュ）

### 単体テスト

```sh
node tests/page-analyzer.test.js     # 偽通販のページ内容の解析
node tests/phishing-analyzer.test.js # フィッシングの追加チェックと Public Suffix List の処理
```

### urlscan.io を使った評価・データ収集

詐欺サイトに接続するのは urlscan.io 側で、こちらは urlscan.io の API にのみアクセスします。取得した HTML はブラウザで開かず、拡張子 `.txt` で保存して文字列として扱います。API キーは環境変数 `URLSCAN_API_KEY` か `--key-file` で指定します。

```sh
# 日本語の通販系ページを収集（偽通販の候補を含む）
node tools/urlscan-collect.js --out <フォルダ> --key-file ~/.urlscan-key --days 60

# 収集データにラベル（labels.json: {"登録ドメイン": "black"|"white"|"unknown"}）を付けて、ルール別の反応率を比較
node tests/content-eval.js --samples <フォルダ> --labels <フォルダ>/labels.json   --legit legit_shops.txt --legit-cache <urlscan-eval のキャッシュ>

# ドメイン一覧を指定して、urlscan.io のスキャン結果で判定精度を評価
node tests/urlscan-eval.js --black list.txt --white legit.txt --cache <フォルダ> --key-file ~/.urlscan-key
```

### 定期評価（開発側のPCで2週間ごとに自動実行）

拡張機能を使う人の端末ではなく、開発側のPCで動かす仕組みです。urlscan.io から直近14日分の日本語通販ページを集め、URL の特徴で仮ラベルを付け、ページ内容のルールの精度を評価します。

```powershell
# 登録（2週間ごと・土曜 10:00。PC が停止していた場合は次の起動時に実行）
powershell -ExecutionPolicy Bypass -File tools\register-task.ps1
# 手動で今すぐ実行
node tools\periodic-check.js
# 登録解除
Unregister-ScheduledTask -TaskName "SiteChecker 定期評価" -Confirm:$false
```

| 出力 | 内容 |
|---|---|
| `%USERPROFILE%\sitechecker-data\runs\<日付>\report.txt` | 評価レポート（ルール別の反応率、見逃し一覧） |
| `%USERPROFILE%\sitechecker-data\runs\<日付>\labels-review.tsv` | 仮ラベルの確認用一覧（判断保留のサイトもここで確認） |
| `%USERPROFILE%\sitechecker-data\history.csv` | 検知率・誤検知率の推移 |

仮ラベルを手で直すときは、`runs\<日付>\labels-manual.json` に `{"登録ドメイン": "black"|"white"}` を書いて `node tools/auto-label.js --samples <runフォルダ>` を再実行します。

### 独立したデータでの精度評価（人手によるラベル付け）

定期評価の仮ラベルは検出器自身の URL スコアを使うため、精度の保証にはなりません。独立した評価には、人が判断したラベルを使います。

```sh
# 1. ルール作成に使っていない新しいデータだけで、ブラインド形式の確認シートを作る（自動ラベル・スコアは表示しない）
node tools/human-review.js --make <収集フォルダ> --since 2026-10-08 --exclude <過去の収集フォルダ>
# 2. human-review.tsv の human_label 列に black / white を記入（urlscan 列のリンクでスクリーンショットを確認。url 列は開かない）
# 3. 取り込んで評価
node tools/human-review.js --import <収集フォルダ>
node tests/content-eval.js --samples <収集フォルダ> --labels <収集フォルダ>/labels-human.json
```

### E2E テスト（実ブラウザ）

```sh
node tests/e2e.js ["C:\Program Files\Google\Chrome\Application\chrome.exe"]
```

一時プロファイルのヘッドレス Edge（または指定した Chrome）に拡張機能を読み込み、`127.0.0.1` で配信する模擬ページ（`tests/fixtures/`）で次を確認します。普段のブラウザのプロファイルには影響しません。

- 模擬ページの判定とバッジ、手動チェック、RDAP（初期設定オフ・ブラウザ内での動作）
- 回帰: 判定中に別ページへ移動しても、前のページの結果でバッジを上書きしない
- 回帰: SPA（再読み込みなしの URL 変更）と、遅れて描画される内容への追随
- 保存期限: 期限切れの照会結果の削除、RDAP 無効化時の全削除
- フィッシングの追加チェック: 初期状態オフでは解析しない／オンにすると開いているタブに反映／正規のログイン・決済・ニュース記事を誤検知しない／入力値を取得・保存しない／オフで追加警告と結果を削除し既存の警告は保持／処理中のオフ・オン→オフ→オン・ページ遷移で古い結果を反映しない／SPA と遅延描画に追随

テスト用のドメイン名（`slowshop.top`、`portal.sitechecker-test.net`）はブラウザ内で `127.0.0.1` に向けるため、外部のサーバーには接続しません。配布用 ZIP を展開したフォルダで試す場合は、環境変数 `SITECHECKER_EXT_DIR` にそのフォルダを指定します。

模擬ページを手動で確認したい場合は `node tests/serve-fixtures.js` を実行し、表示された URL を開いてください。

## 配布

```powershell
# ストア提出用 ZIP を作成（dist/sitechecker-<version>.zip。テスト・収集ツールは含めない）
powershell -ExecutionPolicy Bypass -File tools\build.ps1
```

- ストアの掲載文・審査申請の下書き: `store/listing.md`
- プライバシーポリシー（GitHub Pages で公開）: `docs/privacy.html`
- 更新時は `manifest.json` の `version` を上げてから ZIP を作り直してください。

## ライセンス

GPL-3.0（`LICENSE`）。同梱のブラックリストなど第三者のデータについては `THIRD_PARTY_NOTICES.md` を参照してください。

## 注意
自動判定は補助的なものです。誤検知・見逃しはあり得るため、最終的な判断は運営者情報・支払い方法・口コミなどと併せて行ってください。
