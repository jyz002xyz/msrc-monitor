# msrc_monitor

*他の言語で読む: [English](README.md)*

Microsoft の毎月の Patch Tuesday 一次データ（MSRC CVRF）を取得し、事実として集計し、
**変化**のみを通知する監視ツールです。凍結した事実から日英バイリンガルのレポート生成も支援します。

## 公開レポート

📄 **[レポートを読む → jyz002xyz.github.io/msrc-monitor](https://jyz002xyz.github.io/msrc-monitor/)**
&nbsp;([日本語](https://jyz002xyz.github.io/msrc-monitor/report_ja.html) · [English](https://jyz002xyz.github.io/msrc-monitor/report_en.html))

フロンティアAIによる脆弱性発見の急増に関する状況分析（2026年7月時点）。数値は機械生成の
事実、解釈は人間の分析で、個人名は役割へ一般化しています。情報提供のみを目的とし、助言では
ありません。

## 設計思想

**「変化検知は自動、意味づけ（解釈）は人間が行う」**

このプログラムは意図的に、解釈も帰属もしません。事実（CVE 件数・深刻度・再起動クラス・
製品カテゴリ・発見者バケット）を集計し、閾値を超えた*変化*を通知するだけです。
それを物語に仕立てること、そして因果や帰属の断定は、人間に委ねます。

特にパーサ（`cvrf_parse.py`）は、クレジット文字列から発見者の正体（例：「どの AI/ツールか」）を
一切推測しません。機械的な文字列分類のみを行います。データ層を判断から自由に保つため、
役割を次のように分離しています。

- **CISA KEV** ＝ 悪用確認の離散的な事実（エッジ trigger 型の通知シグナル）です。
- **FIRST EPSS** ＝ 取得時点の参考値です。レポート表示のみに使い、通知トリガーには使いません
  （日々変動するため）。

## データとプライバシー

**本リポジトリは実 MSRC データを意図的に同梱していません。**

Microsoft の CVRF 謝辞クレジットには、第三者であるセキュリティ研究者の個人情報
（氏名・SNS ハンドル・メールアドレス）が含まれます。そのプライバシーに配慮し、実際の
`state/` スナップショットや CVRF フィクスチャは同梱していません。また、生成される
`state/*.json` は git 管理から除外し、利用者が研究者 PII を誤って commit しないようにしています。

テストは `tests/fixtures/make_synthetic_cvrf.py` が生成する**合成データ**（ダミー名のみ・
`example.com` アドレス）だけで完結します。実データを取得するには、下記の一次 API に対して
コレクタを実行します。取得したデータはローカルに留まります。

## はじめに

```bash
# Python 3.12+、依存は requests のみ
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 当月を取得 (state/ に書き込む。state/ は git 管理外)
python collect.py
python collect.py 2026-Jul          # 特定の月

# テスト実行 (合成データ・ネットワーク不要)
python tests/fixtures/make_synthetic_cvrf.py   # 合成 fixture を(再)生成
python -m pytest tests/ -q                      # または: python tests/test_regression.py

# 日英レポートのドラフトを生成 (PDF には Node.js + LibreOffice が必要)
./report/build.sh
```

通知や dead-man's switch の認証情報（例：Pushover）は環境変数 / `env.sh` から読み込み、
git には一切 commit しません（`.gitignore` 参照）。

## 一次データの取得元

- **MSRC CVRF API**: `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{YYYY-MMM}`
  （例：`2026-Jul`）。スキーマの参照実装：
  `https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API`。
- **謝辞**: 研究者クレジットは Microsoft の Security Update Guide の謝辞
  （`https://msrc.microsoft.com/update-guide/acknowledgement`）で公開されています。
  本プロジェクトは個々の研究者の氏名を再掲載しません。

## リポジトリ構成

```
cvrf_parse.py        # 自己完結型 CVRF パーサ + 事実分類
collect.py           # CVRF取得 -> 月次の事実サマリ (冪等・過去月は凍結)
diff.py              # 前月比の閾値判定 + 新規クレジット検出
draft.py             # 事実のみの下書き生成 (解釈なし)
notify.py            # エッジtrigger型の通知
enrich.py            # KEV/EPSS エンリッチメント層 (KEV=通知トリガー / EPSS=参考)
report/              # 日英レポート生成 (docx/pdf) + 匿名化ゲート
interpretation/      # 人間が書くレポート解釈文 (ja/en)
tests/               # 回帰テスト + ユニットテスト (合成データで実行)
systemd/             # スケジュール実行用の service + timer (任意)
```

## 免責事項

本プロジェクトは、作者個人の興味に基づく調査として実施しているものです。賛同・批判・
改善のご要望など、どのようなフィードバックもありがたく拝見しますが、それらへの対応や
改善をお約束するものではありません。

内容には誤りが含まれる可能性があり、正確性・完全性は保証しません（あわせて
[LICENSE](LICENSE) もご参照ください）。本プロジェクトを活用される場合は、内容の是非を
ご自身の責任でご判断ください。

## ライセンス

MIT — [LICENSE](LICENSE) を参照してください。
