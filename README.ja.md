# msrc_monitor

*他の言語で読む: [English](README.md)*

Microsoft の毎月の Patch Tuesday 一次データ（MSRC CVRF）を取得し、事実として集計し、
**変化**のみを通知する監視ツール。凍結した事実から日英バイリンガルのレポート生成も支援する。

## 設計思想

**「変化検知は自動、意味づけ（解釈）は人間が行う」**

このプログラムは意図的に、解釈も帰属もしない。事実（CVE 件数・深刻度・再起動クラス・
製品カテゴリ・発見者バケット）を集計し、閾値を超えた*変化*を通知するだけである。
それを物語に仕立てること、そして因果や帰属の断定は、人間に委ねる。

特にパーサ（`cvrf_parse.py`）は、クレジット文字列から発見者の正体（例：「どの AI/ツールか」）を
一切推測しない。機械的な文字列分類のみを行う。データ層を判断から自由に保つため、
役割を次のように分離している。

- **CISA KEV** ＝ 悪用確認の離散的な事実（エッジ trigger 型の通知シグナル）。
- **FIRST EPSS** ＝ 取得時点の参考値。レポート表示のみに使い、通知トリガーには使わない
  （日々変動するため）。

## データとプライバシー

**本リポジトリは実 MSRC データを意図的に同梱していない。**

Microsoft の CVRF 謝辞クレジットには、第三者であるセキュリティ研究者の個人情報
（氏名・SNS ハンドル・メールアドレス）が含まれる。そのプライバシーに配慮し、実際の
`state/` スナップショットや CVRF フィクスチャは同梱していない。また、生成される
`state/*.json` は git 管理から除外し、利用者が研究者 PII を誤って commit しないようにしている。

テストは `tests/fixtures/make_synthetic_cvrf.py` が生成する**合成データ**（ダミー名のみ・
`example.com` アドレス）だけで完結する。実データを取得するには、下記の一次 API に対して
コレクタを実行する。取得したデータはローカルに留まる。

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
git には一切 commit しない（`.gitignore` 参照）。

## 一次データの取得元

- **MSRC CVRF API**: `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{YYYY-MMM}`
  （例：`2026-Jul`）。スキーマの参照実装：
  `https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API`。
- **謝辞**: 研究者クレジットは Microsoft の Security Update Guide の謝辞
  （`https://msrc.microsoft.com/update-guide/acknowledgement`）で公開されている。
  本プロジェクトは個々の研究者の氏名を再掲載しない。

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

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
