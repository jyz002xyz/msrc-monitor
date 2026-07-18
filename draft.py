#!/usr/bin/env python3
"""
draft.py — 事実のみの Markdown 下書きを生成する

diff.py の出力と当月 state から、「何がどう変わったか」だけの下書きを作る。
人間がこれに解釈を足して初めてレポートになる。

★このモジュールがやらないこと (設計原則。違反は不合格) ★
    - 帰属をしない。クレジット名から AI/ツールの正体を書かない。
    - 解釈・原因分析・結論を書かない (「危険」「AI が」「〜と考えられる」等)。
    - 比率トレンドを載せない。
    - 確定版を作らない。出力は必ず「下書き」であり固定ヘッダを刻む。

使い方:
    python draft.py 2026-Jul                    # stdout に下書き
    python draft.py 2026-Jul --out drafts/2026-Jul.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import diff

# 下書き冒頭の固定ヘッダ (改変不可)。帰属禁止・未検証を毎回明示する。
FIXED_HEADER = """\
> ⚠ これは機械生成の事実記録です。解釈・帰属・結論を含みません。
> クレジット名から AI/ツールの正体を推測しないでください
> （Kugelblitz=MDASH 断定が 2026-07 に一次情報で反証された教訓）。
> この下書きに人間が解釈を加えて初めてレポートになります。
> 数値は MSRC CVRF の取得結果（取得日: {fetched_at}）。
"""


def _table(rows: list[tuple[str, str]]) -> list[str]:
    """(項目, 値) の2列 Markdown テーブルを行リストで返す。"""
    out = ["| 項目 | 値 |", "| --- | --- |"]
    for k, v in rows:
        out.append(f"| {k} | {v} |")
    return out


def _bold_if(flag: bool, text: str) -> str:
    """flag が立った項目は太字。評価語は付けない (閾値超過という事実だけ)。"""
    return f"**{text}（閾値超過）**" if flag else text


def render(month: str, rep: dict, state: dict) -> str:
    """diff レポート rep と当月 state から下書き Markdown を組み立てる。"""
    fetched_at = state.get("fetched_at") or "不明"
    L: list[str] = []

    L.append(FIXED_HEADER.format(fetched_at=fetched_at))
    L.append(f"# MSRC {month} 変化記録（下書き）\n")

    # --- 当月の総数・内訳 (事実) --------------------------------------------
    L.append("## 当月の集計（CVRF 全体）\n")
    tc = state.get("tier_count") or {}
    sc = state.get("severity_count") or {}
    rows = [
        ("総CVE (CVRF全体の母集団)", str(state.get("cve_total", "?"))),
        ("クレジット有り (実数)", str(state.get("credited", "?"))),
        ("クレジット無し (実数)", str(state.get("uncredited", "?"))),
    ]
    L += _table(rows)
    L.append("")

    L.append("### 深刻度内訳\n")
    L += _table([(k, str(v)) for k, v in sc.items()])
    L.append("")

    L.append("### 再起動クラス内訳\n")
    L += _table([(k, str(v)) for k, v in tc.items()])
    L.append("")

    # --- 前月比の変化 -------------------------------------------------------
    L.append("## 前月比の変化\n")
    if not rep.get("prev_available"):
        L.append(f"{rep['note']}\n")
    else:
        c = rep["changes"]
        ct = c["cve_total"]
        pct = "n/a" if ct["pct"] is None else f"{ct['pct']:+.1%}"
        hv = c["heavy"]
        ratio = "n/a" if hv["ratio"] is None else f"{hv['ratio']:.2f}x"
        cr = c["critical"]
        zd = c["zero_days_uncredited"]
        rows = [
            ("総CVE (CVRF全体)",
             _bold_if(ct["flag"],
                      f"{ct['prev']} → {ct['now']}（{ct['delta']:+d}, {pct}）")),
            ("重い層 T2+T3",
             _bold_if(hv["flag"], f"{hv['prev']} → {hv['now']}（{ratio}）")),
            ("Critical (参考)",
             f"{cr['prev']} → {cr['now']}（{cr['delta']:+d}）"),
            ("ゼロデイ計", str(c["zero_days_total"])),
            ("うちクレジット無し",
             _bold_if(zd["flag"], f"{zd['count']} 件")),
        ]
        L += _table(rows)
        L.append("")
        L.append(f"> 注記: 総CVE は {ct['note']}")
        L.append("")

    # --- 新規クレジット名 (全件・帰属注記なし) ------------------------------
    L.append("## 新規クレジット名（前月に無かったもの・全件）\n")
    nc = rep.get("new_credits") or []
    if not nc:
        L.append("（前月比較なし、または新規クレジット名なし）\n")
    else:
        L.append("| 件数 | クレジット名 |")
        L.append("| --- | --- |")
        for item in nc:
            name = _bold_if(item["flag"], item["name"])
            L.append(f"| {item['count']} | {name} |")
        L.append("")

    # --- ゼロデイ一覧 -------------------------------------------------------
    L.append("## ゼロデイ一覧\n")
    zds = state.get("zero_days") or []
    if not zds:
        L.append("（該当なし）\n")
    else:
        L.append("| CVE | 深刻度 | 悪用 | 公開 | 発見者クレジット |")
        L.append("| --- | --- | --- | --- | --- |")
        for z in zds:
            exploited = "Yes" if z.get("exploited") else "No"
            disclosed = "Yes" if z.get("disclosed") else "No"
            credits = "、".join(z.get("credits") or []) or "（クレジット無し）"
            L.append(f"| {z.get('cve', '?')} | {z.get('severity', '?')} | "
                     f"{exploited} | {disclosed} | {credits} |")
        L.append("")

    # --- 人間が確認・追記すべき点 (誘導しない・空欄) -------------------------
    L.append("## 人間が確認・追記すべき点\n")
    L.append("- [ ] 新規クレジット名の正体を一次情報で確認したか")
    L.append("- [ ] 重い層 (T2+T3) の増減要因を確認したか")
    L.append("- [ ] ゼロデイの発見経緯・クレジットを一次情報で確認したか")
    L.append("- [ ] 総CVE の集計基準（母集団）を確認したか")
    L.append("")

    return "\n".join(L)


def build_draft(month: str, prev_tag: str | None = None) -> str:
    """月タグから下書き文字列を組み立てる (CLI/他モジュール共通の入口)。"""
    rep = diff.build_report(month, prev_tag)
    state = diff.load_state(month)
    if state is None:
        raise FileNotFoundError(f"当月ファイルが無い: state/{month}.json")
    return render(month, rep, state)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="事実のみの下書きを生成する (解釈・帰属なし)")
    ap.add_argument("month", help="当月タグ 例: 2026-Jul")
    ap.add_argument("--prev", help="比較対象の月タグ (省略時は直前月)")
    ap.add_argument("--out", help="出力先パス (省略時は stdout)")
    args = ap.parse_args()

    try:
        text = build_draft(args.month, args.prev)
    except FileNotFoundError as e:
        print(f"[draft] エラー: {e}", file=sys.stderr)
        return 1

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"[draft] 書き出し: {out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
