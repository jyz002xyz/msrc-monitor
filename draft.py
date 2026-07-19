#!/usr/bin/env python3
"""
draft.py — generate a facts-only Markdown draft

From diff.py's output and the current month's state, produces a draft of
"what changed and how" only. It becomes a report only after a human adds
interpretation.

★ What this module does NOT do (design rules; violations fail review) ★
    - No attribution. Never state the identity of an AI/tool from a credit name.
    - No interpretation, root-cause analysis, or conclusions (no "dangerous",
      "the AI did X", "likely ...", etc.).
    - No ratio trends.
    - Never produce a final version. Output is always a "draft" and carries a
      fixed header.

Usage:
    python draft.py 2026-Jul                    # draft to stdout
    python draft.py 2026-Jul --out drafts/2026-Jul.md
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import diff

# Fixed header at the top of every draft (do not alter). Restates the
# no-attribution / unverified stance each time. (Body text is intentionally Japanese.)
FIXED_HEADER = """\
> ⚠ これは機械生成の事実記録です。解釈・帰属・結論を含みません。
> クレジット名から AI/ツールの正体を推測しないでください
> （Kugelblitz=MDASH 断定が 2026-07 に一次情報で反証された教訓）。
> この下書きに人間が解釈を加えて初めてレポートになります。
> 数値は MSRC CVRF の取得結果（取得日: {fetched_at}）。
"""


def _table(rows: list[tuple[str, str]]) -> list[str]:
    """Return a 2-column (item, value) Markdown table as a list of lines."""
    out = ["| 項目 | 値 |", "| --- | --- |"]
    for k, v in rows:
        out.append(f"| {k} | {v} |")
    return out


def _bold_if(flag: bool, text: str) -> str:
    """Bold the item if the flag is set. No evaluative words — just the fact
    that a threshold was exceeded."""
    return f"**{text}（閾値超過）**" if flag else text


def render(month: str, rep: dict, state: dict) -> str:
    """Assemble the draft Markdown from the diff report `rep` and current `state`.
    (The rendered body text is intentionally Japanese — this is the draft output.)"""
    fetched_at = state.get("fetched_at") or "不明"
    L: list[str] = []

    L.append(FIXED_HEADER.format(fetched_at=fetched_at))
    L.append(f"# MSRC {month} 変化記録（下書き）\n")

    # --- current month totals / breakdown (facts) ---------------------------
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

    # --- month-over-month changes -------------------------------------------
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

    # --- new credit names (all, no attribution notes) -----------------------
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

    # --- zero-day list ------------------------------------------------------
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

    # --- points for a human to verify / add (no leading questions, left open) ---
    L.append("## 人間が確認・追記すべき点\n")
    L.append("- [ ] 新規クレジット名の正体を一次情報で確認したか")
    L.append("- [ ] 重い層 (T2+T3) の増減要因を確認したか")
    L.append("- [ ] ゼロデイの発見経緯・クレジットを一次情報で確認したか")
    L.append("- [ ] 総CVE の集計基準（母集団）を確認したか")
    L.append("")

    return "\n".join(L)


def build_draft(month: str, prev_tag: str | None = None) -> str:
    """Build the draft string from a month tag (shared entry for CLI and other modules)."""
    rep = diff.build_report(month, prev_tag)
    state = diff.load_state(month)
    if state is None:
        raise FileNotFoundError(f"no state file for the month: state/{month}.json")
    return render(month, rep, state)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate a facts-only draft (no interpretation, no attribution)")
    ap.add_argument("month", help="current month tag, e.g. 2026-Jul")
    ap.add_argument("--prev", help="month tag to compare against (defaults to the previous month)")
    ap.add_argument("--out", help="output path (defaults to stdout)")
    args = ap.parse_args()

    try:
        text = build_draft(args.month, args.prev)
    except FileNotFoundError as e:
        print(f"[draft] error: {e}", file=sys.stderr)
        return 1

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"[draft] wrote: {out}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
