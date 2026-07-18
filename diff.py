#!/usr/bin/env python3
"""
diff.py — 隣接2ヶ月の state サマリを比較し「事実の変化」と「閾値フラグ」を出す

★このモジュールがやること★
    - 前月と当月の実数を比べ、変化量・変化率を出す。
    - 閾値を超えた変化に flag を立てる。
    - 前月に無かったクレジット名を「新規」として全件挙げる。

★このモジュールがやらないこと (設計原則。違反は不合格) ★
    - 帰属判断をしない。クレジット名から AI/ツール/組織の正体を推測しない。
      新規クレジット名は「名前」と「件数」だけを出す。
      (Kugelblitz=MDASH 断定が 2026-07 に一次情報で反証された教訓)
    - 比率トレンドを判定に使わない。特に「クレジット無し比率」は取得ラグの
      アーティファクトなので触らない。扱うのは実数のみ。
    - 解釈・原因分析をしない。「何がどう変わったか」だけを出す。

使い方:
    python diff.py 2026-Jul                  # 直前月(2026-Jun)と比較
    python diff.py 2026-Jul --prev 2026-Jun  # 比較対象を明示
    python diff.py 2026-Jul --json           # JSON 出力 (draft.py が消費)

閾値:
    home()/thresholds.json があれば読み込み、無ければ DEFAULT_THRESHOLDS。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

DEFAULT_THRESHOLDS = {
    "cve_total_pct": 0.50,      # 総CVE前月比 ±50% 超で flag
    "heavy_ratio": 1.5,         # T2+T3 が前月比 1.5倍 超で flag
    "new_credit_min_cve": 20,   # 新規クレジット名が 20 CVE 超で flag
    "zero_day_uncredited": 1,   # ゼロデイにクレジット無しが 1 件以上で flag
}


def home() -> Path:
    env = os.environ.get("MSRC_MONITOR_HOME")
    return Path(env) if env else Path(__file__).resolve().parent


def state_dir() -> Path:
    return home() / "state"


def load_thresholds() -> dict:
    """home()/thresholds.json があれば DEFAULT を上書き。無ければ DEFAULT。"""
    path = home() / "thresholds.json"
    th = dict(DEFAULT_THRESHOLDS)
    if path.exists():
        try:
            th.update(json.loads(path.read_text()))
        except Exception as e:
            print(f"[diff] 警告: thresholds.json 読み込み失敗 ({e}). "
                  f"デフォルトを使用", file=sys.stderr)
    return th


def prev_month_tag(tag: str) -> str:
    """'2026-Jul' -> '2026-Jun'"""
    y, m = tag.split("-")
    y = int(y)
    i = MONTHS.index(m)
    if i == 0:
        return f"{y - 1}-{MONTHS[11]}"
    return f"{y}-{MONTHS[i - 1]}"


def load_state(month: str) -> dict | None:
    path = state_dir() / f"{month}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def heavy_count(state: dict) -> int:
    """再起動の重い層 T2+T3 の実数。人員計画シグナル。"""
    tc = state.get("tier_count") or {}
    return int(tc.get("T2", 0)) + int(tc.get("T3", 0))


def compute_diff(now: dict, prev: dict | None, month: str, prev_tag: str,
                 th: dict) -> dict:
    """
    当月 now と前月 prev のサマリから差分レポート dict を作る。
    prev が None のときは「比較対象なし」を返す (例外は投げない)。
    """
    if prev is None:
        return {
            "month": month,
            "prev": prev_tag,
            "prev_available": False,
            "note": f"比較対象なし (前月ファイル state/{prev_tag}.json が無い)",
            "changes": None,
            "new_credits": [],
            "any_flag": False,
            "fetched_at": now.get("fetched_at"),
        }

    flags: list[bool] = []

    # --- 1. 総CVE件数の変化 (実数。CVRF全体=母集団) --------------------------
    now_total = int(now.get("cve_total", 0))
    prev_total = int(prev.get("cve_total", 0))
    delta_total = now_total - prev_total
    pct_total = (delta_total / prev_total) if prev_total else None
    flag_total = pct_total is not None and abs(pct_total) > th["cve_total_pct"]
    flags.append(flag_total)

    # --- 2. 重い層 T2+T3 の変化 (最重要。人員計画シグナル) -------------------
    now_heavy = heavy_count(now)
    prev_heavy = heavy_count(prev)
    if prev_heavy == 0:
        ratio_heavy = None
        # 0 -> N の跳ね上がりは比率で表せないが、重要なので拾う
        flag_heavy = now_heavy > 0
    else:
        ratio_heavy = round(now_heavy / prev_heavy, 3)
        flag_heavy = ratio_heavy > th["heavy_ratio"]
    flags.append(flag_heavy)

    # --- 3. 新規クレジット名の検出 (前月に無く今月にある。全件出す) ----------
    #     帰属はしない。名前と件数だけ。閾値超過に強調 flag。
    prev_credits = prev.get("credit_counts") or {}
    now_credits = now.get("credit_counts") or {}
    new_credits: list[dict] = []
    for name, count in now_credits.items():
        if name not in prev_credits:
            f = int(count) > th["new_credit_min_cve"]
            new_credits.append({"name": name, "count": int(count), "flag": f})
    # 件数降順で並べる (人間が全リストを上から見られるように)
    new_credits.sort(key=lambda x: -x["count"])
    flags.append(any(c["flag"] for c in new_credits))

    # --- 4. ゼロデイの発見者 (クレジット無し件数) ---------------------------
    #     「AI が出した」とは書かない。「クレジット無しのゼロデイが N 件」。
    zds = now.get("zero_days") or []
    zd_uncredited = sum(1 for z in zds if not z.get("credited"))
    flag_zd = zd_uncredited >= th["zero_day_uncredited"]
    flags.append(flag_zd)

    # --- 5. 深刻度 (参考情報。flag は立てない) ------------------------------
    now_crit = int((now.get("severity_count") or {}).get("Critical", 0))
    prev_crit = int((prev.get("severity_count") or {}).get("Critical", 0))

    changes = {
        "cve_total": {
            "now": now_total, "prev": prev_total,
            "delta": delta_total, "pct": pct_total, "flag": flag_total,
            # 値の誤解を防ぐ注記 (帰属判断ではない)
            "note": "CVRF 全体の母集団 (Edge/Mariner 等を含む)。集計基準に注意。",
        },
        "heavy": {
            "now": now_heavy, "prev": prev_heavy,
            "ratio": ratio_heavy, "flag": flag_heavy,
            "note": "再起動の重い層 T2+T3 の実数 (人員計画シグナル)。",
        },
        "critical": {
            "now": now_crit, "prev": prev_crit,
            "delta": now_crit - prev_crit,
        },
        "zero_days_total": len(zds),
        "zero_days_uncredited": {"count": zd_uncredited, "flag": flag_zd},
    }

    return {
        "month": month,
        "prev": prev_tag,
        "prev_available": True,
        "changes": changes,
        "new_credits": new_credits,
        "any_flag": any(flags),
        "fetched_at": now.get("fetched_at"),
    }


# --- 人間向けの整形出力 ------------------------------------------------------

def _fmt_pct(p: float | None) -> str:
    return "n/a" if p is None else f"{p:+.1%}"


def _fmt_ratio(r: float | None) -> str:
    return "n/a" if r is None else f"{r:.2f}x"


def render_text(rep: dict) -> str:
    lines: list[str] = []
    lines.append(f"MSRC diff: {rep['month']} vs {rep['prev']}")
    if not rep.get("prev_available"):
        lines.append(f"  {rep['note']}")
        return "\n".join(lines)

    c = rep["changes"]
    F = lambda flag: "  [FLAG]" if flag else ""

    ct = c["cve_total"]
    lines.append(f"  総CVE (CVRF全体): {ct['prev']} -> {ct['now']} "
                 f"({ct['delta']:+d}, {_fmt_pct(ct['pct'])}){F(ct['flag'])}")
    hv = c["heavy"]
    lines.append(f"  重い層 T2+T3:     {hv['prev']} -> {hv['now']} "
                 f"({_fmt_ratio(hv['ratio'])}){F(hv['flag'])}")
    cr = c["critical"]
    lines.append(f"  Critical:         {cr['prev']} -> {cr['now']} "
                 f"({cr['delta']:+d})  (参考)")
    zd = c["zero_days_uncredited"]
    lines.append(f"  ゼロデイ計 {c['zero_days_total']} / "
                 f"うちクレジット無し {zd['count']}{F(zd['flag'])}")

    nc = rep["new_credits"]
    lines.append(f"  新規クレジット名: {len(nc)} 件 (前月に無かったもの・全件)")
    for item in nc:
        mark = "  [FLAG]" if item["flag"] else ""
        lines.append(f"      {item['count']:>4}  {item['name']}{mark}")

    lines.append(f"  => any_flag: {rep['any_flag']}")
    return "\n".join(lines)


def build_report(month: str, prev_tag: str | None = None,
                 th: dict | None = None) -> dict:
    """月タグから差分レポートを組み立てる (CLI/他モジュール共通の入口)。"""
    if th is None:
        th = load_thresholds()
    if prev_tag is None:
        prev_tag = prev_month_tag(month)
    now = load_state(month)
    if now is None:
        raise FileNotFoundError(
            f"当月ファイルが無い: state/{month}.json (先に collect.py を実行)")
    prev = load_state(prev_tag)
    return compute_diff(now, prev, month, prev_tag, th)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="隣接2ヶ月の state を比較し変化と閾値フラグを出す (判断なし)")
    ap.add_argument("month", help="当月タグ 例: 2026-Jul")
    ap.add_argument("--prev", help="比較対象の月タグ (省略時は直前月)")
    ap.add_argument("--json", action="store_true", help="JSON で出力")
    args = ap.parse_args()

    try:
        rep = build_report(args.month, args.prev)
    except FileNotFoundError as e:
        print(f"[diff] エラー: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print(render_text(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
