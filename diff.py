#!/usr/bin/env python3
"""
diff.py — compare two adjacent months of state summaries and emit "factual changes" and "threshold flags"

What this module does:
    - Compares actual counts between the previous and current month, emitting deltas and percent changes.
    - Raises a flag on changes that exceed a threshold.
    - Lists every credit name that is new this month (absent last month).

What this module does NOT do (design principles; violations are a fail):
    - No attribution. It never guesses the identity of an AI/tool/org from a
      credit name. For new credit names it emits only the name and the count.
      (Lesson from the Kugelblitz=MDASH assertion, refuted by primary sources in 2026-07.)
    - No ratio trends used in decisions. In particular the "uncredited ratio"
      is an artifact of fetch lag, so leave it alone. Work with actual counts only.
    - No interpretation or root-cause analysis. Emit only "what changed and by how much".

Usage:
    python diff.py 2026-Jul                  # compare against the previous month (2026-Jun)
    python diff.py 2026-Jul --prev 2026-Jun  # state the comparison target explicitly
    python diff.py 2026-Jul --json           # JSON output (consumed by draft.py)

Thresholds:
    Loaded from home()/thresholds.json if present, otherwise DEFAULT_THRESHOLDS.
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
    "cve_total_pct": 0.50,      # flag if total CVEs move more than +/-50% MoM
    "heavy_ratio": 1.5,         # flag if T2+T3 is more than 1.5x the previous month
    "new_credit_min_cve": 20,   # flag if a new credit name covers more than 20 CVEs
    "zero_day_uncredited": 1,   # flag if 1 or more zero-days are uncredited
}


def home() -> Path:
    env = os.environ.get("MSRC_MONITOR_HOME")
    return Path(env) if env else Path(__file__).resolve().parent


def state_dir() -> Path:
    return home() / "state"


def load_thresholds() -> dict:
    """Override DEFAULT with home()/thresholds.json if present, otherwise DEFAULT."""
    path = home() / "thresholds.json"
    th = dict(DEFAULT_THRESHOLDS)
    if path.exists():
        try:
            th.update(json.loads(path.read_text()))
        except Exception as e:
            print(f"[diff] warning: failed to load thresholds.json ({e}). "
                  f"Using defaults", file=sys.stderr)
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
    """Actual count of the heavy reboot tiers T2+T3. A staffing signal."""
    tc = state.get("tier_count") or {}
    return int(tc.get("T2", 0)) + int(tc.get("T3", 0))


def compute_diff(now: dict, prev: dict | None, month: str, prev_tag: str,
                 th: dict) -> dict:
    """
    Build a diff report dict from the current month `now` and previous month `prev`.
    When `prev` is None, return "no comparison target" (does not raise).
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

    # --- 1. Change in total CVE count (actual count. Whole CVRF = population) ---
    now_total = int(now.get("cve_total", 0))
    prev_total = int(prev.get("cve_total", 0))
    delta_total = now_total - prev_total
    pct_total = (delta_total / prev_total) if prev_total else None
    flag_total = pct_total is not None and abs(pct_total) > th["cve_total_pct"]
    flags.append(flag_total)

    # --- 2. Change in the heavy tiers T2+T3 (most important. A staffing signal) ---
    now_heavy = heavy_count(now)
    prev_heavy = heavy_count(prev)
    if prev_heavy == 0:
        ratio_heavy = None
        # a 0 -> N jump can't be expressed as a ratio, but it matters, so catch it
        flag_heavy = now_heavy > 0
    else:
        ratio_heavy = round(now_heavy / prev_heavy, 3)
        flag_heavy = ratio_heavy > th["heavy_ratio"]
    flags.append(flag_heavy)

    # --- 3. Detect new credit names (absent last month, present this month; list all) ---
    #     No attribution. Names and counts only. Emphasis flag on threshold exceedance.
    prev_credits = prev.get("credit_counts") or {}
    now_credits = now.get("credit_counts") or {}
    new_credits: list[dict] = []
    for name, count in now_credits.items():
        if name not in prev_credits:
            f = int(count) > th["new_credit_min_cve"]
            new_credits.append({"name": name, "count": int(count), "flag": f})
    # sort descending by count (so a human can scan the full list top-down)
    new_credits.sort(key=lambda x: -x["count"])
    flags.append(any(c["flag"] for c in new_credits))

    # --- 4. Zero-day finders (uncredited count) ---
    #     Never write "found by AI". Just "N zero-days are uncredited".
    zds = now.get("zero_days") or []
    zd_uncredited = sum(1 for z in zds if not z.get("credited"))
    flag_zd = zd_uncredited >= th["zero_day_uncredited"]
    flags.append(flag_zd)

    # --- 5. Severity (reference only. No flag raised) ---
    now_crit = int((now.get("severity_count") or {}).get("Critical", 0))
    prev_crit = int((prev.get("severity_count") or {}).get("Critical", 0))

    changes = {
        "cve_total": {
            "now": now_total, "prev": prev_total,
            "delta": delta_total, "pct": pct_total, "flag": flag_total,
            # note to prevent misreading the value (not an attribution call)
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


# --- Human-readable formatted output ------------------------------------------

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
    lines.append(f"  Total CVEs (whole CVRF): {ct['prev']} -> {ct['now']} "
                 f"({ct['delta']:+d}, {_fmt_pct(ct['pct'])}){F(ct['flag'])}")
    hv = c["heavy"]
    lines.append(f"  Heavy tiers T2+T3:       {hv['prev']} -> {hv['now']} "
                 f"({_fmt_ratio(hv['ratio'])}){F(hv['flag'])}")
    cr = c["critical"]
    lines.append(f"  Critical:                {cr['prev']} -> {cr['now']} "
                 f"({cr['delta']:+d})  (reference)")
    zd = c["zero_days_uncredited"]
    lines.append(f"  Zero-days total {c['zero_days_total']} / "
                 f"uncredited {zd['count']}{F(zd['flag'])}")

    nc = rep["new_credits"]
    lines.append(f"  New credit names: {len(nc)} (absent last month; all listed)")
    for item in nc:
        mark = "  [FLAG]" if item["flag"] else ""
        lines.append(f"      {item['count']:>4}  {item['name']}{mark}")

    lines.append(f"  => any_flag: {rep['any_flag']}")
    return "\n".join(lines)


def build_report(month: str, prev_tag: str | None = None,
                 th: dict | None = None) -> dict:
    """Assemble the diff report from month tags (shared entry point for CLI and other modules)."""
    if th is None:
        th = load_thresholds()
    if prev_tag is None:
        prev_tag = prev_month_tag(month)
    now = load_state(month)
    if now is None:
        raise FileNotFoundError(
            f"current-month file missing: state/{month}.json (run collect.py first)")
    prev = load_state(prev_tag)
    return compute_diff(now, prev, month, prev_tag, th)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compare two adjacent months of state and emit changes and threshold flags (no judgment)")
    ap.add_argument("month", help="current-month tag e.g. 2026-Jul")
    ap.add_argument("--prev", help="comparison month tag (defaults to the previous month)")
    ap.add_argument("--json", action="store_true", help="output JSON")
    args = ap.parse_args()

    try:
        rep = build_report(args.month, args.prev)
    except FileNotFoundError as e:
        print(f"[diff] error: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print(render_text(rep))
    return 0


if __name__ == "__main__":
    sys.exit(main())
