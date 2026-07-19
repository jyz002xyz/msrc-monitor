#!/usr/bin/env python3
"""
gen_charts.py — build trend charts from frozen state (no hardcoded numbers)

The actual trend figures are read from the frozen values in state/2026-*.json;
nothing is hardcoded. Charts are rendered for both languages to
report/assets/{lang}/chart{1-4}.png.

Usage:
    python gen_charts.py            # both ja and en
    python gen_charts.py --lang ja  # a single language
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

HERE = Path(__file__).resolve().parent
HOME = Path(os.environ.get("MSRC_MONITOR_HOME") or HERE.parent)
STATE = HOME / "state"
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul"]

# Color palette (aligned with the report's navy theme)
NAVY, ACCENT, GREY, RED, GOLD = "#1F3864", "#2E5496", "#8C9BB0", "#C0504D", "#BF9000"


def find_cjk_font() -> font_manager.FontProperties | None:
    """Detect a CJK font at runtime for Japanese charts (environment-agnostic)."""
    candidates = [
        "/System/Library/Fonts/ヒラギノ角ゴシック W4.ttc",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
        "/System/Library/Fonts/Supplemental/BIZ-UDGothic-Regular.ttc",
        "/Library/Fonts/BIZ-UDGothic-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ]
    for p in candidates:
        if os.path.exists(p):
            return font_manager.FontProperties(fname=p)
    # fall back to matching by font name
    for name in ("Hiragino Sans", "BIZ UDGothic", "Yu Gothic",
                 "Noto Sans CJK JP", "Osaka"):
        try:
            path = font_manager.findfont(name, fallback_to_default=False)
            if path:
                return font_manager.FontProperties(fname=path)
        except Exception:
            continue
    return None


def load_trend() -> dict:
    """Read the actual trend figures from frozen state (nothing hardcoded)."""
    out = {k: [] for k in ("cve_all", "cve_core", "crit_all",
                           "heavy_all", "kugel", "ms_internal")}
    for m in MONTHS:
        d = json.loads((STATE / f"2026-{m}.json").read_text())
        t = d.get("tier_count") or {}
        out["cve_all"].append(int(d["cve_total"]))
        out["cve_core"].append(int(d["core_total"]))
        out["crit_all"].append(int((d.get("severity_count") or {}).get("Critical", 0)))
        out["heavy_all"].append(int(t.get("T2", 0)) + int(t.get("T3", 0)))
        out["kugel"].append(int(d.get("kugelblitz", 0)))
        out["ms_internal"].append(int(d.get("ms_internal", 0)))
    return out


# Per-language labels come from config files (never inlined; subject to the anonymization gate).
# The policy of keeping causally-implying names (MDASH, etc.) out of annotations is enforced in the config files.
def load_labels(lang: str) -> dict:
    path = HERE / f"chart_labels_{lang}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def style_ax(ax, fp):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color(GREY)
    ax.spines["bottom"].set_color(GREY)
    ax.tick_params(colors="#333333", labelsize=11)
    ax.grid(axis="y", color="#E5E9F0", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    if fp:
        for lbl in ax.get_xticklabels() + ax.get_yticklabels():
            lbl.set_fontproperties(fp)


def gen_lang(lang: str, trend: dict, fp) -> list[str]:
    L = load_labels(lang)
    months = L["months"]
    outdir = HERE / "assets" / lang
    outdir.mkdir(parents=True, exist_ok=True)
    fpk = {"fontproperties": fp} if fp else {}
    written = []

    def legend(ax):
        (ax.legend(prop=fp, frameon=False, fontsize=10, loc="upper left") if fp
         else ax.legend(frameon=False, fontsize=10, loc="upper left"))

    # Chart 1: total CVE count (all vs core). The "June is the peak" annotation is a fact (observed from state).
    fig, ax = plt.subplots(figsize=(7.2, 3.6), dpi=150)
    ax.plot(months, trend["cve_all"], "-o", color=NAVY, linewidth=2.4, markersize=7, label=L["c1"]["all"], zorder=3)
    ax.plot(months, trend["cve_core"], "-o", color=GREY, linewidth=2.0, markersize=6, label=L["c1"]["core"], zorder=3)
    peak_i = trend["cve_all"].index(max(trend["cve_all"]))
    ax.annotate(L["c1"]["peak"], xy=(peak_i, trend["cve_all"][peak_i]),
                xytext=(max(peak_i - 2, 0.2), max(trend["cve_all"]) * 0.9),
                color=RED, arrowprops=dict(arrowstyle="->", color=RED, lw=1.3), fontsize=10, **fpk)
    ax.set_title(L["c1"]["title"], color=NAVY, fontsize=13, fontweight="bold", pad=12, **fpk)
    ax.set_ylabel(L["count"], fontsize=11, **fpk)
    style_ax(ax, fp); legend(ax); fig.tight_layout()
    p = outdir / "chart1_cve.png"; fig.savefig(p, bbox_inches="tight", facecolor="white"); plt.close(); written.append(str(p))

    # Chart 2: Critical vs the heavy tiers. The numbers in the annotation come from state = fact.
    fig, ax = plt.subplots(figsize=(7.2, 3.6), dpi=150)
    ax.plot(months, trend["crit_all"], "-o", color=NAVY, linewidth=2.4, markersize=7, label=L["c2"]["crit"], zorder=3)
    ax.plot(months, trend["heavy_all"], "-s", color=GOLD, linewidth=2.4, markersize=6, label=L["c2"]["heavy"], zorder=3)
    pi = trend["crit_all"].index(max(trend["crit_all"]))
    note2 = L["c2"]["peak_detail"].format(crit=trend["crit_all"][pi], heavy=trend["heavy_all"][pi])
    ax.annotate(note2, xy=(pi, trend["crit_all"][pi]),
                xytext=(max(pi - 2.4, 0.2), max(trend["crit_all"]) * 0.8),
                color=RED, arrowprops=dict(arrowstyle="->", color=RED, lw=1.3), fontsize=9.5, **fpk)
    ax.set_title(L["c2"]["title"], color=NAVY, fontsize=13, fontweight="bold", pad=12, **fpk)
    ax.set_ylabel(L["count"], fontsize=11, **fpk)
    style_ax(ax, fp); legend(ax); fig.tight_layout()
    p = outdir / "chart2_critical.png"; fig.savefig(p, bbox_inches="tight", facecolor="white"); plt.close(); written.append(str(p))

    # Chart 3: the Kugelblitz cliff (bars). Keep MDASH causal wording out of the title.
    fig, ax = plt.subplots(figsize=(7.2, 3.6), dpi=150)
    kugel = trend["kugel"]
    bars = ax.bar(months, kugel, color=[GREY if v == 0 else RED for v in kugel], zorder=3, width=0.6)
    ax.bar_label(bars, labels=[str(v) if v else "" for v in kugel], color=RED, padding=3, **fpk)
    ax.set_title(L["c3"]["title"].format(n=max(kugel)), color=NAVY, fontsize=12.5, fontweight="bold", pad=12, **fpk)
    ax.set_ylabel(L["count"], fontsize=11, **fpk)
    ax.set_ylim(0, max(max(kugel) + 7, 10))
    style_ax(ax, fp); fig.tight_layout()
    p = outdir / "chart3_kugelblitz.png"; fig.savefig(p, bbox_inches="tight", facecolor="white"); plt.close(); written.append(str(p))

    # Chart 4: surge in internally-discovered issues (bars). Annotation is numbers only (prev->now). MDASH causal implication already removed.
    fig, ax = plt.subplots(figsize=(7.2, 3.6), dpi=150)
    ms = trend["ms_internal"]
    bars = ax.bar(months, ms, color=[ACCENT] * (len(ms) - 1) + [NAVY], zorder=3, width=0.6)
    ax.bar_label(bars, color="#333333", padding=3, **fpk)
    mi = ms.index(max(ms))
    note4 = L["c4"]["note"].format(prev=ms[mi - 1] if mi > 0 else ms[mi], now=ms[mi])
    ax.annotate(note4, xy=(mi, ms[mi]), xytext=(max(mi - 2.7, 0.2), max(ms) * 0.82),
                color=RED, arrowprops=dict(arrowstyle="->", color=RED, lw=1.3), fontsize=9.5, **fpk)
    ax.set_title(L["c4"]["title"], color=NAVY, fontsize=12.5, fontweight="bold", pad=12, **fpk)
    ax.set_ylabel(L["count"], fontsize=11, **fpk)
    ax.set_ylim(0, max(ms) * 1.15)
    style_ax(ax, fp); fig.tight_layout()
    p = outdir / "chart4_internal.png"; fig.savefig(p, bbox_inches="tight", facecolor="white"); plt.close(); written.append(str(p))

    return written


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lang", choices=["ja", "en"], help="both if omitted")
    args = ap.parse_args()
    langs = [args.lang] if args.lang else ["ja", "en"]

    trend = load_trend()
    fp = find_cjk_font()
    if fp is None:
        print("[charts] warning: no CJK font found; Japanese charts may render with missing glyphs.")

    for lang in langs:
        # en needs no CJK (labels are English); only ja uses fp.
        written = gen_lang(lang, trend, fp if lang == "ja" else None)
        print(f"[charts] {lang}: {len(written)} charts -> {HERE/'assets'/lang}")
    print(f"[charts] trend source (frozen state): cve_all={trend['cve_all']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
