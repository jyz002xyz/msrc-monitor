#!/usr/bin/env python3
"""report.py — render a cross-vendor KEV/EPSS snapshot to Markdown + standalone HTML.

DESCRIPTIVE, not evaluative: the report RECORDS and PRESENTS facts. It does NOT assess
the predictive validity of EPSS or KEV. EPSS scores are shown as an attribute recorded at
the time of KEV addition; no "miss / blind spot / prediction failed" framing. Definitional
notes (what the data is) are always emitted to prevent misreading. No external deps.
"""
from __future__ import annotations

import html
from collections import Counter

# Definitional / process notes — descriptions of what the data IS, not claims about it.
NOTES = [
    "EPSS は「30日以内に悪用活動が観測される確率」であって深刻度ではない。",
    "EPSS スコアは KEV 追加時点で記録した属性として提示する。予測の当否は評価しない。",
    "KEV は悪用の完全な記録ではない。CISA が確認し、連邦機関向けに優先付けしたもの。",
    "ベンダー別件数は、連邦環境での配備状況と CISA の可視性を反映するものであり、"
    "セキュリティ品質の順位ではない。",
    "ベンダーを件数で順位付けしない（数え方がベンダーで異なる）。",
    "「NVD 公開日」は NVD が CVE レコードを公開した日であり、原開示日ではない（近いが遅れうる）。"
    "「公開→収載(日)」= dateAdded − NVD 公開日で、KEV 収載は悪用開始日ではないため「悪用までの時間」"
    "ではない。要約統計は出さず CVE ごとの値をそのまま提示する。",
    "事実と解釈は分離。凍結スナップショットは不変。命名・タイミングから因果を断定しない"
    "（Kugelblitz）。公開前に人間が確認する。",
]


def _fmt_epss(row) -> str:
    if row["epss"] is None:
        return "—"
    return f"{row['epss']:.3f} / p{row['percentile']*100:.0f}"


def ransomware_split(snap) -> tuple[int, int]:
    """(Known, Unknown). KEV's knownRansomwareCampaignUse is strictly Known/Unknown, so
    non-Known == Unknown. Written out explicitly so a 0 never reads as 'not applicable'."""
    known = sum(1 for r in snap["kev_added"] if r["ransomware"])
    return known, snap["count"] - known


def _aggregates(snap) -> dict:
    rows = snap["kev_added"]
    vendors = Counter(r["vendor"] or "(unknown)" for r in rows)
    known, unknown = ransomware_split(snap)
    dist = None
    if snap["epss_observed"]:
        buckets = {"<0.05": 0, "0.05–0.20": 0, "0.20–0.50": 0, "≥0.50": 0, "n/a": 0}
        for r in rows:
            e = r["epss"]
            if e is None:
                buckets["n/a"] += 1
            elif e < 0.05:
                buckets["<0.05"] += 1
            elif e < 0.20:
                buckets["0.05–0.20"] += 1
            elif e < 0.50:
                buckets["0.20–0.50"] += 1
            else:
                buckets["≥0.50"] += 1
        dist = buckets
    return {"n": len(rows), "vendors": vendors, "known": known, "unknown": unknown, "dist": dist}


# --- Markdown ----------------------------------------------------------------
def render_markdown(snap) -> str:
    agg = _aggregates(snap)
    L: list[str] = []
    L.append(f"# Cross-vendor KEV/EPSS — {snap['window']}")
    state_label = ("**OPEN — 進行中 / in progress（値は未確定・月末まで追加されうる）**"
                   if snap.get("state") == "open" else "**SEALED — 確定（immutable）**")
    epss_state = ("EPSS observed (recorded at first sighting)" if snap["epss_observed"]
                  else "EPSS blank (backfilled window — observed-time EPSS not available; "
                       "current values are NOT back-filled)")
    L.append(f"*State: {state_label}. KEV additions: **{agg['n']}**. {epss_state}. "
             f"Generated {snap['generated_at']}.*\n")
    if snap.get("corrections"):
        L.append("> **訂正記録 (corrections):**")
        for c in snap["corrections"]:
            L.append(f"> - {c}")
        L.append("")

    L.append("## 事実 (machine-generated)\n")
    L.append("### 窓内の KEV 追加")
    L.append("| CVE | Vendor | Product | Added | Due | Ransomware | EPSS/pctl | NVD pub | Pub→KEV(d) |")
    L.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    import kevtrack as _k
    for r in snap["kev_added"]:
        pub = (r.get("nvd_published") or "")[:10] or "—"
        d = _k.days_to_kev(r)
        L.append(f"| {r['cve']} | {r['vendor'] or ''} | {r['product'] or ''} | "
                 f"{r['date_added'] or ''} | {r['due_date'] or ''} | "
                 f"{'Known' if r['ransomware'] else 'Unknown'} | {_fmt_epss(r)} | "
                 f"{pub} | {'—' if d is None else d} |")
    L.append("")

    L.append("### 集計")
    L.append(f"- ランサムウェア (`knownRansomwareCampaignUse`): "
             f"**Known {agg['known']} 件 / Unknown {agg['unknown']} 件**")
    L.append("- ベンダー別内訳（**順位ではない**・配備/可視性の反映）:")
    for v, c in agg["vendors"].most_common():
        L.append(f"    - {v}: {c}")
    if agg["dist"]:
        L.append("- KEV 追加時点で記録された EPSS スコアの分布（事実。ここから結論は導かない）: "
                 + ", ".join(f"{k}={v}" for k, v in agg["dist"].items()))
    else:
        L.append("- EPSS: このウィンドウは未観測（バックフィル）。EPSS 列は空欄。")
    L.append("")

    L.append("## 定義・注記（データが何であるか）")
    for c in NOTES:
        L.append(f"- {c}")
    L.append("")
    return "\n".join(L)


# --- HTML (standalone, local preview only) -----------------------------------
_CSS = """body{font-family:-apple-system,'Hiragino Sans',Arial,sans-serif;max-width:920px;
margin:0 auto;padding:28px 20px;color:#1a1a1a;background:#f6f7f9}
h1{color:#1f3864}h2{color:#1f3864;border-bottom:2px solid #e3e6ea;padding-bottom:4px;margin-top:28px}
h3{color:#33415c}table{border-collapse:collapse;width:100%;background:#fff;font-size:13px;
box-shadow:0 1px 6px rgba(0,0,0,.06);margin:10px 0}th,td{border-bottom:1px solid #eef0f3;
padding:7px 10px;text-align:left}th{background:#f0f2f5}
.note{background:#eef3fb;border:1px solid #c9dcf5;border-left:4px solid #1f3864;
border-radius:6px;padding:12px 16px;color:#26364d;font-size:13px;line-height:1.7;margin:16px 0}
.sub{color:#666;font-size:13px}"""


def _h(x) -> str:
    return html.escape("" if x is None else str(x))


def render_html(snap) -> str:
    agg = _aggregates(snap)
    state_label = ("OPEN — 進行中 / in progress（未確定）" if snap.get("state") == "open"
                   else "SEALED — 確定 (immutable)")
    epss_state = ("EPSS observed (recorded at first sighting)" if snap["epss_observed"]
                  else "EPSS blank (backfilled window — current values NOT back-filled)")
    corr = ""
    if snap.get("corrections"):
        items = "".join(f"<li>{_h(c)}</li>" for c in snap["corrections"])
        corr = f"<div class='note'><b>訂正記録 (corrections):</b><ul>{items}</ul></div>"
    rows = "\n".join(
        f"<tr><td>{_h(r['cve'])}</td><td>{_h(r['vendor'])}</td><td>{_h(r['product'])}</td>"
        f"<td>{_h(r['date_added'])}</td><td>{_h(r['due_date'])}</td>"
        f"<td>{'Known' if r['ransomware'] else 'Unknown'}</td><td>{_h(_fmt_epss(r))}</td></tr>"
        for r in snap["kev_added"])
    vend = "".join(f"<li>{_h(v)}: {c}</li>" for v, c in agg["vendors"].most_common())
    if agg["dist"]:
        dist = ("<p><b>KEV 追加時点で記録された EPSS スコアの分布</b>（事実・結論は導かない）: "
                + ", ".join(f"{_h(k)}={v}" for k, v in agg["dist"].items()) + "</p>")
    else:
        dist = "<p class='sub'>EPSS: 未観測（バックフィル）。</p>"
    note = "".join(f"<li>{_h(c)}</li>" for c in NOTES)
    return f"""<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cross-vendor KEV/EPSS — {_h(snap['window'])} (PROTOTYPE, local)</title>
<style>{_CSS}</style></head><body>
<h1>Cross-vendor KEV/EPSS — {_h(snap['window'])}</h1>
<p class="sub"><b>State: {_h(state_label)}.</b> KEV additions: <b>{agg['n']}</b>. {_h(epss_state)}.
Generated {_h(snap['generated_at'])}.<br><b>Phase 1 prototype — local only, not published.</b></p>
{corr}
<h2>事実 (machine-generated)</h2>
<h3>窓内の KEV 追加</h3>
<table><thead><tr><th>CVE</th><th>Vendor</th><th>Product</th><th>Added</th><th>Due</th>
<th>Ransomware</th><th>EPSS/pctl</th></tr></thead><tbody>{rows}</tbody></table>
<h3>集計</h3>
<p>ランサムウェア (<code>knownRansomwareCampaignUse</code>):
<b>Known {agg['known']} 件 / Unknown {agg['unknown']} 件</b></p>
<p>ベンダー別内訳（<b>順位ではない</b>・配備/可視性の反映）:</p><ul>{vend}</ul>{dist}
<h2>定義・注記（データが何であるか）</h2>
<div class="note"><ul>{note}</ul></div>
</body></html>"""
