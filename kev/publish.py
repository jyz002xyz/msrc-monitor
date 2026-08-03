#!/usr/bin/env python3
"""publish.py — render sealed/open KEV windows into the public-site layout (bilingual).

Produces docs/kev/-style output: an index plus per-month {ja,en}.html, in the SAME visual
style as the existing msrc-monitor site (reused CSS/topbar), so the KEV section is
consistent with the rest of the site. HTML only (docx/pdf are overkill for a monthly KEV
facts table). No LLM generalization (KEV has no researcher real-names). shortDescription is
kept verbatim in English (source text, not translated).

This module only WRITES a local site tree; it does not push or publish. Placement into the
public repo's docs/kev/ and the go-live are separate, gated steps.
"""
from __future__ import annotations

import datetime as dt
import html
import re
from collections import Counter
from pathlib import Path

import report as _r   # reuse ransomware_split / aggregates helpers
import kevtrack as _k  # days_to_kev

# Per-CVE deep link. NVD is chosen because these pages already display nvd_published, so a
# reader can verify that same date at the same source. Vendor advisories are per-vendor and
# would be inconsistent across a cross-vendor table.
NVD_CVE_BASE = "https://nvd.nist.gov/vuln/detail/"
# Only a well-formed CVE id becomes a link; anything else is rendered as plain text, so a
# malformed/unexpected id can never be interpolated into an href.
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Site CSS reused from the existing public pages (gen_public_html look: dark topbar,
# paper card, amber note). Kept inline so each page is self-contained like the archive.
CSS = """
:root{color-scheme:light}*{box-sizing:border-box}
body{margin:0;background:#eef0f3;color:#1a1a1a;font-family:-apple-system,BlinkMacSystemFont,
'Segoe UI','Hiragino Kaku Gothic ProN','Noto Sans JP',Arial,sans-serif}
.topbar{position:sticky;top:0;z-index:10;background:#1f3864;color:#fff;display:flex;
align-items:center;justify-content:space-between;padding:10px 18px;font-size:14px}
.topbar a{color:#fff;text-decoration:none;opacity:.92}.topbar a:hover{opacity:1;text-decoration:underline}
.topbar .nav a{margin-left:16px}
.topbar .langpill{border:1px solid rgba(255,255,255,.6);border-radius:14px;padding:3px 13px;margin-left:22px;opacity:1}
.topbar .langpill:hover{background:rgba(255,255,255,.16);text-decoration:none}
.tablecaveat{font-size:12px;color:#7a4e00;background:#fff7e6;border:1px solid #f0d9a8;border-left:3px solid #d99b1c;border-radius:6px;padding:8px 12px;margin:2px 0 16px}
.idxlinks a{margin-right:6px;color:#1f3864;font-weight:600;text-decoration:none}.idxlinks a:hover{text-decoration:underline}
.banner{max-width:960px;margin:16px auto 0;padding:10px 16px;border-radius:6px;font-size:13px;line-height:1.6}
.banner.open{background:#fff3cd;border:1px solid #ffe69c;color:#664d03}
.banner.sealed{background:#e7f1e9;border:1px solid #b9d9c1;color:#20502f}
.paper{max-width:960px;margin:18px auto 40px;background:#fff;padding:32px 40px;border-radius:8px;
box-shadow:0 2px 12px rgba(0,0,0,.08);overflow-x:auto}
h1{color:#1f3864;font-size:22px;margin:0 0 6px}h2{color:#1f3864;border-bottom:2px solid #e3e6ea;
padding-bottom:4px;margin-top:26px;font-size:17px}h3{color:#33415c;font-size:15px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}
th,td{border-bottom:1px solid #eef0f3;padding:7px 10px;text-align:left}th{background:#f0f2f5}
th.sortable{cursor:pointer;user-select:none;white-space:nowrap}th.sortable:hover{background:#e7ebf1}
th .caret{opacity:.4;font-size:11px;margin-left:5px}
th[aria-sort="ascending"] .caret::after{content:"\\25B2"}
th[aria-sort="descending"] .caret::after{content:"\\25BC"}
th[aria-sort="none"] .caret::after{content:"\\2195"}
th[aria-sort="ascending"] .caret,th[aria-sort="descending"] .caret{opacity:1}
.notes{background:#eef3fb;border:1px solid #c9dcf5;border-left:4px solid #1f3864;border-radius:6px;
padding:12px 16px;color:#26364d;font-size:13px;line-height:1.7;margin:16px 0}
.sub{color:#666;font-size:13px}.footer{max-width:960px;margin:0 auto 40px;color:#888;font-size:12px;text-align:center}
a.cvelink{color:#1f3864;text-decoration:none;border-bottom:1px dotted #9ab0d4}
a.cvelink:hover{text-decoration:underline}
dl.gloss{margin:8px 0 0}dl.gloss dt{font-weight:700;margin-top:8px}
dl.gloss dd{margin:2px 0 0 14px}
.sources{max-width:960px;margin:0 auto 10px;padding:0 20px;color:#666;font-size:12px;line-height:1.7}
.sources a{color:#1f3864}.sources p{margin:6px 0}.sources .srchead{font-weight:700;color:#444}
"""

# Bilingual UI labels + the confounder/definition notes (both languages, always shown).
LABELS = {
    "ja": {
        "lang": "ja", "site": "MSRC 脆弱性動向レポート",
        "section": "クロスベンダー KEV/EPSS", "home": "トップへ", "other": "English",
        "index_title": "クロスベンダー KEV/EPSS — 月次一覧",
        "positioning": "本セクションは「MSRC 脆弱性動向レポート」（Microsoft 中心）に付随する、"
                       "ベンダー横断の KEV/EPSS セクションです。主レポートが Microsoft 起票の月次を"
                       "扱うのに対し、本セクションは CISA KEV に載った全ベンダーの脆弱性を横断的に記録します。",
        "index_lead": "CISA KEV に月内で追加された脆弱性を、ベンダー横断で記録する。事実の記録であり、"
                      "KEV/EPSS の有効性は論じない。",
        "cols": ["CVE", "ベンダー", "製品", "追加日", "期限", "ランサムウェア", "EPSS/百分位",
                 "NVD 公開日", "公開→収載(日)"],
        "idx_cols": ["年月", "状態", "KEV 追加", "ランサムウェア (Known/Unknown)", "EPSS", "レポート"],
        "state_open": "進行中 / in progress",
        "state_sealed": "確定 / sealed",
        "sort_note": "列見出しをクリックで並べ替え（既定は追加日の降順。JS 無効時もこの順で表示）。EPSS 列はスコアで並べ替え（百分位は併記）。空欄は常に末尾。",
        "col_caveat": "「公開→収載(日)」= KEV 収載日 − NVD 公開日。KEV 収載は悪用開始日ではない"
                      "ため「悪用までの時間」ではない（点在する大きな値は古い CVE の近年収載）。",
        "facts": "事実 (機械生成)", "adds": "窓内の KEV 追加", "agg": "集計",
        "ransom": "ランサムウェア (knownRansomwareCampaignUse)",
        "vendors": "ベンダー別内訳（順位ではない・配備/可視性の反映）",
        "epss_dist": "KEV 追加時点で記録された EPSS スコアの分布（事実・結論は導かない）",
        "epss_blank": "EPSS: このウィンドウは未観測（バックフィル）。EPSS 列は空欄。",
        "notes_h": "定義・注記（データが何であるか）",
        "open_banner": "この窓は進行中です。値は確定しておらず、月末までに KEV が追加される可能性があり、"
                       "後続の公開で更新されます。",
        "sealed_banner": "この窓は確定（sealed・不変）です。",
        "generated": "生成", "prototype": "本セクションはクロスベンダー KEV/EPSS の試作です。",
    },
    "en": {
        "lang": "en", "site": "MSRC Vulnerability Trend Report",
        "section": "Cross-vendor KEV/EPSS", "home": "Home", "other": "日本語",
        "index_title": "Cross-vendor KEV/EPSS — monthly index",
        "positioning": "This is a cross-vendor KEV/EPSS section accompanying the MSRC "
                       "Vulnerability Trend Report (Microsoft-focused). While the main report "
                       "covers Microsoft's monthly CVEs, this section records — across all "
                       "vendors — the vulnerabilities listed in CISA KEV.",
        "index_lead": "Vulnerabilities added to CISA KEV within each month, recorded across "
                      "vendors. A record of facts; it does not assess the validity of KEV or EPSS.",
        "cols": ["CVE", "Vendor", "Product", "Added", "Due", "Ransomware", "EPSS/pctl",
                 "NVD published", "Pub→KEV (days)"],
        "idx_cols": ["Month", "State", "KEV added", "Ransomware (Known/Unknown)", "EPSS", "Report"],
        "state_open": "in progress",
        "state_sealed": "sealed",
        "sort_note": "Click a column header to sort (default: Added descending; this order also shows when JS is off). The EPSS column sorts by score (percentile shown alongside). Blanks always sort last.",
        "col_caveat": "Pub→KEV (days) = KEV listing date minus NVD publication; KEV listing is "
                      "not when exploitation began, so this is NOT time-to-exploitation "
                      "(large values are old CVEs listed recently).",
        "facts": "Facts (machine-generated)", "adds": "KEV additions in the window", "agg": "Aggregates",
        "ransom": "Ransomware (knownRansomwareCampaignUse)",
        "vendors": "By vendor (not a ranking — reflects deployment/visibility)",
        "epss_dist": "Distribution of EPSS scores recorded at KEV-add time (a fact; no conclusion drawn)",
        "epss_blank": "EPSS: this window was not observed (backfill). The EPSS column is blank.",
        "notes_h": "Definitions / notes (what the data is)",
        "open_banner": "This window is in progress. Values are not final; more KEV entries may be "
                       "added before month-end and updated in later publications.",
        "sealed_banner": "This window is final (sealed, immutable).",
        "generated": "Generated", "prototype": "This section is a cross-vendor KEV/EPSS prototype.",
    },
}

# --- "About this data" block -------------------------------------------------
# What the page is, how often it changes, and the vocabulary needed to read the table.
# Orientation only — no evaluative claims, and no hard-coded counts (they change daily; the
# per-month Known/Unknown and KEV-added figures are already in the tables).
ABOUT = {
    "ja": {
        "h": "このデータについて",
        "what_month": "このページは、CISA KEV（悪用が確認された脆弱性のカタログ）に収載された脆弱性を、"
                      "暦月ごとに記録したものです。対象は KEV 収載日（dateAdded）がその月に入るもので、"
                      "ベンダーを問いません（Microsoft 以外も含む）。",
        "what_index": "このセクションは、CISA KEV（悪用が確認された脆弱性のカタログ）に収載された脆弱性を、"
                      "暦月ごとに記録したものです。各行が1か月分で、ベンダーを問いません"
                      "（Microsoft 以外も含む）。",
        "update": "更新頻度: 日次自動更新（GitHub Actions・08:30 JST 予定）。ベストエフォートのため"
                  "遅延することがあり、新規収載がない日は更新されません。増えるのは進行中（open）の"
                  "月だけで、確定（sealed）月のデータは変更しません。",
        "render": "確定（sealed）月のデータは不変ですが、ページの表示は説明の追加・改善に伴って"
                  "再生成されることがあります（データの不変性とは別のことです）。",
        "ransom_caveat": "「ランサムウェア」列の Unknown は CISA が未確認という意味であり、"
                         "「使われていない」という意味ではない。",
        "gloss_h": "用語",
    },
    "en": {
        "h": "About this data",
        "what_month": "This page records the vulnerabilities listed in CISA KEV (the catalog of "
                      "vulnerabilities confirmed as exploited) for one calendar month. A row is "
                      "included when its KEV listing date (dateAdded) falls in that month, "
                      "regardless of vendor (not only Microsoft).",
        "what_index": "This section records the vulnerabilities listed in CISA KEV (the catalog of "
                      "vulnerabilities confirmed as exploited), one row per calendar month, "
                      "across vendors (not only Microsoft).",
        "update": "Update frequency: updated automatically every day (GitHub Actions, scheduled "
                  "08:30 JST). It is best-effort, so it can be delayed, and there is no update on "
                  "a day with no new KEV listings. Only the in-progress (open) month grows; the "
                  "data of a sealed month is never changed.",
        "render": "The data of a sealed month is immutable, but the rendered page may be "
                  "regenerated when explanations are added or improved (that is separate from "
                  "the immutability of the data).",
        "ransom_caveat": "In the “Ransomware” column, Unknown means CISA has not confirmed it — "
                         "not that the vulnerability is unused by ransomware.",
        "gloss_h": "Terms",
    },
}

GLOSSARY = {
    "ja": [
        ("KEV", "CISA Known Exploited Vulnerabilities Catalog。CISA が悪用を確認した脆弱性の一覧で、"
                "連邦機関向けに是正期限（Due）が付く。"),
        ("EPSS（スコア / 百分位）", "スコアは「今後30日以内に悪用活動が観測される確率」で、"
                                    "0 から 1 の値をとる（0.21 ならおよそ 21%）。百分位 (p) は"
                                    "これとは別の軸で、そのスコアが全 CVE の中でどの位置にあるかを示す。"
                                    "p92 は「全 CVE の 92% よりスコアが高い」という意味。スコアは"
                                    "低い側に大きく偏っているため、スコアが小さくても百分位は"
                                    "高く出ることがある。どちらも深刻度ではない。"),
        ("NVD 公開日", "NVD が CVE レコードを公開した日。開示の目安であり、ベンダーの原開示日ではない。"),
        ("公開→収載(日)", "KEV 収載日(dateAdded) − NVD 公開日。0 は同日収載、負値は NVD 公開前の収載。"
                          "悪用までの時間ではない。"),
        ("open（進行中） / sealed（確定）", "open は当月の窓で、月末まで KEV が追加されうる。"
                                            "sealed は暦月が閉じた後に確定した窓で、以後データは変更しない。"),
        ("Known / Unknown", "CISA KEV の knownRansomwareCampaignUse の値。Unknown は「CISA が確認していない」"
                            "であって「使われていない」ではない（下記の注記を参照）。"),
    ],
    "en": [
        ("KEV", "CISA Known Exploited Vulnerabilities Catalog — vulnerabilities CISA has confirmed "
                "as exploited, each with a remediation due date for federal agencies."),
        ("EPSS (score / percentile)", "The score is the probability that exploitation activity will "
                                      "be observed in the next 30 days; it runs from 0 to 1 "
                                      "(0.21 is roughly 21%). The percentile (p) is a separate "
                                      "axis: where that score sits among all CVEs. p92 means the "
                                      "score is higher than 92% of all CVEs. Scores are heavily "
                                      "concentrated at the low end, so a small score can still "
                                      "land in a high percentile. Neither is severity."),
        ("NVD published", "The date NVD published the CVE record — a proxy for disclosure, not the "
                          "vendor's original disclosure date."),
        ("Pub→KEV (days)", "KEV listing date (dateAdded) minus NVD publication date. 0 means listed "
                           "the same day; a negative value means listed before NVD published. It is "
                           "not time-to-exploitation."),
        ("open / sealed", "open is the current month's window — more KEV entries may still be added "
                          "before month-end. sealed is a window finalized after its calendar month "
                          "closed; its data is never changed afterwards."),
        ("Known / Unknown", "The value of CISA KEV's knownRansomwareCampaignUse. Unknown means "
                            "“CISA has not confirmed it”, not “it is not used” "
                            "(see the note below)."),
    ],
}

# --- Data sources -------------------------------------------------------------
# Listed as sources, NOT as an endorsement or a partnership. Terms as published by each
# source (checked): CISA KEV is CC0 1.0 and its license text states that use of the data is
# not an endorsement by CISA or DHS; NIST publications are public domain and the NVD asks
# services that use its API to display a specific notice; FIRST requests attribution when
# EPSS data is used in publications.
SOURCES = [
    ("CISA Known Exploited Vulnerabilities Catalog",
     "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ("FIRST EPSS", "https://www.first.org/epss/"),
    ("NVD (NIST National Vulnerability Database)", "https://nvd.nist.gov/"),
]
# The main (Microsoft-focused) report's source. Not a source of THIS section's data; shown
# only so a reader arriving here can find where the main report's data comes from.
MAIN_REPORT_SOURCE = ("Microsoft Security Response Center (MSRC) Security Update Guide (CVRF)",
                      "https://msrc.microsoft.com/update-guide")
# Verbatim notice the NVD asks API consumers to display (nvd.nist.gov General FAQs).
NVD_NOTICE = ("This product uses data from the NVD API but is not endorsed or certified "
              "by the NVD.")

SOURCE_TERMS = {
    "ja": [
        "CISA KEV は CC0 1.0 で公開されている。データの利用は CISA・DHS による推奨を意味しない。",
        "EPSS は FIRST の EPSS SIG が維持し、スコアは Empirical Security が生成して無償公開している。"
        "利用時には出典の表示が求められている。",
        "NVD は NIST の公開データ（パブリックドメイン）。本セクションは NVD API のデータを使用しているが、"
        "NVD による推奨・認証を受けたものではない: 「" + NVD_NOTICE + "」",
        "上記の組織は本レポートと無関係であり、その内容を推奨するものではない。",
    ],
    "en": [
        "The CISA KEV catalog is published under CC0 1.0. Use of the data does not imply "
        "endorsement by CISA or DHS.",
        "EPSS is maintained by the EPSS SIG at FIRST; the scores are generated by Empirical "
        "Security and published freely. Attribution is requested when the data is used.",
        "NVD data is public domain (NIST). " + NVD_NOTICE,
        "None of the organizations above are affiliated with this report, and none of them "
        "endorse its contents.",
    ],
}
SOURCE_LABELS = {
    "ja": {"h": "出典データ", "main": "主レポート（Microsoft 中心）の出典"},
    "en": {"h": "Data sources", "main": "Source of the main report (Microsoft-focused)"},
}

NOTES = {
    "ja": [
        "KEV は悪用の完全な記録ではない。CISA が確認し、連邦機関向けに優先付けしたもの。",
        "「ランサムウェア」列の出典は CISA KEV の knownRansomwareCampaignUse。Known は CISA が"
        "ランサムウェアキャンペーンでの使用を確認したもの。Unknown は CISA が確認していないという"
        "意味であり、「ランサムウェアで使われていない」という意味ではない。カタログ全体では"
        "Unknown が多数を占めるため、Unknown を「安全」と読むと系統的に誤る。",
        "EPSS は「30日以内に悪用活動が観測される確率」であって深刻度ではない。KEV 追加時点で"
        "記録した属性として提示し、予測の当否は評価しない。",
        "ベンダー別件数は、連邦環境での配備状況と CISA の可視性を反映するものであり、"
        "セキュリティ品質の順位ではない。ベンダーを件数で順位付けしない。",
        "バックフィルした過去月は EPSS 空欄（観測時点の値のみ記録し、現在値では埋めない）。",
        "「NVD 公開日」は NVD が CVE レコードを公開した日であり、ベンダーの原開示日ではない"
        "（近いが遅れうる）。",
        "「公開→収載(日)」= KEV 収載日(dateAdded) − NVD 公開日。KEV 収載日は CISA が KEV に載せた日"
        "であって悪用開始日ではない。よって本値は「悪用までの時間」ではない。",
        "要約統計（中央値・平均）は出さない。古い CVE の近年収載と新規開示の速やかな収載は"
        "質的に異なり「典型的な日数」は意味を持たないため。CVE ごとの値をそのまま提示する。",
    ],
    "en": [
        "KEV is not a complete record of exploitation; it is what CISA confirmed and prioritized "
        "for federal agencies.",
        "The “Ransomware” column comes from CISA KEV's knownRansomwareCampaignUse. Known = CISA "
        "has confirmed use in a ransomware campaign. Unknown = CISA has NOT confirmed it; it does "
        "not mean the vulnerability is unused by ransomware. Unknown is the majority of the "
        "catalog, so reading Unknown as “safe” is a systematic error.",
        "EPSS is the probability of exploitation activity within 30 days — not severity. It is "
        "presented as an attribute recorded at KEV-add time; its predictive correctness is not judged.",
        "Vendor counts reflect federal deployment and CISA visibility, not security quality. "
        "Vendors are never ranked by count.",
        "Backfilled past windows leave EPSS blank (only observed-time values are recorded; current "
        "values are not back-filled).",
        "“NVD published” is the date NVD published the CVE record — a proxy for "
        "disclosure, NOT the vendor's original disclosure date (it can lag).",
        "“Pub→KEV (days)” = KEV listing date (dateAdded) minus NVD publication date. "
        "The KEV listing date is when CISA added it to KEV, NOT when exploitation began; so this is "
        "NOT time-to-exploitation.",
        "No summary statistics (median/mean) are given: a decades-old CVE listed recently and a "
        "just-disclosed CVE listed promptly are qualitatively different, so a “typical” "
        "figure is not meaningful. Per-CVE values are shown as-is.",
    ],
}


def _h(x) -> str:
    return html.escape("" if x is None else str(x))


def _epss_cell(r) -> str:
    return "—" if r["epss"] is None else f"{r['epss']:.3f} / p{r['percentile']*100:.0f}"


def _cve_cell(cve) -> str:
    """CVE cell linking to its NVD record. The sort key (data-sort) stays the plain CVE id, so
    the column-click sort is unaffected; only the cell's text becomes a link."""
    key = _h(cve or "")
    if cve and CVE_ID_RE.match(cve):
        inner = f'<a class="cvelink" href="{NVD_CVE_BASE}{key}" rel="noopener">{key}</a>'
    else:
        inner = key                      # unexpected id -> plain text, never a link
    return f'<td data-sort="{key}">{inner}</td>'


def _about_html(lang: str, *, index: bool) -> str:
    """"About this data" block: what the page is, how often it updates, and the fact that a
    sealed month's DATA is fixed even though the page may be re-rendered."""
    a = ABOUT[lang]
    what = a["what_index"] if index else a["what_month"]
    return (f"<div class='notes'><b>{_h(a['h'])}</b>"
            f"<ul><li>{_h(what)}</li><li>{_h(a['update'])}</li><li>{_h(a['render'])}</li></ul></div>")


def _glossary_html(lang: str) -> str:
    items = "".join(f"<dt>{_h(t)}</dt><dd>{_h(d)}</dd>" for t, d in GLOSSARY[lang])
    return f"<b>{_h(ABOUT[lang]['gloss_h'])}</b><dl class='gloss'>{items}</dl>"


def _sources_html(langs: list[str]) -> str:
    """Data-source list with links + the terms/non-endorsement lines. Listing a source is not
    a claim of affiliation or endorsement; the wording says so explicitly."""
    blocks = []
    for lang in langs:
        sl = SOURCE_LABELS[lang]
        links = " · ".join(f"<a href='{u}' rel='noopener'>{_h(n)}</a>" for n, u in SOURCES)
        main_n, main_u = MAIN_REPORT_SOURCE
        terms = " ".join(_h(t) for t in SOURCE_TERMS[lang])
        blocks.append(f"<p><span class='srchead'>{_h(sl['h'])}:</span> {links}</p>"
                      f"<p>{terms}</p>"
                      f"<p>{_h(sl['main'])}: "
                      f"<a href='{main_u}' rel='noopener'>{_h(main_n)}</a></p>")
    return "<div class='sources'>" + "".join(blocks) + "</div>"


def render_month(snap: dict, lang: str) -> str:
    L, N = LABELS[lang], NOTES[lang]
    agg = _r._aggregates(snap)
    known, unknown = _r.ransomware_split(snap)
    is_open = snap.get("state") == "open"
    state = L["state_open"] if is_open else L["state_sealed"]
    banner = L["open_banner"] if is_open else L["sealed_banner"]
    other = f"{'en' if lang == 'ja' else 'ja'}.html"

    # Default display order = dateAdded DESCENDING (newest first), deterministic tie-break
    # (same day -> CVE id ascending). Generation-time; snapshot data is unchanged.
    disp = sorted(snap["kev_added"], key=lambda r: (r.get("cve") or ""))
    disp = sorted(disp, key=lambda r: (r.get("date_added") or ""), reverse=True)

    def _c(display, key):   # td with an explicit data-sort key ("" -> sorts last)
        return f'<td data-sort="{_h("" if key is None else str(key))}">{_h(display)}</td>'
    trs = []
    for r in disp:
        pub = (r.get("nvd_published") or "")[:10]
        d = _k.days_to_kev(r)
        rw = "Known" if r["ransomware"] else "Unknown"
        trs.append(
            "<tr>"
            + _cve_cell(r["cve"]) + _c(r.get("vendor") or "", r.get("vendor") or "")
            + _c(r.get("product") or "", r.get("product") or "")
            + _c(r.get("date_added") or "", r.get("date_added") or "")
            + _c(r.get("due_date") or "", r.get("due_date") or "")
            + _c(rw, rw)
            + _c(_epss_cell(r), "" if r.get("epss") is None else r["epss"])   # sort by EPSS score
            + _c(pub or "—", pub)
            + _c("—" if d is None else str(d), "" if d is None else d)        # numeric, negatives ok
            + "</tr>")
    rows = "\n".join(trs)
    vend = "".join(f"<li>{_h(v)}: {c}</li>" for v, c in agg["vendors"].most_common())
    dist = (f"<p><b>{_h(L['epss_dist'])}:</b> "
            + ", ".join(f"{_h(k)}={v}" for k, v in agg["dist"].items()) + "</p>") \
        if agg["dist"] else f"<p class='sub'>{_h(L['epss_blank'])}</p>"
    corr = ""
    if snap.get("corrections"):
        items = "".join(f"<li>{_h(c)}</li>" for c in snap["corrections"])
        corr = f"<div class='notes'><b>corrections:</b><ul>{items}</ul></div>"
    notes = "".join(f"<li>{_h(n)}</li>" for n in N)
    # sortable headers. Types: CVE/Vendor/Product/Ransomware=text, Added/Due/NVD=date,
    # EPSS/Days=num. Default sort = Added (index 3) descending, matching the row order above.
    col_types = ["text", "text", "text", "date", "date", "text", "num", "date", "num"]
    default_col = 3
    th = "".join(
        f'<th class="sortable" data-type="{col_types[i]}" '
        f'aria-sort="{"descending" if i == default_col else "none"}">'
        f'{_h(c)}<span class="caret"></span></th>'
        for i, c in enumerate(L["cols"]))
    return f"""<!DOCTYPE html><html lang="{L['lang']}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_h(L['section'])} {_h(snap['window'])} — {_h(L['site'])}</title>
<style>{CSS}</style></head><body>
<div class="topbar"><a href="../../index.html">{_h(L['site'])}</a>
<div class="nav"><a href="../index.html">{_h(L['section'])}</a><a href="../../index.html">{_h(L['home'])}</a>
<a class="langpill" href="{other}">{_h(L['other'])}</a></div></div>
<div class="banner {'open' if is_open else 'sealed'}"><b>{_h(state)}.</b> {_h(banner)}</div>
<article class="paper">
<h1>{_h(L['section'])} — {_h(snap['window'])}</h1>
<div class="notes">{_h(L['positioning'])}</div>
{_about_html(lang, index=False)}
<p class="sub">{_h(L['generated'])} {_h(snap['generated_at'])}. {_h(L['prototype'])}</p>
{corr}
<h2>{_h(L['facts'])}</h2>
<h3>{_h(L['adds'])} ({agg['n']})</h3>
<table id="kevtable"><thead><tr>{th}</tr></thead><tbody>{rows}</tbody></table>
<div class="tablecaveat">{_h(L['col_caveat'])}<br>{_h(ABOUT[lang]['ransom_caveat'])}</div>
<p class="sub">{_h(L['sort_note'])}</p>
<script>
(function(){{
  var t=document.getElementById('kevtable'); if(!t||!t.tHead) return;
  var ths=t.tHead.rows[0].cells, tb=t.tBodies[0];
  for(var i=0;i<ths.length;i++){{(function(idx){{
    var th=ths[idx]; if((th.className||'').indexOf('sortable')<0) return;
    th.addEventListener('click',function(){{
      var dir=th.getAttribute('aria-sort')==='ascending'?'descending':'ascending';
      for(var j=0;j<ths.length;j++) ths[j].setAttribute('aria-sort','none');
      th.setAttribute('aria-sort',dir);
      var type=th.getAttribute('data-type')||'text', sgn=dir==='ascending'?1:-1;
      var rows=Array.prototype.slice.call(tb.rows);
      rows.sort(function(ra,rb){{
        var a=ra.cells[idx].getAttribute('data-sort'), b=rb.cells[idx].getAttribute('data-sort');
        var ea=(a===''||a==null), eb=(b===''||b==null);
        if(ea||eb){{ return ea&&eb?0:(ea?1:-1); }}   /* blanks always last, both directions */
        var r = type==='num' ? (parseFloat(a)-parseFloat(b)) : (a<b?-1:(a>b?1:0));
        return sgn*r;
      }});
      rows.forEach(function(r){{tb.appendChild(r);}});
    }});
  }})(i);}}
}})();
</script>
<h3>{_h(L['agg'])}</h3>
<p>{_h(L['ransom'])}: <b>Known {known} / Unknown {unknown}</b></p>
<p>{_h(L['vendors'])}:</p><ul>{vend}</ul>{dist}
<h2>{_h(L['notes_h'])}</h2>
<div class="notes">{_glossary_html(lang)}<ul>{notes}</ul></div>
</article>
{_sources_html([lang])}
<div class="footer">{_h(L['site'])} · {_h(L['section'])}</div>
</body></html>"""


def render_index(snaps: list[dict]) -> str:
    # Bilingual order English-first per the site convention (msrc_monitor
    # docs/SITE_BILINGUAL_CONVENTION.md). Single-language month pages keep own language first.
    """Single BILINGUAL index, English-first (EN / JA): one table, both language links per
    row, so either-language readers reach everything from one row. Single-language month
    pages keep their own language first; only this index is English-first."""
    rows = sorted(snaps, key=lambda s: s["window"], reverse=True)
    ja, en = LABELS["ja"], LABELS["en"]
    # bilingual headers, English first
    headers = ["Month / 年月", "State / 状態", "KEV added / KEV 追加",
               "Ransomware (Known/Unknown) / ランサムウェア", "EPSS", "Report / レポート"]
    th = "".join(f"<th>{_h(c)}</th>" for c in headers)
    tr = []
    for s in rows:
        n = s["count"]
        k = sum(1 for r in s["kev_added"] if r["ransomware"])
        st = "in progress / 進行中" if s.get("state") == "open" else "sealed / 確定"
        ep = "observed" if s["epss_observed"] else "blank"
        m = s["window"]
        tr.append(f"<tr><td>{m}</td><td>{_h(st)}</td><td>{n}</td>"
                  f"<td>Known {k} / Unknown {n-k}</td><td>{ep}</td>"
                  f"<td class='idxlinks'><a href='{m}/en.html'>English</a> · "
                  f"<a href='{m}/ja.html'>日本語</a></td></tr>")
    notes = "".join(f"<li>{_h(x)}</li>" for x in (NOTES["en"] + NOTES["ja"]))
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cross-vendor KEV/EPSS — MSRC Vulnerability Trend Report</title>
<style>{CSS}</style></head><body>
<div class="topbar"><a href="../index.html">MSRC Vulnerability Trend Report</a>
<div class="nav"><a href="../index.html">Home / トップへ</a></div></div>
<article class="paper">
<h1>{_h(en['index_title'])}<br><span style="font-size:16px;color:#33415c">{_h(ja['index_title'])}</span></h1>
<div class="notes">{_h(en['positioning'])}<br><br>{_h(ja['positioning'])}</div>
{_about_html("en", index=True)}
{_about_html("ja", index=True)}
<p class="sub">{_h(en['index_lead'])} {_h(en['prototype'])}<br>{_h(ja['index_lead'])}</p>
<table><thead><tr>{th}</tr></thead><tbody>{''.join(tr)}</tbody></table>
<div class="tablecaveat">{_h(ABOUT['en']['ransom_caveat'])}<br>{_h(ABOUT['ja']['ransom_caveat'])}</div>
<h2>Definitions &amp; notes / 定義・注記</h2>
<div class="notes">{_glossary_html("en")}{_glossary_html("ja")}<ul>{notes}</ul></div>
</article>
{_sources_html(["en", "ja"])}
<div class="footer">MSRC Vulnerability Trend Report · Cross-vendor KEV/EPSS (prototype)</div>
</body></html>"""


def build_site(snaps: list[dict], kev_dir: Path) -> None:
    """Write the docs/kev/-style tree: index.html + {month}/{ja,en}.html."""
    kev_dir.mkdir(parents=True, exist_ok=True)
    (kev_dir / "index.html").write_text(render_index(snaps), encoding="utf-8")
    for s in snaps:
        d = kev_dir / s["window"]
        d.mkdir(parents=True, exist_ok=True)
        for lang in ("ja", "en"):
            (d / f"{lang}.html").write_text(render_month(s, lang), encoding="utf-8")
