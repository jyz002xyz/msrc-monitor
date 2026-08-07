#!/usr/bin/env python3
"""publish.py — render the disclosure record into docs/incidents/ (bilingual).

Facts only: organisation, dates, filing type, links. No interpretation, no summarising of
article prose.

The scope statement is rendered as the SECTION'S DEFINITION, at the top, before any table —
not as a footnote. What this section cannot see is larger than what it can, and a reader who
meets the table first will read it as "incidents", which it is not.

Writes only into docs/incidents/. Nothing else on the site is touched.
"""
from __future__ import annotations

import html
from pathlib import Path

from . import records as records_mod
from . import store as store_mod

CSS = """
:root{color-scheme:light}*{box-sizing:border-box}
body{margin:0;background:#eef0f3;color:#1a1a1a;font-family:-apple-system,BlinkMacSystemFont,
'Segoe UI','Hiragino Kaku Gothic ProN','Noto Sans JP',Arial,sans-serif}
.topbar{position:sticky;top:0;z-index:10;background:#1f3864;color:#fff;display:flex;
align-items:center;justify-content:space-between;padding:10px 18px;font-size:14px}
.topbar a{color:#fff;text-decoration:none;opacity:.92}.topbar a:hover{opacity:1;text-decoration:underline}
.topbar .nav{display:flex;flex-wrap:wrap}.topbar .nav a{margin-left:16px;white-space:nowrap}
.topbar .langpill{border:1px solid rgba(255,255,255,.6);border-radius:14px;padding:3px 13px;margin-left:22px;opacity:1}
.topbar .langpill:hover{background:rgba(255,255,255,.16);text-decoration:none}
.paper{max-width:960px;margin:18px auto 40px;background:#fff;padding:32px 40px;border-radius:8px;
box-shadow:0 2px 12px rgba(0,0,0,.08);overflow-x:auto}
h1{color:#1f3864;font-size:22px;margin:0 0 6px}
h2{color:#1f3864;border-bottom:2px solid #e3e6ea;padding-bottom:4px;margin-top:30px;font-size:17px}
.sub{color:#666;font-size:13px;line-height:1.7}
.scope{background:#fff7e6;border:1px solid #f0d9a8;border-left:4px solid #d99b1c;border-radius:6px;
padding:14px 18px;margin:18px 0 6px;color:#5a4600;font-size:13px;line-height:1.75}
.scope .h{font-weight:700;display:block;margin-bottom:6px}
.scope ul{margin:8px 0 0;padding-left:20px}.scope li{margin:4px 0}
.layer{background:#eef3fb;border:1px solid #c9dcf5;border-left:4px solid #1f3864;border-radius:6px;
padding:12px 16px;margin:10px 0 14px;color:#26364d;font-size:13px;line-height:1.7}
table{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}
th,td{border-bottom:1px solid #eef0f3;padding:7px 10px;text-align:left;vertical-align:top}
th{background:#f0f2f5;font-size:12.5px}
td.org{font-weight:600;color:#1f3864}
.stmt{font-size:12.5px;color:#444;margin:2px 0}
.stmt a{color:#1f3864;text-decoration:none;border-bottom:1px dotted #9ab0d4}
.stmt a:hover{text-decoration:underline}
.amend{color:#7a4e00}
.empty{background:#f5f6f8;border:1px dashed #c9ccd2;border-radius:6px;padding:18px 20px;
color:#555;font-size:13px;line-height:1.7;margin:10px 0}
.xlink{font-size:12px;color:#7a4e00;margin-top:4px}
.xlink a{color:#7a4e00}
.sources{max-width:960px;margin:0 auto 10px;padding:0 20px;color:#666;font-size:12px;line-height:1.7}
.sources a{color:#1f3864}.sources .srchead{font-weight:700;color:#444}
.footer{max-width:960px;margin:0 auto 40px;color:#888;font-size:12px;text-align:center;padding:0 20px}
@media (max-width:640px){.paper{margin:12px;padding:22px 18px}}
"""

# Source, with the terms as published. sec.gov states its information is public and may be
# copied or redistributed, asking for appropriate citation. SEC's seal/logos are not used and
# "SEC"/"EDGAR" appear only as references in text — the section is not affiliated with, nor
# approved by, the SEC.
SOURCE = ("U.S. Securities and Exchange Commission — EDGAR",
          "https://www.sec.gov/edgar/search/")
MAIN_REPORT_SOURCE = ("Microsoft Security Response Center (MSRC) Security Update Guide (CVRF)",
                      "https://msrc.microsoft.com/update-guide")

L = {
    "en": {
        "lang": "en", "site": "MSRC Vulnerability Trend Report",
        "section": "Disclosed cybersecurity incidents",
        "home": "Home", "archive": "Archive", "kev": "Cross-vendor KEV/EPSS",
        "other": "日本語", "other_href": "ja.html",
        "title": "Cybersecurity incidents disclosed to the SEC by US-listed companies",
        "lede": "A record of what was disclosed, and by whom. Facts and links only — no "
                "interpretation, and no retelling of press coverage.",
        "scope_h": "What is in this section, and what is not",
        "scope": [
            "<b>The automatic layer is SEC Form 8-K Item 1.05 only.</b> That item is filed when "
            "the company itself has determined a cybersecurity incident is material. Taking only "
            "1.05 is deliberate: the company decides what counts, not this site.",
            "<b>Japan, Australia and Europe contribute nothing automatically.</b> This is not "
            "because fewer incidents happen there. No such jurisdiction publishes a structured, "
            "per-incident feed. Australia's OAIC, for instance, publishes statistics but no "
            "per-incident record — a count of zero here would mean “cannot be retrieved”, never "
            "“did not happen”. For that reason this section shows no totals and no per-region "
            "counts.",
            "<b>Within the United States, only SEC registrants appear.</b> Item 1.05 binds listed "
            "companies. Private companies, government bodies, non-profits and most healthcare "
            "providers are absent. Healthcare in particular is missing wholesale: the HHS breach "
            "portal is not machine-readable without browser automation, and collecting it was "
            "deferred, not attempted and abandoned.",
            "<b>The curated layer is not comprehensive.</b> It holds incidents an editor chose "
            "to record, and nothing follows from an incident being absent from it.",
        ],
        "auto_h": "Disclosed to the SEC (Item 1.05)",
        "auto_note": "Collected daily. One incident is one company and one date of the earliest "
                     "reported event; the original 8-K and every later 8-K/A amendment are listed "
                     "as separate statements under it. Nothing here is edited after it is recorded.",
        "cur_h": "Editor-recorded incidents",
        "cur_note": "Added by hand, when there is something to record. Each entry lists who stated "
                    "what, and when. A correction is added as a further statement; the earlier one "
                    "stays. Attacker attribution, where present, is recorded as a claim by a named "
                    "party — never as a finding of who was responsible.",
        "empty_auto": "No Item 1.05 disclosure has been recorded yet. Item 1.05 filings are "
                      "genuinely rare — a few per month across all US-listed companies — so an "
                      "empty table is the ordinary state, not a fault.",
        "empty_cur": "No editor-recorded incident yet. This layer is filled in when there is "
                     "something worth recording; it is not filled in on a schedule.",
        "th_org": "Organisation", "th_date": "Event date", "th_stmts": "Statements (filings)",
        "th_type": "Type", "th_when": "Statements",
        "sources_h": "Source", "terms": (
            "Information presented on sec.gov is public information and may be copied or further "
            "distributed; SEC is cited as the source. This section is not affiliated with, "
            "endorsed by, or approved by the SEC."),
        "main_h": "The main report's source",
        "foot": "Facts are machine-collected from public filings; the curated layer is written by "
                "a human. No interpretation is offered here.",
        "also": "Also disclosed to the SEC — see the row above",
    },
    "ja": {
        "lang": "ja", "site": "MSRC 脆弱性動向レポート",
        "section": "開示されたサイバーインシデント",
        "home": "トップへ", "archive": "アーカイブ", "kev": "クロスベンダー KEV/EPSS",
        "other": "English", "other_href": "en.html",
        "title": "米国上場企業が SEC に開示したサイバーインシデント",
        "lede": "「誰が何を開示したか」の記録です。事実とリンクのみで、解釈は書きません。"
                "報道の文章を要約することもしません。",
        "scope_h": "このセクションに入っているもの、入っていないもの",
        "scope": [
            "<b>自動で集めるのは SEC Form 8-K の Item 1.05 だけです。</b>この項目は、"
            "企業自身がそのインシデントを重要と判断したときに提出されます。1.05 に限るのは意図的で、"
            "何を重要とするかを決めるのは当サイトではなく企業自身です。",
            "<b>日本・豪州・欧州は自動では1件も入りません。</b>それらの地域でインシデントが"
            "少ないからではありません。個別事案を構造化して公開する仕組みが存在しないためです。"
            "たとえば豪州 OAIC は統計を公表しますが個別事案の記録は公開していません — "
            "ここでの0件は「取得できない」であって「起きていない」ではありません。"
            "したがって本セクションでは<b>合計件数も地域別件数も示しません</b>。",
            "<b>米国内でも、対象は SEC 登録企業（上場企業）だけです。</b>Item 1.05 の義務を負うのは"
            "上場企業です。非上場企業・政府機関・非営利団体・医療機関の大半は入りません。"
            "とくに医療分野はまるごと欠けます — HHS の侵害ポータルはブラウザ自動化なしには"
            "機械可読でなく、その収集は<b>見送った</b>ものです（試みて断念したのではありません）。",
            "<b>編者が記録する層は網羅的ではありません。</b>編者が選んで記録したものだけで、"
            "そこに無いことから何かが言えるわけではありません。",
        ],
        "auto_h": "SEC への開示（Item 1.05）",
        "auto_note": "日次で収集しています。インシデントは「企業」と「報告された最初の事象の日付」の"
                     "組で識別し、初報の 8-K と以後の 8-K/A（訂正・追報）は、その下に個別の言明として"
                     "並べます。記録した内容は後から書き換えません。",
        "cur_h": "編者が記録したインシデント",
        "cur_note": "記録すべきことがあるときに手で追加します。各エントリは「誰が・いつ・何と述べたか」を"
                    "並べます。訂正は言明の追加として足し、元の言明は残します。攻撃者の帰属がある場合は"
                    "「誰が何を主張したか」として記録し、「誰がやったか」としては書きません。",
        "empty_auto": "Item 1.05 の開示はまだ記録されていません。Item 1.05 の提出は実際に少なく"
                      "（米国上場企業全体で月に数件）、表が空であることは異常ではなく通常の状態です。",
        "empty_cur": "編者が記録したインシデントはまだありません。この層は記録すべきことがあるときに"
                     "書くもので、定期的に埋めるものではありません。",
        "th_org": "組織", "th_date": "事象の日付", "th_stmts": "言明（提出書類）",
        "th_type": "類型", "th_when": "言明",
        "sources_h": "出典", "terms": (
            "sec.gov に掲載された情報は公開情報であり、複製・再配布が可能です。出典として SEC を"
            "明示しています。本セクションは SEC と提携しておらず、SEC の承認・公認を受けたものでは"
            "ありません。"),
        "main_h": "主レポートの出典",
        "foot": "事実は公開された提出書類から機械的に収集しています。編者が記録する層は人間が書いて"
                "います。ここでは解釈を提示しません。",
        "also": "SEC にも開示あり — 上の表を参照",
    },
}


def _h(x) -> str:
    return html.escape(str(x if x is not None else ""), quote=True)


def _topbar(lang: str, *, depth: int = 1) -> str:
    up = "../" * depth
    t = L[lang]
    return (f'<div class="topbar"><a href="{up}index.html">{_h(t["site"])}</a>'
            f'<div class="nav"><a href="{up}index.html">{_h(t["home"])}</a>'
            f'<a href="{up}archive/index.html">{_h(t["archive"])}</a>'
            f'<a href="{up}kev/index.html">{_h(t["kev"])}</a>'
            f'<a class="langpill" href="{t["other_href"]}">{_h(t["other"])}</a></div></div>')


def _scope(lang: str) -> str:
    t = L[lang]
    items = "".join(f"<li>{p}</li>" for p in t["scope"])
    return (f'<div class="scope"><span class="h">{_h(t["scope_h"])}</span>'
            f'<ul>{items}</ul></div>')


def _sources(lang: str) -> str:
    t = L[lang]
    n, u = SOURCE
    mn, mu = MAIN_REPORT_SOURCE
    return (f'<div class="sources"><p class="srchead">{_h(t["sources_h"])}</p>'
            f'<p><a href="{u}" rel="noopener">{_h(n)}</a></p>'
            f'<p>{_h(t["terms"])}</p>'
            f'<p class="srchead">{_h(t["main_h"])}</p>'
            f'<p><a href="{mu}" rel="noopener">{_h(mn)}</a></p></div>')


def _statement_line(s: dict) -> str:
    form = _h(s.get("form"))
    amend = ' class="amend"' if str(s.get("form") or "").endswith("/A") else ""
    items = ", ".join(_h(i) for i in (s.get("items") or []))
    return (f'<div class="stmt"><span{amend}>{_h(s.get("filing_date"))} · {form}</span> '
            f'· items {items} · <a href="{_h(s.get("url"))}" rel="noopener">'
            f'{_h(s.get("adsh"))}</a></div>')


def _auto_table(store: dict, lang: str, linked_keys: set[str]) -> str:
    t = L[lang]
    incs = store.get("incidents") or []
    if not incs:
        return f'<div class="empty">{_h(t["empty_auto"])}</div>'
    rows = []
    for inc in incs:
        stmts = "".join(_statement_line(s) for s in inc["statements"])
        also = (f'<div class="xlink">{_h(t["also"])}</div>'
                if inc["key"] in linked_keys else "")
        rows.append(
            f'<tr><td class="org">{_h(inc["company"])}<div class="stmt">CIK '
            f'{_h(inc["cik"])}</div>{also}</td>'
            f'<td>{_h(inc.get("report_date"))}</td><td>{stmts}</td></tr>')
    return (f'<table><thead><tr><th>{_h(t["th_org"])}</th><th>{_h(t["th_date"])}</th>'
            f'<th>{_h(t["th_stmts"])}</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')


def _record_statements(r: dict, lang: str) -> str:
    out = []
    for s in r.get("statements") or []:
        kind = _h(s.get("kind"))
        retr = f' · retracts {_h(s.get("retracts"))}' if s.get("kind") == "retraction" else ""
        facts = f' — {_h(s.get("facts"))}' if s.get("facts") else ""
        out.append(f'<div class="stmt">{_h(s.get("date"))} · {kind} · '
                   f'<a href="{_h(s.get("url"))}" rel="noopener">{_h(s.get("source"))}</a>'
                   f'{retr}{facts}</div>')
    for c in r.get("attacker_claims") or []:
        out.append(f'<div class="stmt amend">{_h(c.get("date"))} · claim by '
                   f'{_h(c.get("claimed_by"))}: {_h(c.get("claim"))} · '
                   f'<a href="{_h(c.get("url"))}" rel="noopener">source</a></div>')
    return "".join(out)


def _curated_table(doc: dict, lang: str) -> str:
    t = L[lang]
    recs = doc.get("records") or []
    if not recs:
        return f'<div class="empty">{_h(t["empty_cur"])}</div>'
    rows = []
    for r in recs:
        sec = r.get("sec") or {}
        xl = (f'<div class="xlink">SEC: CIK {_h(sec.get("cik"))}'
              f'{" · " + _h(sec.get("adsh")) if sec.get("adsh") else ""}</div>') if sec else ""
        rows.append(
            f'<tr><td class="org">{_h(r.get("organization"))}{xl}</td>'
            f'<td>{_h(r.get("type"))}</td>'
            f'<td>{_record_statements(r, lang)}</td></tr>')
    return (f'<table><thead><tr><th>{_h(t["th_org"])}</th><th>{_h(t["th_type"])}</th>'
            f'<th>{_h(t["th_when"])}</th></tr></thead><tbody>{"".join(rows)}</tbody></table>')


def render(store: dict, recs: dict, lang: str) -> str:
    t = L[lang]
    linked = {k for k in ((r.get("sec") or {}).get("incident_key")
                          for r in (recs.get("records") or [])) if k}
    return f"""<!DOCTYPE html><html lang="{t['lang']}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_h(t['title'])} — {_h(t['site'])}</title>
<meta name="description" content="{_h(t['lede'])}">
<style>{CSS}</style></head><body>
{_topbar(lang)}
<div class="paper">
  <h1>{_h(t['title'])}</h1>
  <p class="sub">{_h(t['lede'])}</p>
  {_scope(lang)}
  <h2>{_h(t['auto_h'])}</h2>
  <div class="layer">{_h(t['auto_note'])}</div>
  {_auto_table(store, lang, linked)}
  <h2>{_h(t['cur_h'])}</h2>
  <div class="layer">{_h(t['cur_note'])}</div>
  {_curated_table(recs, lang)}
</div>
{_sources(lang)}
<div class="footer">{_h(t['foot'])}</div>
</body></html>
"""


def render_index() -> str:
    en, ja = L["en"], L["ja"]
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_h(en['section'])} / {_h(ja['section'])} — MSRC Vulnerability Trend Report</title>
<style>{CSS}</style></head><body>
<div class="topbar"><a href="../index.html">MSRC Vulnerability Trend Report</a>
<div class="nav"><a href="../index.html">Home / トップへ</a>
<a href="../archive/index.html">Archive / アーカイブ</a>
<a href="../kev/index.html">Cross-vendor KEV/EPSS</a></div></div>
<div class="paper">
  <h1>{_h(en['section'])} / {_h(ja['section'])}</h1>
  <p class="sub"><a href="en.html">English</a> · <a href="ja.html">日本語</a></p>
  <p class="sub">{_h(en['lede'])}</p>
  <p class="sub">{_h(ja['lede'])}</p>
  {_scope('en')}
  {_scope('ja')}
</div>
<div class="footer">{_h(en['foot'])}<br>{_h(ja['foot'])}</div>
</body></html>
"""


def build_site(store: dict, recs: dict, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for lang in ("en", "ja"):
        p = out_dir / f"{lang}.html"
        p.write_text(render(store, recs, lang), encoding="utf-8")
        written.append(p)
    p = out_dir / "index.html"
    p.write_text(render_index(), encoding="utf-8")
    written.append(p)
    return written


__all__ = ["build_site", "render", "render_index", "L", "SOURCE",
           "store_mod", "records_mod"]
