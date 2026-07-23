#!/usr/bin/env python3
"""gen_archive.py — Phase A: additive, non-invasive month archive for the public site.

Reads the CURRENTLY published report pages under docs/ (docs/report_{ja,en}.html +
docs/assets/) and files an immutable, self-contained copy under
docs/archive/YYYY-MM/{ja,en}.html (+ its own assets/), then regenerates
docs/archive/index.html (a month list) from docs/archive/manifest.json.

Design principles:
  - Additive only. The live "latest" pages (docs/index.html, docs/report_*.html) are
    NEVER modified. Method D is not touched (Phase B will wire archiving into it).
  - Idempotent. A month that already exists in the archive is left untouched (frozen
    snapshots are immutable); re-running only (re)builds the index.
  - Self-contained. Each month copies its own assets, so a snapshot never breaks when
    the latest assets change.
  - No fabricated data. The per-month "count" is optional; if unknown it is shown as
    "—" rather than invented.

Usage:
    python report/gen_archive.py --month 2026-07 [--count 1281]
    python report/gen_archive.py --rebuild-index-only
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MONTH_RE = re.compile(r"^\d{4}-\d{2}$")


def _load_manifest(archive_dir: Path) -> dict:
    p = archive_dir / "manifest.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"months": []}


def _save_manifest(archive_dir: Path, manifest: dict) -> None:
    # stable order: newest month first, deterministic
    manifest["months"].sort(key=lambda m: m["month"], reverse=True)
    (archive_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _rewrite_report_links(html: str) -> str:
    """Rewrite a published report page's nav/footer links for its archive location
    (docs/archive/YYYY-MM/). The live pages are copied, never modified in place."""
    # cross-language links: report_{ja,en}.html -> {ja,en}.html (siblings in the month dir)
    html = html.replace("report_ja.html", "ja.html").replace("report_en.html", "en.html")
    # "top / latest" links point back up to the live site root
    html = html.replace('href="index.html"', 'href="../../index.html"')
    return html


def _inject_archive_banner(html: str, month: str) -> str:
    """Add a small, inline-styled banner marking this as an archived snapshot, with a
    link to the latest report and to the archive index. Inline style => no CSS edits."""
    banner = (
        '<div style="background:#fff3cd;border-bottom:1px solid #ffe69c;color:#664d03;'
        'padding:8px 16px;font-size:13px;text-align:center">'
        f'\U0001F4C4 アーカイブ版スナップショット（{month}） / Archived snapshot ({month}) — '
        '<a href="../../index.html" style="color:#664d03;font-weight:700">最新レポート / Latest</a> · '
        '<a href="../index.html" style="color:#664d03;font-weight:700">アーカイブ一覧 / All archives</a>'
        '</div>'
    )
    # place it immediately after <body ...>
    return re.sub(r"(<body[^>]*>)", r"\1\n" + banner, html, count=1)


def _recorded_subject(dest: Path) -> str | None:
    """The subject-month recorded in a frozen slot's meta.json, or None when the slot
    has no meta.json / no recorded subject (a legacy snapshot predating this field)."""
    meta_p = dest / "meta.json"
    if not meta_p.exists():
        return None
    try:
        return json.loads(meta_p.read_text(encoding="utf-8")).get("subject")
    except (ValueError, OSError):
        return None


def archive_month(month: str, docs: Path, count: int | None, subject: str) -> bool:
    """File the current published report as archive/<month>/. Returns True if newly
    created, False if it already existed as a genuine idempotent re-run.

    Slot-collision guard (fail-halt): an existing slot is only skipped when its
    recorded subject-month matches the incoming one (the same month re-run). If the
    slot exists but records a DIFFERENT subject-month — or records none at all — this
    is a mis-key that would silently drop the incoming report, so we halt (exit 3)
    instead of skipping. This is what makes Phase B's freeze fail loudly rather than
    quietly no-op when a slot key collides with a different report."""
    archive_dir = docs / "archive"
    dest = archive_dir / month
    if dest.exists():
        recorded = _recorded_subject(dest)
        if recorded == subject:
            print(f"[archive] {month} already archived (immutable, subject "
                  f"{subject}) — skipping copy")
            return False
        if recorded is None:
            print(f"[archive] HALT: slot {month}/ already exists but records no "
                  f"subject-month; refusing to skip (incoming subject {subject!r}). "
                  f"The slot may be mis-keyed — resolve manually before retrying.",
                  file=sys.stderr)
        else:
            print(f"[archive] HALT: slot {month}/ is occupied by subject-month "
                  f"{recorded!r}, but the incoming report's subject-month is "
                  f"{subject!r}. Skipping would silently drop the incoming report. "
                  f"Re-key the occupying slot (see docs/archive/REKEY.md) first.",
                  file=sys.stderr)
        sys.exit(3)

    # inputs: the currently published report + assets
    missing = [f"report_{l}.html" for l in ("ja", "en")
               if not (docs / f"report_{l}.html").exists()]
    if missing:
        print(f"[archive] ERROR: published pages missing: {missing}", file=sys.stderr)
        sys.exit(2)

    dest.mkdir(parents=True, exist_ok=False)
    for lang in ("ja", "en"):
        html = (docs / f"report_{lang}.html").read_text(encoding="utf-8")
        html = _rewrite_report_links(html)
        html = _inject_archive_banner(html, month)
        (dest / f"{lang}.html").write_text(html, encoding="utf-8")
        # self-contained assets: copy this language's images into the month dir
        src_assets = docs / "assets" / lang
        if src_assets.exists():
            shutil.copytree(src_assets, dest / "assets" / lang)
    (dest / "meta.json").write_text(
        json.dumps({"month": month, "count": count, "subject": subject},
                   ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"[archive] {month}: wrote {dest}/ja.html, en.html (+assets, meta.json)")
    return True


ARCHIVE_INDEX_CSS = """
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Hiragino Kaku Gothic ProN',
'Noto Sans JP',Meiryo,sans-serif;margin:0;color:#222;background:#f5f6f8}
.topbar{position:sticky;top:0;background:#1f3864;color:#fff;padding:12px 16px;
display:flex;justify-content:space-between;align-items:center}
.topbar a{color:#fff;text-decoration:none}.topbar a:hover{text-decoration:underline}
.wrap{max-width:760px;margin:0 auto;padding:32px 20px}
h1{color:#1f3864;font-size:22px;margin:0 0 6px}.sub{color:#555;font-size:14px;margin:0 0 24px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:10px;overflow:hidden;
box-shadow:0 2px 12px rgba(0,0,0,.06)}
th,td{text-align:left;padding:12px 16px;border-bottom:1px solid #eef0f3;font-size:14px}
th{background:#f0f2f5;color:#333;font-size:13px}
td.month{color:#1f3864}
.mmain{font-weight:700}
.msnap{font-size:12px;color:#888;font-weight:400;margin-top:2px}
.mnote{font-size:12px;color:#8a5a00;font-weight:400;margin-top:4px}
.mnote a{color:#8a5a00;font-weight:700;text-decoration:none}
.mnote a:hover{text-decoration:underline}
a.rep{color:#1f3864;text-decoration:none;font-weight:600;margin-right:12px}
a.rep:hover{text-decoration:underline}
.footer{max-width:760px;margin:24px auto;padding:0 20px;color:#888;font-size:12px}
""".strip()


_MONTHS_EN = ["January", "February", "March", "April", "May", "June",
              "July", "August", "September", "October", "November", "December"]


def _fmt_subject(subject: str) -> tuple[str, str]:
    """'2026-06' -> ('2026年6月', 'June 2026'). Falls back to the raw string."""
    m = re.match(r"(\d{4})-(\d{2})$", subject or "")
    if not m:
        return subject, subject
    y, mo = int(m.group(1)), int(m.group(2))
    return f"{y}年{mo}月", f"{_MONTHS_EN[mo - 1]} {y}"


def _count_cell(entry: dict) -> str:
    """Two-value count when both are known, single when only --count given, else '—'
    (never fabricated)."""
    counts = entry.get("counts") or {}
    cvrf, core = counts.get("cvrf"), counts.get("core")
    if isinstance(cvrf, int) and isinstance(core, int):
        return f"{cvrf:,} CVRF / {core:,} 本体相当・core"
    if isinstance(entry.get("count"), int):
        return f"{entry['count']:,}"
    return "—"


def build_index(docs: Path) -> None:
    # Bilingual order = English first, then Japanese (headers, month cell, links, text).
    # See docs/SITE_BILINGUAL_CONVENTION.md (private msrc_monitor). The frozen snapshots
    # docs/archive/YYYY-MM/{ja,en}.html are immutable and NOT touched here.
    archive_dir = docs / "archive"
    manifest = _load_manifest(archive_dir)
    rows = []
    for m in manifest["months"]:
        slot = m["month"]                       # folder / link key (unchanged)
        subject = m.get("subject") or slot      # the month the report is ABOUT
        snapshot = m.get("snapshot")            # data freshness date
        ja_m, en_m = _fmt_subject(subject)
        month_cell = f'<div class="mmain">{en_m} / {ja_m}</div>'
        if snapshot:
            month_cell += (f'<div class="msnap">snapshot {snapshot} / '
                           f'スナップショット {snapshot}</div>')
        # optional revision note: source data revised after publication. Links live
        # OUTSIDE the frozen snapshot dir (docs/archive/notes-*.html), so the immutable
        # YYYY-MM/ snapshot is never touched.
        notes = m.get("notes") or {}
        if notes.get("en") and notes.get("ja"):
            month_cell += (
                '<div class="mnote">⚠ Source data revised after publication — '
                f'revision note: <a href="{notes["en"]}">English</a> · '
                f'<a href="{notes["ja"]}">日本語</a><br>'
                '公開後に元データが改訂 — 改訂ノート: '
                f'<a href="{notes["en"]}">English</a> · '
                f'<a href="{notes["ja"]}">日本語</a></div>')
        rows.append(
            f'<tr><td class="month">{month_cell}</td><td>{_count_cell(m)}</td>'
            f'<td><a class="rep" href="{slot}/en.html">English</a> · '
            f'<a class="rep" href="{slot}/ja.html">日本語</a></td></tr>')
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Archive / アーカイブ — MSRC Vulnerability Trend Report</title>
<meta name="description" content="Monthly archive of the MSRC vulnerability trend report.">
<style>{ARCHIVE_INDEX_CSS}</style>
</head>
<body>
<div class="topbar">
  <a href="../index.html">MSRC Vulnerability Trend Report</a>
  <div class="nav"><a href="../index.html">Latest / 最新レポート</a></div>
</div>
<div class="wrap">
  <h1>Archive / アーカイブ</h1>
  <p class="sub">A list of previously published monthly reports. Each month's snapshot is preserved as published.<br>
  過去に公開した月次レポートの一覧。各月のスナップショットは公開時点のまま保持されます。</p>
  <table>
    <thead><tr><th>Month / 年月</th><th>Count / CVE 件数</th><th>Report / レポート</th></tr></thead>
    <tbody>
    {chr(10).join("    " + r for r in rows) if rows else '<tr><td colspan="3">(no archives yet / まだアーカイブがありません)</td></tr>'}
    </tbody>
  </table>
</div>
<div class="footer">Facts are machine-generated; interpretation is human. Source: Microsoft Security Response Center (MSRC) CVRF.</div>
</body>
</html>
"""
    (archive_dir / "index.html").write_text(page, encoding="utf-8")
    print(f"[archive] wrote {archive_dir}/index.html ({len(manifest['months'])} month(s))")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--month", help="YYYY-MM slot (folder/link key) to archive as")
    ap.add_argument("--subject", default=None,
                    help="YYYY-MM the report is ABOUT (display); defaults to --month")
    ap.add_argument("--snapshot", default=None, help="data freshness date YYYY-MM-DD (display)")
    ap.add_argument("--count-cvrf", type=int, default=None, help="full-CVRF CVE count")
    ap.add_argument("--count-core", type=int, default=None, help="Microsoft-core CVE count")
    ap.add_argument("--count", type=int, default=None, help="single CVE count (fallback)")
    ap.add_argument("--docs", default=str(ROOT / "docs"), help="site docs dir")
    ap.add_argument("--rebuild-index-only", action="store_true",
                    help="only regenerate archive/index.html from the manifest")
    args = ap.parse_args()
    docs = Path(args.docs)
    archive_dir = docs / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)

    if not args.rebuild_index_only:
        if not args.month or not MONTH_RE.match(args.month):
            print("[archive] ERROR: --month YYYY-MM required", file=sys.stderr)
            return 2
        # snapshot copy is immutable (skipped only on a genuine same-subject re-run;
        # a different/absent subject halts). The manifest is the nav layer, so its
        # display metadata is (re)set here without touching the snapshot.
        subject = args.subject or args.month
        archive_month(args.month, docs, args.count, subject)
        meta = {"month": args.month,
                "subject": subject,
                "snapshot": args.snapshot,
                "counts": {"cvrf": args.count_cvrf, "core": args.count_core}}
        if args.count is not None:
            meta["count"] = args.count
        manifest = _load_manifest(archive_dir)
        entry = next((m for m in manifest["months"] if m["month"] == args.month), None)
        if entry:
            entry.update(meta)
        else:
            manifest["months"].append(meta)
        _save_manifest(archive_dir, manifest)
    build_index(docs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
