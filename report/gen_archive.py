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


def archive_month(month: str, docs: Path, count: int | None) -> bool:
    """File the current published report as archive/<month>/. Returns True if newly
    created, False if it already existed (idempotent skip)."""
    archive_dir = docs / "archive"
    dest = archive_dir / month
    if dest.exists():
        print(f"[archive] {month} already archived (immutable) — skipping copy")
        return False

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
        json.dumps({"month": month, "count": count}, ensure_ascii=False, indent=2) + "\n",
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
    archive_dir = docs / "archive"
    manifest = _load_manifest(archive_dir)
    rows = []
    for m in manifest["months"]:
        slot = m["month"]                       # folder / link key (unchanged)
        subject = m.get("subject") or slot      # the month the report is ABOUT
        snapshot = m.get("snapshot")            # data freshness date
        ja_m, en_m = _fmt_subject(subject)
        month_cell = f'<div class="mmain">{ja_m} / {en_m}</div>'
        if snapshot:
            month_cell += (f'<div class="msnap">スナップショット {snapshot} / '
                           f'snapshot {snapshot}</div>')
        rows.append(
            f'<tr><td class="month">{month_cell}</td><td>{_count_cell(m)}</td>'
            f'<td><a class="rep" href="{slot}/ja.html">日本語</a>'
            f'<a class="rep" href="{slot}/en.html">English</a></td></tr>')
    page = f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>アーカイブ / Archive — MSRC 脆弱性動向レポート</title>
<meta name="description" content="Monthly archive of the MSRC vulnerability trend report.">
<style>{ARCHIVE_INDEX_CSS}</style>
</head>
<body>
<div class="topbar">
  <a href="../index.html">MSRC 脆弱性動向レポート</a>
  <div class="nav"><a href="../index.html">最新レポート / Latest</a></div>
</div>
<div class="wrap">
  <h1>アーカイブ / Archive</h1>
  <p class="sub">過去に公開した月次レポートの一覧。各月のスナップショットは公開時点のまま保持されます。<br>
  A list of previously published monthly reports. Each month's snapshot is preserved as published.</p>
  <table>
    <thead><tr><th>年月 / Month</th><th>CVE 件数 / Count</th><th>レポート / Report</th></tr></thead>
    <tbody>
    {chr(10).join("    " + r for r in rows) if rows else '<tr><td colspan="3">（まだアーカイブがありません / no archives yet）</td></tr>'}
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
        # snapshot copy is immutable (skipped if it exists); the manifest is the nav
        # layer, so its display metadata is (re)set here without touching the snapshot.
        archive_month(args.month, docs, args.count)
        meta = {"month": args.month,
                "subject": args.subject or args.month,
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
