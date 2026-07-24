#!/usr/bin/env python3
"""run.py — build cross-vendor KEV/EPSS windows + reports (Phase 1 prototype, local).

Lifecycle:
  - The CURRENT month is an OPEN window: refreshed each run, EPSS observed at first sighting
    and kept, NOT immutable.
  - Past months are SEALED (immutable) once closed. Already-sealed months are reused as-is.
  - A sealed file found for the CURRENT month is an invalid mid-month seal: it is reverted to
    OPEN once, the correction is recorded (not silent), and its observed EPSS is preserved.

Nothing is published or pushed.

    python run.py                       # open current month + backfill 5 past months
    python run.py --months 6
    python run.py --current 2026-08     # override "today" (testing month transitions)
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

import integrity
import kevtrack
import report
import publish

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
# Public output: this generator now lives in msrc-monitor at kev/, so it regenerates the
# repo's docs/kev/ tree directly (../docs/kev). Path adaptation to the new home only — the
# rendered bytes are unchanged from the kev_cross_vendor prototype (verified byte-identical).
SITE_KEV = HERE.parent / "docs" / "kev"
# Lightweight cross-run meta (git-tracked, under snapshots/): catalog size at the last
# successful run, for the integrity decrease-rate check. Only written on a successful run.
META = HERE / "snapshots" / "catalog_meta.json"


def load_prev_count() -> int | None:
    try:
        return int(json.loads(META.read_text(encoding="utf-8"))["last_catalog_count"])
    except Exception:  # noqa: BLE001 — missing/corrupt meta just skips the decrease check
        return None


def write_meta(count: int, now_iso: str) -> None:
    META.parent.mkdir(parents=True, exist_ok=True)
    META.write_text(
        json.dumps({"last_catalog_count": count, "updated_at": now_iso}, indent=2) + "\n",
        encoding="utf-8")


def _content_sig(snap: dict) -> str:
    """Snapshot content minus its generation timestamp — used to keep generated_at (and the
    published HTML, which embeds it) stable across no-op runs so no-op detection is exact."""
    return json.dumps({k: v for k, v in snap.items() if k != "generated_at"},
                      sort_keys=True, ensure_ascii=False)


def prev_months(ym: str, n: int) -> list[str]:
    y, m = map(int, ym.split("-"))
    out = []
    for _ in range(n):
        m -= 1
        if m == 0:
            m, y = 12, y - 1
        out.append(f"{y:04d}-{m:02d}")
    return out


def _write_reports(snap: dict) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / f"{snap['window']}.md").write_text(report.render_markdown(snap), encoding="utf-8")
    (OUT / f"{snap['window']}.html").write_text(report.render_html(snap), encoding="utf-8")


def _build_index(snaps: list[dict]) -> None:
    rows = sorted(snaps, key=lambda s: s["window"], reverse=True)
    head = ["# Cross-vendor KEV/EPSS — index (prototype, local)\n",
            "| Window | State | KEV added | Ransomware (Known/Unknown) | EPSS | Report |",
            "| --- | --- | --- | --- | --- | --- |"]
    foot = [
        "",
        "*KEV は悪用の完全な記録ではなく、CISA が確認し連邦機関向けに優先付けしたもの。*",
        "*ベンダー別件数は連邦環境での配備状況と CISA の可視性を反映するもので、"
        "セキュリティ品質の順位ではない（ベンダーを件数で順位付けしない）。*",
        "*EPSS は悪用確率であって深刻度ではない。open 窓は進行中（未確定）、sealed 窓は確定。*",
    ]
    md, tr = [], []
    for s in rows:
        m, n = s["window"], s["count"]
        k = sum(1 for r in s["kev_added"] if r["ransomware"])
        rk = f"Known {k} / Unknown {n - k}"
        state = "進行中 / in progress" if s["state"] == "open" else "sealed"
        epss = "observed" if s["epss_observed"] else "blank (backfill)"
        md.append(f"| {m} | {state} | {n} | {rk} | {epss} | [md]({m}.md) · [html]({m}.html) |")
        tr.append(f"<tr><td>{m}</td><td>{state}</td><td>{n}</td><td>{rk}</td><td>{epss}</td>"
                  f"<td><a href='{m}.md'>md</a> · <a href='{m}.html'>html</a></td></tr>")
    (OUT / "index.md").write_text("\n".join(head + md + foot), encoding="utf-8")
    foot_html = "".join(f"<p class='sub'>{report._h(x.strip('*'))}</p>" for x in foot if x.strip())
    (OUT / "index.html").write_text(
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Cross-vendor KEV/EPSS — index (prototype)</title>"
        "<style>body{font-family:-apple-system,Arial,sans-serif;max-width:860px;margin:0 auto;"
        "padding:28px 20px;color:#1a1a1a;background:#f6f7f9}h1{color:#1f3864}"
        "table{border-collapse:collapse;width:100%;background:#fff}th,td{border-bottom:"
        "1px solid #eef0f3;padding:8px 12px;text-align:left}th{background:#f0f2f5}"
        ".sub{color:#666;font-size:13px}</style></head><body>"
        "<h1>Cross-vendor KEV/EPSS — index</h1>"
        "<p class='sub'>Phase 1 prototype — local only, not published.</p>"
        "<table><thead><tr><th>Window</th><th>State</th><th>KEV added</th>"
        "<th>Ransomware (Known/Unknown)</th><th>EPSS</th><th>Report</th></tr></thead><tbody>"
        + "\n".join(tr) + "</tbody></table>" + foot_html + "</body></html>", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--months", type=int, default=5, help="backfill this many past months")
    ap.add_argument("--current", default=None, help="override 'today' month YYYY-MM (testing)")
    args = ap.parse_args()

    kev = kevtrack.fetch_kev_full()
    if kev is None:
        print("[run] KEV catalog unreachable — aborting (no changes).")
        return 1
    print(f"[run] KEV catalog: {len(kev)} entries")

    today_m = args.current or kevtrack.current_month()

    # INTEGRITY GATE (fail-halt): evaluated every run, before anything is written. A degraded
    # catalog must not be published, and — critically — must not seal a month permanently.
    seal_candidates = [m for m in prev_months(today_m, args.months)
                       if kevtrack.load_sealed(m) is None]
    failures, stats = integrity.evaluate(kev, prev_count=load_prev_count(),
                                         seal_months=seal_candidates)
    print(f"[run] integrity stats: {stats}")
    if failures:
        for f in failures:
            print(f"[run] INTEGRITY FAIL: {f}", file=sys.stderr)
        print("[run] fail-halt: nothing generated or sealed; open window left intact for "
              "recovery on the next run.", file=sys.stderr)
        return 3

    # (1) OPEN current month, with mid-month-seal correction + EPSS accumulation.
    corrections, prev_rows = [], None
    prev_open = kevtrack.load_open(today_m)
    if prev_open:
        corrections = list(prev_open.get("corrections", []))
        prev_rows = prev_open.get("kev_added")
    stale = kevtrack.load_sealed(today_m)
    if stale is not None:
        note = (f"re-opened {today_m}: was mid-month sealed at {stale.get('generated_at')} "
                f"({stale.get('count')} items) before the calendar month closed; reverted to "
                f"OPEN (immutability exception, recorded).")
        corrections.append(note)
        if prev_rows is None:
            prev_rows = stale.get("kev_added")      # preserve first-observed EPSS
        kevtrack.sealed_path(today_m).unlink()
        print(f"[run] CORRECTION: {note}")
    open_snap = kevtrack.build_open(today_m, kev, prev_rows,
                                    fetch_nvd_fn=kevtrack.fetch_nvd_published, corrections=corrections)
    # No-op determinism: if the open window's data is unchanged, keep the previous generated_at
    # so neither the snapshot nor the published HTML (which prints it) churns on identical data.
    if prev_open is not None and _content_sig(open_snap) == _content_sig(prev_open):
        open_snap["generated_at"] = prev_open["generated_at"]
    kevtrack.write_open(open_snap)
    print(f"[run] {today_m}: OPEN (in progress) — {open_snap['count']} KEV additions, "
          f"EPSS {'observed' if open_snap['epss_observed'] else 'none'}")
    built = [open_snap]

    # (2) SEAL past months. Existing seals get a one-time nvd_published schema migration
    #     (recorded); a just-closed open month is sealed; an unseen past window is backfilled.
    for m in prev_months(today_m, args.months):
        sealed = kevtrack.load_sealed(m)
        if sealed is not None:
            if kevtrack.migrate_sealed_add_nvd(m, kevtrack.fetch_nvd_published):
                print(f"[run] {m}: sealed — added nvd_published (recorded schema migration)")
            built.append(kevtrack.load_sealed(m))
            continue
        openm = kevtrack.load_open(m)
        if openm is not None:
            kevtrack.seal(openm)
            print(f"[run] {m}: month closed -> SEALED ({openm['count']} items)")
        else:
            kevtrack.seal(kevtrack.build_backfill(m, kev, fetch_nvd_fn=kevtrack.fetch_nvd_published))
            print(f"[run] {m}: backfilled -> SEALED (EPSS blank, nvd_published filled)")
        built.append(kevtrack.load_sealed(m))

    for snap in built:
        _write_reports(snap)
    _build_index(built)
    print(f"[run] internal preview -> {OUT}/index.html")
    # public bilingual site: regenerate the repo's docs/kev/ tree in place
    publish.build_site(built, SITE_KEV)
    print(f"[run] public site -> {SITE_KEV}/  (docs/kev/; commit is a separate, gated step)")
    # Record catalog size for the next run's integrity decrease-rate check (success only).
    write_meta(len(kev), dt.datetime.now().isoformat(timespec="seconds"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
