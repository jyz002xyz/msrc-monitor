#!/usr/bin/env python3
"""reseal_2026_08.py — ONE-OFF, run by hand: add the two entries the 2026-08 seal missed.

    python3 kev/manual/reseal_2026_08.py        # from the repo root; needs network (KEV, NVD)

Why: 2026-08 was sealed with 29 of its 31 entries. The last August run (08-31 01:30 UTC)
came before CISA listed two PaperCut CVEs (08-31 16:45 UTC), and the 09-01 01:58 UTC run
sealed the stored open file without re-reading the catalog. The seal step now re-reads the
window at close (#124); this script repairs the one month sealed before that fix.

Not called by run.py. The daily job's diff-scope check (#125) refuses any change to an
existing seal, so this lands only through a reviewed PR. Running it a second time does
nothing (both CVEs already present).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import kevtrack  # noqa: E402

MONTH = "2026-08"
MISSING = ["CVE-2026-81578", "CVE-2026-82078"]
NOTE = {
    "ja": "この月は 29 件で封印していたが、2026-08-31 に CISA が収載した 2 件"
          "（CVE-2026-81578、CVE-2026-82078）が漏れていた。原因は、封印の処理が月末時点の"
          "カタログを読み直さず、直前の実行で保存した内容をそのまま固めていたこと"
          "（#124 で修正済み）。2 件を追加して 31 件で封印し直した。既存の 29 行は変更していない。"
          "追加した 2 行の EPSS は、KEV 追加時点に観測していないため空欄とした。",
    "en": "This month was sealed with 29 entries and missed 2 that CISA listed on 2026-08-31 "
          "(CVE-2026-81578, CVE-2026-82078). Cause: the seal step froze the content stored by "
          "the previous run instead of re-reading the catalog at month-end (fixed in #124). "
          "The 2 entries were added and the month re-sealed with 31. The existing 29 rows are "
          "unchanged. The EPSS of the 2 added rows is left blank because it was not observed "
          "at KEV-add time.",
}


def main() -> int:
    snap = kevtrack.load_sealed(MONTH)
    if snap is None:
        print(f"[reseal] {MONTH} is not sealed — nothing to do", file=sys.stderr)
        return 1
    have = {r["cve"] for r in snap["kev_added"]}
    if all(c in have for c in MISSING):
        print(f"[reseal] {MONTH} already contains {', '.join(MISSING)} — nothing to do")
        return 0
    kev = kevtrack.fetch_kev_full()
    if kev is None:
        print("[reseal] KEV catalog unreachable — aborting (no changes)", file=sys.stderr)
        return 1
    out = kevtrack.reseal_add_entries(MONTH, kev, MISSING, note=NOTE,
                                      fetch_nvd_fn=kevtrack.fetch_nvd_published)
    print(f"[reseal] {MONTH}: {out['reseals'][-1]['count_before']} -> {out['count']} rows; "
          f"added {', '.join(MISSING)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
