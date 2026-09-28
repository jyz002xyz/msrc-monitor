#!/usr/bin/env python3
"""post_seal.py — detect KEV entries that belong to an already-sealed month but are not in
its seal. DETECTION ONLY: never writes a snapshot.

Why: the seal step re-reads the window from the catalog at close (#124), but an entry CISA
lists AFTER the sealing run, dated back into the closed month, is still missed — the window
is read once. That is how a month can end up sealed short without anyone seeing it
(2026-08 was sealed with 29 of 31). Fixing it needs a person (a recorded re-seal, see
kev/manual/); this module makes sure a person hears about it.

Two halves, so the GitHub side stays thin and the logic is testable offline:
  - run.py calls gap() for the month before the current one and writes the result to
    kev/out/post_seal_gap.json (git-ignored; outside the daily diff scope).
  - The daily workflow runs `python kev/post_seal.py notify kev/out/post_seal_gap.json`,
    which opens ONE GitHub issue per distinct gap.

Not ringing daily for the same gap: the same idea as msrc_monitor's .last_notified_*.json
(notify once; ring again only when the content changes), but the record is the issue itself.
The daily job is stateless — a notified-file would only persist on days docs/kev/ changes
(no-op days open no PR), so it would be lost and the issue re-filed. Instead the title
carries a signature of the gap ([post-seal:<sig>]); an issue with that tag, open OR closed,
means "already notified". A different gap (another late entry) has a different signature
and is notified again.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import kevtrack  # noqa: E402

GAP_FILE = HERE / "out" / "post_seal_gap.json"
TAG = "post-seal"


def gap(month: str, kev_full: list[dict], snap_dir: Path = kevtrack.SNAP_DIR) -> dict | None:
    """Compare a sealed month with the catalog's window for it. None if the month is not
    sealed. `missing` = in the catalog window, not in the seal; `extra` = in the seal, no
    longer in the catalog window (removed or re-dated upstream)."""
    snap = kevtrack.load_sealed(month, snap_dir)
    if snap is None:
        return None
    sealed = {r["cve"] for r in snap["kev_added"]}
    window = {e.get("cveID") for e in kevtrack.window_of(kev_full, month) if e.get("cveID")}
    return {"month": month, "sealed_count": len(sealed), "window_count": len(window),
            "missing": sorted(window - sealed), "extra": sorted(sealed - window)}


def has_gap(g: dict | None) -> bool:
    return bool(g and (g["missing"] or g["extra"]))


def signature(g: dict) -> str:
    key = json.dumps({"month": g["month"], "missing": g["missing"], "extra": g["extra"]},
                     sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def issue_title(g: dict) -> str:
    return (f"kev: sealed {g['month']} differs from the KEV catalog "
            f"({len(g['missing'])} missing, {len(g['extra'])} extra) [{TAG}:{signature(g)}]")


def issue_body(g: dict) -> str:
    lines = [f"The sealed snapshot `kev/snapshots/{g['month']}.json.gz` has "
             f"{g['sealed_count']} entries; the KEV catalog's window for {g['month']} now has "
             f"{g['window_count']}.", ""]
    if g["missing"]:
        lines += ["**In the catalog window, not in the seal** (listed after the sealing run, "
                  "dated into the month):", *[f"- `{c}`" for c in g["missing"]], ""]
    if g["extra"]:
        lines += ["**In the seal, no longer in the catalog window** (removed or re-dated "
                  "upstream):", *[f"- `{c}`" for c in g["extra"]], ""]
    lines += ["Detection only — the daily job did not change the seal (and its diff-scope "
              "check would refuse to). Repairing a seal is a person's decision: a recorded "
              "re-seal in a reviewed PR, as for 2026-08 (`kev/manual/reseal_2026_08.py`).",
              "",
              f"This issue is filed once per distinct gap (tag `[{TAG}:{signature(g)}]`). "
              "Closing it does not re-file the same gap; a changed gap is filed again."]
    return "\n".join(lines)


def notify(g: dict | None, list_titles, create) -> str | None:
    """File one issue for this gap unless one with its tag already exists (any state).
    Returns the created title, or None when nothing was filed."""
    if not has_gap(g):
        return None
    tag = f"[{TAG}:{signature(g)}]"
    if any(tag in t for t in list_titles()):
        return None
    title = issue_title(g)
    create(title, issue_body(g))
    return title


def write_gap(g: dict | None, path: Path = GAP_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(g, indent=2) + "\n", encoding="utf-8")


# --- GitHub side (gh CLI; GH_TOKEN from the workflow) -------------------------
def _gh_titles() -> list[str]:
    out = subprocess.run(["gh", "issue", "list", "--state", "all", "--limit", "1000",
                          "--json", "title", "--jq", ".[].title"],
                         check=True, capture_output=True, text=True).stdout
    return [t for t in out.splitlines() if t]


def _gh_create(title: str, body: str) -> None:
    subprocess.run(["gh", "issue", "create", "--title", title, "--body", body], check=True)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "notify":
        print("usage: post_seal.py notify <gap.json>", file=sys.stderr)
        return 2
    p = Path(argv[1])
    if not p.exists():
        # run.py writes the file on every successful run; its absence is a failure, not "no gap"
        print(f"[post-seal] {p} not found — run.py did not record the check", file=sys.stderr)
        return 1
    g = json.loads(p.read_text(encoding="utf-8"))
    if not has_gap(g):
        print(f"[post-seal] {(g or {}).get('month', '(no sealed previous month)')}: "
              f"seal matches the catalog window — nothing to file")
        return 0
    filed = notify(g, _gh_titles, _gh_create)
    print(f"[post-seal] filed: {filed}" if filed else
          f"[post-seal] gap already filed ([{TAG}:{signature(g)}]) — not filing again")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
