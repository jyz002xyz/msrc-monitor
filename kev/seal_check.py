#!/usr/bin/env python3
"""seal_check.py — verify a month AT THE MOMENT it is sealed; fail the run if it is wrong.

Two checks, on each month sealed in this run, from CWE_FROM (2026-09) on:
  1. Row count = the catalog's window for that month at seal time (post_seal.gap(): nothing
     missing, nothing extra). build_final() reads the same catalog, so a mismatch here is a
     code or data fault, not CISA's timing.
  2. Every sealed row carries the `cwes` key. [] (CISA gave none) is fine; None (the field was
     absent in KEV for that entry) is reported but is not a failure — integrity.py already
     halts the run if the field goes missing across the catalog. `cwes` is NOT a required
     field in integrity.py (an empty list must stay normal).

Months before CWE_FROM are not checked: they were sealed before `cwes` was recorded.

On failure run.py exits 4 before anything is rendered, so the job fails, the daily PR is not
opened, and the seal is not committed — nothing is repaired automatically. The result is
written to kev/out/seal_check.json (git-ignored) and the workflow files one GitHub issue per
distinct failure. Everything is visible in the run log and the issue; no local session is
needed to read the outcome.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import kevtrack   # noqa: E402
import post_seal  # noqa: E402

CWE_FROM = "2026-09"
RESULT_FILE = HERE / "out" / "seal_check.json"
TAG = "seal-check"


def applies(month: str) -> bool:
    return month >= CWE_FROM


def check(month: str, kev_full: list[dict], snap_dir: Path = kevtrack.SNAP_DIR) -> dict:
    """Result for one just-sealed month: {"month", "checked", "problems", ...}."""
    if not applies(month):
        return {"month": month, "checked": False, "problems": [],
                "reason": f"sealed before cwes was recorded (checks apply from {CWE_FROM})"}
    snap = kevtrack.load_sealed(month, snap_dir)
    if snap is None:
        return {"month": month, "checked": True, "problems": [f"{month} is not sealed"]}
    g = post_seal.gap(month, kev_full, snap_dir)
    rows = snap["kev_added"]
    no_key = sorted(r["cve"] for r in rows if "cwes" not in r)
    bad_type = sorted(r["cve"] for r in rows
                      if "cwes" in r and r["cwes"] is not None and not isinstance(r["cwes"], list))
    problems = []
    if g["missing"] or g["extra"]:
        problems.append(f"row count {g['sealed_count']} != catalog window {g['window_count']} "
                        f"(missing {g['missing']}, extra {g['extra']})")
    if no_key:
        problems.append(f"{len(no_key)} sealed row(s) without the cwes key: {no_key}")
    if bad_type:
        problems.append(f"{len(bad_type)} sealed row(s) with cwes neither a list nor null: "
                        f"{bad_type}")
    return {"month": month, "checked": True, "problems": problems,
            "sealed_count": g["sealed_count"], "window_count": g["window_count"],
            "cwes_list": sum(isinstance(r.get("cwes"), list) for r in rows),
            "cwes_empty": sum(r.get("cwes") == [] for r in rows),
            "cwes_null": sorted(r["cve"] for r in rows if "cwes" in r and r["cwes"] is None)}


def summary(res: dict) -> str:
    m = res["month"]
    if not res["checked"]:
        return f"seal check {m}: skipped — {res['reason']}"
    if res["problems"]:
        return f"SEAL CHECK FAILED {m}: " + "; ".join(res["problems"])
    return (f"seal check {m}: OK — {res['sealed_count']} rows = catalog window "
            f"{res['window_count']}; cwes on {res['cwes_list']}/{res['sealed_count']} "
            f"({res['cwes_empty']} empty list, {len(res['cwes_null'])} null)")


def signature(res: dict) -> str:
    key = json.dumps({"month": res["month"], "problems": res["problems"]}, sort_keys=True)
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def issue_title(res: dict) -> str:
    return f"kev: seal check failed for {res['month']} [{TAG}:{signature(res)}]"


def issue_body(res: dict) -> str:
    return "\n".join([
        f"Sealing **{res['month']}** failed the seal-time check, so the daily run exited "
        "non-zero: the seal was not committed and nothing was published or repaired.", "",
        *[f"- {p}" for p in res["problems"]], "",
        "The open snapshot for the month is still in the repository, so the next run will "
        "try to seal again. If it keeps failing, the fault is in the code or the data, not in "
        "CISA's timing — look at the run log's `[run] SEAL CHECK FAILED` line.", "",
        f"Filed once per distinct failure (tag `[{TAG}:{signature(res)}]`)."])


def notify(results: list[dict], list_titles, create) -> list[str]:
    """One issue per failed month, unless an issue with its tag exists (any state)."""
    filed = []
    for res in results:
        if not res.get("problems"):
            continue
        tag = f"[{TAG}:{signature(res)}]"
        if any(tag in t for t in list_titles()):
            continue
        create(issue_title(res), issue_body(res))
        filed.append(issue_title(res))
    return filed


def write_results(results: list[dict], path: Path = RESULT_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "notify":
        print("usage: seal_check.py notify <seal_check.json>", file=sys.stderr)
        return 2
    p = Path(argv[1])
    if not p.exists():
        print(f"[seal-check] {p} not found — no month was sealed in this run (or run.py "
              f"stopped before the seal step)")
        return 0
    results = json.loads(p.read_text(encoding="utf-8"))
    failed = [r for r in results if r.get("problems")]
    if not failed:
        print("[seal-check] no failed seal check — nothing to file")
        return 0
    filed = notify(results, post_seal._gh_titles, post_seal._gh_create)
    for t in filed:
        print(f"[seal-check] filed: {t}")
    if len(filed) < len(failed):
        print(f"[seal-check] {len(failed) - len(filed)} failure(s) already filed — not filing again")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
