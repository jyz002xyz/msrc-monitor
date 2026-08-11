#!/usr/bin/env python3
"""stateag_store.py — the append-only record of state AG breach-notification filings.

WHY A SIBLING OF store.py RATHER THAN A REUSE OF IT
---------------------------------------------------
store.py models the SEC layer: an INCIDENT (CIK + reportDate) that accumulates STATEMENTS
(one per 8-K/A amendment). That two-level shape exists because a company amends its filing and
we must never rewrite the first version. A state AG registry has no amendment chain — a filing
is a filing, one row, and a corrected filing appears as a new row. Forcing it into the SEC
shape would invent a hierarchy the source does not have.

What IS carried over, deliberately and identically:

- **Append-only.** A row already recorded keeps exactly the values it was published with.
- **No run timestamp anywhere in the output.** A day that finds nothing new must produce a
  byte-identical file, or no-op detection cannot work and the site churns daily.
- **`first_seen` is written once**, when a row is first recorded, and never updated.
- **`coverage.since` only ever widens.** A later, narrower window does not unsee what an
  earlier backfill already collected.

UNIT OF RECORD
--------------
One filing to one state = one row, identified by `key`:

- Washington: `WA:<document id>` — taken from the notification PDF the organisation filed, so
  it is the source's own identifier.
- California: `CA:<reported date>:<slug>:<breach dates>` — composed, because California
  publishes no per-filing id. Two filings by one organisation, reported the same day, naming
  the same breach dates, collapse into one. Measured over the full export (2026-08-10) that
  affected 12 of 5,242 rows, and every colliding group was identical in all published fields
  — the export's own duplicates. See fetch_stateag.parse_ca.

The same breach reported to both states produces TWO rows, one per jurisdiction. They are not
merged: each is a filing to a different regulator, and merging them would mean deciding they
are the same event, which is a judgement this section does not make.
"""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA = 1

# Fields copied verbatim from the source onto a stored row. Anything not in this list is not
# recorded — an accidental extra key in a parser cannot leak into the permanent record.
FIELDS = ("key", "jurisdiction", "organization", "reported_date", "breach_dates",
          "affected", "data_types", "notice_url", "source_url")


def empty() -> dict:
    return {"schema": SCHEMA, "coverage": {"since": None}, "filings": []}


def load(path: Path) -> dict:
    if not path.exists():
        return empty()
    d = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(d, dict) or "filings" not in d:
        raise ValueError(f"{path}: not a state AG registry store")
    d.setdefault("coverage", {"since": None})
    return d


def save(path: Path, store: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, ensure_ascii=False, indent=2,
                               sort_keys=False) + "\n", encoding="utf-8")


def note_coverage(store: dict, since: str | None) -> dict:
    """Widen the recorded coverage start. Never narrows."""
    if not since:
        return store
    cov = store.setdefault("coverage", {"since": None})
    cur = cov.get("since")
    if not cur or since < cur:
        cov["since"] = since
    return store


def _sorted(store: dict) -> dict:
    store["filings"].sort(
        key=lambda f: (f.get("reported_date") or "", f.get("jurisdiction") or "", f["key"]),
        reverse=True)
    return store


def merge(store: dict, rows: list[dict], *, seen_date: str) -> tuple[dict, list[dict]]:
    """Append rows that are not already recorded. Returns (store, newly added rows).

    Existing rows are never modified. If the state later corrects a figure on a filing we have
    already recorded, the recorded row keeps the figure it was published with — the same rule
    the SEC layer follows, for the same reason: what we showed a reader must stay retrievable.
    """
    known = {f["key"] for f in store["filings"]}
    added: list[dict] = []
    for r in rows:
        if r["key"] in known:
            continue
        row = {k: r.get(k) for k in FIELDS}
        row["first_seen"] = seen_date
        store["filings"].append(row)
        known.add(r["key"])
        added.append(row)
    return _sorted(store), added


def fill_missing(store: dict, rows: list[dict], field: str) -> int:
    """Fill a field on already-recorded rows ONLY where it is currently absent.

    WHY THIS IS NOT A HOLE IN THE APPEND-ONLY RULE
    ----------------------------------------------
    The rule exists so that a value a reader was shown stays retrievable: if the state later
    corrects a figure, the recorded row keeps the figure it was published with. That is about a
    value CHANGING. This is about a value that was never collected in the first place.

    The case it was written for: California's rows were recorded from the CSV export, which has
    three columns and no link. The state's HTML list links every row to its notification
    document — the collector simply was not reading it. Leaving 134 rows permanently blank
    would not be preserving a published statement; it would be preserving a gap in our
    collection and calling it a record.

    So the guarantee is kept narrow rather than waived:

    - a stored value that is NOT None is never touched, whatever the source now says;
    - only the named field is considered;
    - it is never called by the daily run. `--backfill-notice-urls` is a deliberate act.

    Returns how many rows were filled.
    """
    if field not in FIELDS:
        raise ValueError(f"{field} is not a stored field")
    fresh = {r["key"]: r.get(field) for r in rows}
    filled = 0
    for row in store.get("filings", []):
        if row.get(field) is not None:
            continue                      # published value: untouchable
        new = fresh.get(row["key"])
        if new is None:
            continue
        row[field] = new
        filled += 1
    return filled


def counts(store: dict) -> dict:
    f = store.get("filings") or []
    return {
        "filings": len(f),
        "organizations": len({r.get("organization") for r in f}),
        "ca": sum(1 for r in f if r.get("jurisdiction") == "CA"),
        "wa": sum(1 for r in f if r.get("jurisdiction") == "WA"),
    }
