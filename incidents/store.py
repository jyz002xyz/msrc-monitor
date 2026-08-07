#!/usr/bin/env python3
"""store.py — the append-only disclosure record.

UNIT OF RECORD
--------------
An INCIDENT is keyed by `CIK + reportDate`. `reportDate` is the date of the earliest event
reported, not the filing date: it stays constant across a filing's whole 8-K/A chain (checked
on River Financial's five filings, all reportDate 2026-06-19, filed 2026-06-25..07-30), so two
separate incidents at one company carry two different reportDates.

A STATEMENT is one filing (`adsh`). The original 8-K and each 8-K/A are separate statements.
Nothing is ever rewritten: a later amendment is appended, never merged over the first. That
holds up here because EDGAR filings are not withdrawn — the accession stays retrievable.

Caveat kept in the open: the reportDate split is inferred from the field's meaning and from
its constancy across an amendment chain. No company filed two separate 1.05 incidents inside
the observed window, so the split itself is untested against a real case.

NO TIMESTAMPS IN THE OUTPUT
---------------------------
The store carries no run timestamp. A daily run that finds nothing new must produce a
byte-identical file, otherwise no-op detection cannot work and the site churns every day.
`first_seen` is written once per statement, when it is first recorded, and never updated.
"""
from __future__ import annotations

import json
from pathlib import Path

SCHEMA = 1


def incident_key(cik: str, report_date: str | None) -> str:
    """CIK + reportDate. A filing with no reportDate falls back to its own filing key so it is
    still recorded rather than dropped or merged into someone else's incident."""
    return f"{str(cik).zfill(10)}:{report_date or 'unknown'}"


def empty() -> dict:
    return {"schema": SCHEMA, "incidents": []}


def load(path: Path) -> dict:
    if not path.exists():
        return empty()
    d = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(d, dict) or "incidents" not in d:
        raise ValueError(f"{path}: not a disclosure store")
    return d


def save(path: Path, store: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, ensure_ascii=False, indent=2,
                               sort_keys=False) + "\n", encoding="utf-8")


def _sorted(store: dict) -> dict:
    for inc in store["incidents"]:
        inc["statements"].sort(key=lambda s: (s.get("filing_date") or "", s["adsh"]))
    store["incidents"].sort(key=lambda i: (i.get("report_date") or "", i["key"]), reverse=True)
    return store


def merge(store: dict, filings: list[dict], *, seen_date: str) -> tuple[dict, list[dict]]:
    """Append filings that are not already recorded. Returns (store, newly added statements).

    Existing statements are never modified — an incident already on record keeps exactly the
    text it was published with. Only genuinely new `adsh` values are added.
    """
    by_key = {i["key"]: i for i in store["incidents"]}
    known = {s["adsh"] for i in store["incidents"] for s in i["statements"]}
    added: list[dict] = []

    for f in filings:
        if f["adsh"] in known:
            continue
        key = incident_key(f["cik"], f.get("report_date"))
        inc = by_key.get(key)
        if inc is None:
            inc = {
                "key": key,
                "cik": str(f["cik"]).zfill(10),
                "company": f["company"],
                "report_date": f.get("report_date"),
                "statements": [],
            }
            by_key[key] = inc
            store["incidents"].append(inc)
        stmt = {
            "adsh": f["adsh"],
            "filing_date": f.get("filing_date"),
            "form": f.get("form"),
            "items": f.get("items") or [],
            "url": f.get("url"),
            "first_seen": seen_date,
        }
        inc["statements"].append(stmt)
        known.add(f["adsh"])
        added.append({**stmt, "key": key, "company": inc["company"]})

    return _sorted(store), added


def counts(store: dict) -> dict:
    return {
        "incidents": len(store["incidents"]),
        "statements": sum(len(i["statements"]) for i in store["incidents"]),
        "companies": len({i["cik"] for i in store["incidents"]}),
    }
