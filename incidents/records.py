#!/usr/bin/env python3
"""records.py — the editor-curated layer: schema and validation.

WHAT THIS LAYER IS
------------------
Incidents an editor chose to record. It is NOT comprehensive and never claims to be. It exists
because the automatic layer only sees SEC registrants, which leaves out most of the world.

THE UNIT IS A STATEMENT, NOT AN INCIDENT
----------------------------------------
Reporting gets corrected and retracted. So the thing recorded is "this party said this, on this
date" — that stays true even after a retraction. A correction is APPENDED as another statement;
the earlier one is kept and marked, never edited away. Same shape as the MSRC revision notes.

RULES ENFORCED HERE (not left to memory)
----------------------------------------
- Organisations are named. They are the substance of the record.
- No personal names. Role and affiliation carry everything needed, and a daily-accumulating
  per-person record is a different artifact from a written piece. Validation rejects a
  `person` field outright; it cannot be added by habit.
- Attacker attribution is recorded as WHO CLAIMED WHAT, never as who did it.
- No summarising of article prose. `facts` holds what the ORGANISATION ITSELF stated; the
  article is linked, not retold.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

SCHEMA = 1
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Statement kinds. `organization` = the affected organisation's own announcement;
# `regulator` = a filing/enforcement record; `media` = a report; `retraction` = withdraws an
# earlier statement (which stays on the record).
KINDS = {"organization", "regulator", "media", "retraction"}

# Deliberately coarse. A fine-grained taxonomy invites judgement calls we said we would not make.
TYPES = {"unauthorized_access", "ransomware", "data_exposure", "supply_chain",
         "credential_compromise", "other", "undisclosed"}

# Fields that must never appear. Rejected loudly rather than stripped, so a would-be author
# finds out at validation time instead of after publication.
FORBIDDEN_KEYS = {"person", "person_name", "individual", "employee_name", "attacker",
                  "perpetrator", "who_did_it"}


def empty() -> dict:
    return {"schema": SCHEMA, "records": []}


def load(path: Path) -> dict:
    if not path.exists():
        return empty()
    d = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(d, dict) or "records" not in d:
        raise ValueError(f"{path}: not a records file")
    return d


def _walk_keys(obj, out: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(k)
            _walk_keys(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _walk_keys(v, out)


def validate(doc: dict) -> list[str]:
    """Return a list of problems. Empty list == the file may be published."""
    errs: list[str] = []
    if doc.get("schema") != SCHEMA:
        errs.append(f"schema must be {SCHEMA}, got {doc.get('schema')!r}")
    records = doc.get("records")
    if not isinstance(records, list):
        return errs + ["`records` must be a list"]

    keys: list[str] = []
    _walk_keys(doc, keys)
    for bad in sorted({k for k in keys if k in FORBIDDEN_KEYS}):
        errs.append(f"forbidden field {bad!r}: individuals are not recorded here — use role "
                    f"and affiliation, and record attacker attribution as a claim")

    ids: set[str] = set()
    for i, r in enumerate(records):
        at = f"records[{i}]"
        rid = r.get("id")
        if not isinstance(rid, str) or not rid:
            errs.append(f"{at}: `id` is required")
        elif rid in ids:
            errs.append(f"{at}: duplicate id {rid!r}")
        else:
            ids.add(rid)
        if not str(r.get("organization") or "").strip():
            errs.append(f"{at}: `organization` is required (organisations are named)")
        if r.get("type") not in TYPES:
            errs.append(f"{at}: `type` must be one of {sorted(TYPES)}")

        stmts = r.get("statements")
        if not isinstance(stmts, list) or not stmts:
            errs.append(f"{at}: at least one statement is required")
            continue
        for j, s in enumerate(stmts):
            sat = f"{at}.statements[{j}]"
            if not DATE_RE.match(str(s.get("date") or "")):
                errs.append(f"{sat}: `date` must be YYYY-MM-DD")
            if s.get("kind") not in KINDS:
                errs.append(f"{sat}: `kind` must be one of {sorted(KINDS)}")
            if not str(s.get("source") or "").strip():
                errs.append(f"{sat}: `source` is required (who said it)")
            if not str(s.get("url") or "").startswith("http"):
                errs.append(f"{sat}: `url` is required (the statement must be checkable)")
            if s.get("kind") == "retraction" and not str(s.get("retracts") or "").strip():
                errs.append(f"{sat}: a retraction must name the statement it retracts "
                            f"(`retracts`); the retracted statement stays on the record")

        for j, c in enumerate(r.get("attacker_claims") or []):
            cat = f"{at}.attacker_claims[{j}]"
            if not str(c.get("claimed_by") or "").strip():
                errs.append(f"{cat}: `claimed_by` is required — this records WHO CLAIMED, "
                            f"not who did it")
            if not DATE_RE.match(str(c.get("date") or "")):
                errs.append(f"{cat}: `date` must be YYYY-MM-DD")
            if not str(c.get("url") or "").startswith("http"):
                errs.append(f"{cat}: `url` is required")

        sec = r.get("sec")
        if sec is not None:
            if not str(sec.get("cik") or "").strip():
                errs.append(f"{at}.sec: `cik` is required when a SEC link is asserted")
            # The link is made by a human on purpose: there is no shared identifier between
            # the two layers, so nothing here may be inferred automatically.
    return errs


def counts(doc: dict) -> dict:
    recs = doc.get("records") or []
    return {
        "records": len(recs),
        "statements": sum(len(r.get("statements") or []) for r in recs),
        "linked_to_sec": sum(1 for r in recs if r.get("sec")),
    }
