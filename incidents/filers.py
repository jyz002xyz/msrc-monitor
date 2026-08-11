#!/usr/bin/env python3
"""filers.py — deciding whether a registry filer is an organisation or an individual.

THE PROBLEM
-----------
California's "Organization Name" column is not always an organisation. Sole practitioners file
under their own name (`Amin Dean, CPA`, `Andrea Yaley, DDS`), and occasionally a bare personal
name appears (`Robert Arshagouni`). Washington's list is cleaner but is treated identically —
nothing guarantees it stays that way.

records.py already states the rule this collides with, for the curated layer:

    No personal names. Role and affiliation carry everything needed, and a daily-accumulating
    per-person record is a different artifact from a written piece.

That is exactly what an unfiltered registry table would become. README.md records the same
question being met from the other direction, and deferred, for ICO (UK).

WHY A MACHINE DOES NOT DECIDE IT
--------------------------------
Measured over California's full export (5,242 rows, 2026-08-10), a name-shaped heuristic
flags 194 rows (3.7%) — and MOST of those are companies: `Abbott Nutrition`, `Brooks Brothers`,
`Texas Capital`, `Carnival Corporation`. A filter that acted on its own verdict would drop real
organisations from a public-record table to catch a handful of individuals.

So the heuristic does not decide. It only asks. It is deliberately tuned for RECALL, not
precision: a company wrongly flagged costs one human "yes" for all time, while an individual
wrongly missed is published.

WHAT HAPPENS TO A FLAGGED NAME
------------------------------
Until a human decides, the row is withheld from BOTH the published page and the permanent
record. That "and the record" matters: this repository is public, so a name written into
`data/state_ag.json` is published just as surely as one written into the HTML.

For the same reason `data/filer_decisions.json` holds decided ORGANISATIONS by name — they are
companies, and their names are published on the page anyway — but decided INDIVIDUALS only as
a hash of the name. That is not secrecy (the state publishes the name, and anyone can hash a
guess); it is so that deciding "this is a person" does not itself write the person's name into
a permanent public file. The point of the rule was never that the string is secret. It was that
this project does not keep a per-person record.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SCHEMA = 1

# Words that mark a legal or institutional form. Their presence is enough to treat the filer as
# an organisation without asking, which is what keeps the queue down to a few percent of rows.
_ORG_FORM = re.compile(
    r"\b(inc|inc\.|incorporated|llc|l\.l\.c|corp|corp\.|corporation|co|co\.|company|companies|"
    r"ltd|ltd\.|limited|lp|llp|pllc|plc|pc|group|holdings|holding|partners|partnership|"
    r"associates|association|assn|society|foundation|trust|fund|university|college|school|"
    r"academy|district|county|city|state|department|dept|agency|bureau|board|commission|"
    r"authority|council|ministry|hospital|health|healthcare|medical|clinic|dental|center|"
    r"centre|institute|laboratory|laboratories|labs|bank|credit|insurance|assurance|mutual|"
    r"services|service|systems|solutions|technologies|technology|enterprises|industries|"
    r"international|national|federal|global|worldwide|usa|america|american|church|ministries|"
    r"union|cooperative|co-op|club|team|networks|network|media|studios|studio|restaurant|"
    r"hotels|hotel|motors|motor|pharmacy|pharmaceuticals|capital|financial|finance|realty|"
    r"properties|property|management|consulting|consultants|engineering|construction|"
    r"logistics|transport|airlines|energy|resources|foods|food|brands|brand|stores|store|"
    r"market|markets|supply|products|manufacturing|mfg|imaging|diagnostics|genetics|"
    r"gaming|casino|resorts|resort|academy|charter|institute)\b", re.I)

# A personal-name shape: optional title, given name, optional middle initial, optional
# nobiliary particle, family name, optional suffix or post-nominal. Deliberately loose — see
# the recall note above. Case-SENSITIVE on the name parts (a lowercase word is not a given
# name), so the post-nominals are spelled out case-insensitively instead of using re.I.
_PERSON_SHAPE = re.compile(
    r"^(?:(?:Dr|Mr|Mrs|Ms|Prof)\.?\s+)?"
    r"[A-Z][a-z'’\-]{1,}"
    r"(?:\s+[A-Z]\.?)?"
    r"(?:\s+(?:van|von|de|del|della|di|da|dos|la|le|el|bin|ibn|al))?"
    r"\s+[A-Z][a-z'’\-]{1,}"
    r"(?:[,\s]+(?:[Jj][Rr]|[Ss][Rr]|II|III|IV|M\.?D|D\.?D\.?S|DO|DC|OD|C\.?P\.?A|"
    r"[Ee]sq|Ph\.?D|RN|LCSW|DPM|DVM)\.?)?$")

# A post-nominal is by itself strong evidence of a natural person, even when an organisation
# word also appears ("Andrew Lundholm CPA Inc" is still a person's practice).
_POST_NOMINAL = re.compile(
    r"[,\s](?:M\.?D|D\.?D\.?S|D\.?O|D\.?C|O\.?D|C\.?P\.?A|Esq|Ph\.?D|R\.?N|L\.?C\.?S\.?W|"
    r"D\.?P\.?M|D\.?V\.?M)\.?\s*$", re.I)


# A trailing legal form, so `Andrew Lundholm CPA, Inc.` can be reduced to `Andrew Lundholm CPA`
# before the post-nominal test, which is anchored at the end. Anchoring matters: an unanchored
# search for "MD" would flag `MD Anderson Cancer Center` on a substring that is a US state
# abbreviation, not a degree.
_TRAILING_ORG_FORM = re.compile(
    r"[,\s]+(?:inc|incorporated|llc|l\.l\.c|corp|corporation|co|company|ltd|limited|lp|llp|"
    r"pllc|plc|pc)\.?\s*$", re.I)


def looks_like_person(name: str) -> bool:
    """True when the filer name might be a natural person, so a human should be asked.

    Not a verdict. A True here withholds the row and queues the name; it never publishes a
    conclusion about anyone.
    """
    n = (name or "").strip()
    if not n:
        return False
    bare = _TRAILING_ORG_FORM.sub("", n).strip()
    # A post-nominal is decisive on its own: a sole practitioner who incorporated is still a
    # person filing under their own name.
    if _POST_NOMINAL.search(bare):
        return True
    if _ORG_FORM.search(n):
        return False
    return bool(_PERSON_SHAPE.match(n))


def name_hash(name: str) -> str:
    """Stable id for a decided individual, so the decision can be recorded without the name."""
    return hashlib.sha256((name or "").strip().encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- decisions

def empty_decisions() -> dict:
    return {"schema": SCHEMA, "organisations": [], "individual_hashes": []}


def load_decisions(path: Path) -> dict:
    if not path.exists():
        return empty_decisions()
    d = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(d, dict) or "organisations" not in d:
        raise ValueError(f"{path}: not a filer decisions file")
    d.setdefault("individual_hashes", [])
    return d


def validate_decisions(doc: dict) -> list[str]:
    """Return a list of problems. Empty list == the file may be used."""
    errs: list[str] = []
    if doc.get("schema") != SCHEMA:
        errs.append(f"schema must be {SCHEMA}, got {doc.get('schema')!r}")
    orgs = doc.get("organisations")
    if not isinstance(orgs, list) or any(not isinstance(x, str) or not x.strip() for x in orgs):
        errs.append("`organisations` must be a list of non-empty names, exactly as published")
    hashes = doc.get("individual_hashes")
    if not isinstance(hashes, list):
        errs.append("`individual_hashes` must be a list")
    else:
        for h in hashes:
            if not isinstance(h, str) or not re.fullmatch(r"[0-9a-f]{64}", h):
                errs.append(f"`individual_hashes` entry is not a sha256 hex digest: {h!r}")
    # The one mistake this file invites is pasting a person's NAME into individual_hashes,
    # which would write into a permanent public file the very string the split exists to keep
    # out of one. The digest check above already rejects it; this says why in the message.
    return errs


def decide(name: str, decisions: dict) -> str:
    """'organisation' (publish), 'individual' (never publish), or 'undecided' (withhold, ask)."""
    n = (name or "").strip()
    if not looks_like_person(n):
        return "organisation"
    if n in set(decisions.get("organisations") or []):
        return "organisation"
    if name_hash(n) in set(decisions.get("individual_hashes") or []):
        return "individual"
    return "undecided"


def split(rows: list[dict], decisions: dict) -> tuple[list[dict], list[dict]]:
    """Partition fetched rows into (publishable, withheld).

    Withheld rows are dropped before anything is written, so neither the page nor the record
    ever carries the name.
    """
    keep, held = [], []
    for r in rows:
        (keep if decide(r.get("organization"), decisions) == "organisation" else held).append(r)
    return keep, held


# ---------------------------------------------------------------- the queue

def empty_queue() -> dict:
    return {"schema": SCHEMA, "pending": []}


def load_queue(path: Path) -> dict:
    if not path.exists():
        return empty_queue()
    d = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(d, dict) or "pending" not in d:
        raise ValueError(f"{path}: not a filer queue file")
    return d


def save_queue(path: Path, queue: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(queue, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def update_queue(queue: dict, withheld: list[dict], decisions: dict, *,
                 seen_date: str) -> tuple[dict, list[dict]]:
    """Refresh the queue from this run's withheld rows. Returns (queue, newly queued rows).

    This file is a WORK QUEUE, not a record: it shrinks when a decision lands, which is why it
    is kept out of state_ag.json and out of the append-only guarantee. It stores only a hash,
    a jurisdiction and a date — never the name.

    Only rows that are newly pending are returned, so a name already waiting does not re-open a
    notice every day and train the reader to ignore it.
    """
    decided_h = set(decisions.get("individual_hashes") or [])
    decided_n = set(decisions.get("organisations") or [])
    known = {p["hash"] for p in queue.get("pending", [])}
    new: list[dict] = []
    pending = list(queue.get("pending", []))

    for r in withheld:
        n = (r.get("organization") or "").strip()
        h = name_hash(n)
        if h in decided_h or n in decided_n:
            continue                      # decided since it was last seen
        if h in known:
            continue                      # already waiting
        pending.append({"hash": h, "jurisdiction": r.get("jurisdiction"),
                        "reported_date": r.get("reported_date"), "first_seen": seen_date})
        known.add(h)
        new.append(r)

    # Drop entries that have since been decided. A queue that never empties is not a queue.
    still = []
    for p in pending:
        if p["hash"] in decided_h:
            continue
        still.append(p)
    queue["schema"] = SCHEMA
    queue["pending"] = sorted(still, key=lambda p: (p.get("reported_date") or "", p["hash"]))
    return queue, new


def resolved_organisations(queue: dict, decisions: dict) -> dict:
    """Remove queue entries whose name has been approved as an organisation.

    Approval is recorded by NAME, and the queue holds only hashes, so the match is made by
    hashing each approved name once.
    """
    approved = {name_hash(n) for n in (decisions.get("organisations") or [])}
    queue["pending"] = [p for p in queue.get("pending", []) if p["hash"] not in approved]
    return queue
