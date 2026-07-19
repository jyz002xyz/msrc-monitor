#!/usr/bin/env python3
"""
notify.py — notify via Pushover only when a flag is raised (edge-triggered)

Fires only when diff.py's result has any_flag — the same "notify only on state
change" approach as the bots. It runs monthly, so usually once a month, but to
avoid duplicate notifications on re-runs it records the last-notified flag set
and does not re-notify if it is unchanged.

★ What this module does NOT do (design rules) ★
    - No attribution or interpretation. Only the fact that something changed,
      plus counts.
    - priority is normal (0). Never treated as urgent (this is monitoring, not
      an incident alert).
    - Never expose secrets (Pushover token, etc.) in code, logs, or git.

Credentials:
    Read from env vars PUSHOVER_TOKEN / PUSHOVER_USER. If either is unset,
    skip the notification, warn, and exit normally (do not crash). Kept
    self-contained within this monitor (no cross-repo dependency).

Usage:
    python notify.py 2026-Jul          # notify if there is a flag
    python notify.py 2026-Jul --force  # notify even with no flag (for testing)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests

import diff

PUSHOVER_URL = "https://api.pushover.net/1/messages.json"


def _flag_lines(rep: dict) -> list[str]:
    """Turn only the flagged items into one-line fact+count entries (no attribution or interpretation)."""
    lines: list[str] = []
    if not rep.get("prev_available"):
        return lines
    c = rep["changes"]

    ct = c["cve_total"]
    if ct["flag"]:
        pct = "n/a" if ct["pct"] is None else f"{ct['pct']:+.0%}"
        lines.append(f"total CVEs: {ct['prev']}->{ct['now']} ({pct}, threshold exceeded)")

    hv = c["heavy"]
    if hv["flag"]:
        ratio = "n/a" if hv["ratio"] is None else f"{hv['ratio']:.2f}x"
        lines.append(f"heavy tier T2+T3: {hv['prev']}->{hv['now']} ({ratio}, threshold exceeded)")

    zd = c["zero_days_uncredited"]
    if zd["flag"]:
        lines.append(f"uncredited zero-days: {zd['count']}")

    for item in rep.get("new_credits") or []:
        if item["flag"]:
            lines.append(f'new credit "{item["name"]}": {item["count"]}')

    return lines


def _last_notified_path(month: str) -> Path:
    return diff.state_dir() / f".last_notified_{month}.json"


def _already_notified(month: str, lines: list[str]) -> bool:
    """True if the flag set is identical to last time (do not re-notify)."""
    path = _last_notified_path(month)
    if not path.exists():
        return False
    try:
        prev = json.loads(path.read_text())
    except Exception:
        return False
    return prev.get("lines") == lines


def _record_notified(month: str, lines: list[str], fetched_at: str | None) -> None:
    path = _last_notified_path(month)
    path.write_text(json.dumps(
        {"lines": lines, "fetched_at": fetched_at},
        ensure_ascii=False, indent=2))


def send_pushover(token: str, user: str, title: str, message: str) -> bool:
    """POST to Pushover. True on success. Never log secrets."""
    resp = requests.post(PUSHOVER_URL, data={
        "token": token,
        "user": user,
        "title": title,
        "message": message,
        "priority": 0,     # normal. never treated as urgent
    }, timeout=20)
    resp.raise_for_status()
    return True


# ===========================================================================
# KEV new-listing notification (Phase 2). edge-triggered.
#   ★ Only KEV is a notification trigger. EPSS is never used for notifications (principle 2). ★
#   ★ Never infer discoverer/causation from KEV/EPSS numbers. Facts (CVE-IDs) only (principles 1 & 4). ★
# ===========================================================================
def _kev_notified_path() -> Path:
    return diff.state_dir() / ".last_notified_kev.json"


def _load_kev_notified() -> set[str]:
    p = _kev_notified_path()
    if p.exists():
        try:
            return set(json.loads(p.read_text()).get("notified") or [])
        except Exception:
            return set()
    return set()


def _save_kev_notified(notified: set[str]) -> None:
    p = _kev_notified_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"notified": sorted(notified)}, ensure_ascii=False, indent=2))


def notify_kev(enrichment: dict, force: bool = False) -> int:
    """Notify KEV new listings from the enrichment (edge-triggered). EPSS is not used.

    Records notified CVEs in .last_notified_kev.json so the same listing is not
    re-notified (dedup on the notify side, independent of enrich's run order).
    """
    kev_listed = enrichment.get("kev_listed")
    if kev_listed is None:
        print("[notify] KEV not acquired (unreachable). Not notifying.")
        return 0

    already = _load_kev_notified()
    new = sorted(set(kev_listed) - already)
    if force and not new:
        new = list(kev_listed[:1])  # for testing
    if not new:
        print("[notify] No new KEV listings. Not notifying.")
        return 0

    month = enrichment.get("month", "")
    title = f"MSRC {month}: {len(new)} new KEV listing(s)"
    # Facts (CVE-IDs) only. No EPSS values, attribution, or interpretation.
    message = "\n".join(f"listed in KEV: {cve}" for cve in new)

    token = os.environ.get("PUSHOVER_TOKEN")
    user = os.environ.get("PUSHOVER_USER")
    if not token or not user:
        print("[notify] warning: PUSHOVER_TOKEN/PUSHOVER_USER not set. Skipping notification.",
              file=sys.stderr)
        return 0
    try:
        send_pushover(token, user, title, message)
    except Exception as e:
        print(f"[notify] warning: failed to send KEV notification: {e}", file=sys.stderr)
        return 0

    _save_kev_notified(already | set(new))
    print(f"[notify] {month}: notified {len(new)} new KEV listing(s)")
    return 0


def notify(month: str, force: bool = False, prev_tag: str | None = None) -> int:
    """
    Evaluate the month tag's diff and notify if needed.
    Returns an exit code (always exits normally / 0-ish; never crashes).
    """
    rep = diff.build_report(month, prev_tag)
    lines = _flag_lines(rep)

    should_notify = bool(rep.get("any_flag")) or force
    if not should_notify:
        print(f"[notify] {month}: no flag. Not notifying.")
        return 0

    if force and not lines:
        lines = ["(--force: no flag, but test notification)"]

    # edge-triggered: prevent re-notifying the same flag set (--force always sends)
    if not force and _already_notified(month, lines):
        print(f"[notify] {month}: same as last time. Not re-notifying.")
        return 0

    token = os.environ.get("PUSHOVER_TOKEN")
    user = os.environ.get("PUSHOVER_USER")
    if not token or not user:
        # secrets unset: warn and exit normally without crashing
        print("[notify] warning: PUSHOVER_TOKEN/PUSHOVER_USER not set. Skipping notification.",
              file=sys.stderr)
        return 0

    title = f"MSRC {month}: {len(lines)} change(s) to review"
    message = "\n".join(lines)

    try:
        send_pushover(token, user, title, message)
    except Exception as e:
        # a send failure must not crash either (collect/draft are already done)
        # e contains no secrets (requests exceptions carry only URL/status)
        print(f"[notify] warning: Pushover send failed: {e}", file=sys.stderr)
        return 0

    _record_notified(month, lines, rep.get("fetched_at"))
    print(f"[notify] {month}: notified ({len(lines)})")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Notify via Pushover only when a flag is raised (edge-triggered)")
    ap.add_argument("month", help="current month tag, e.g. 2026-Jul")
    ap.add_argument("--prev", help="month tag to compare against (defaults to the previous month)")
    ap.add_argument("--force", action="store_true",
                    help="notify even with no flag (for testing)")
    args = ap.parse_args()

    try:
        return notify(args.month, force=args.force, prev_tag=args.prev)
    except FileNotFoundError as e:
        print(f"[notify] error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
