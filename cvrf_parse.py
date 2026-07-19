#!/usr/bin/env python3
"""
cvrf_parse.py — self-contained MSRC CVRF v3.0 parser (msrc_monitor only)

This module is independent of msrc_action.py, so the monitor can live in a
single self-contained directory and run on the Pi with no external deps.

Lessons baked into this parser (bugs found during the 2026-07 investigation):
    1. Strip HTML: credit strings can contain <a href=...> markup. Names must
       be cleaned before classification or the buckets break.
    2. Drop duplicate listings: a single CVE can list the same credit twice
       (e.g. Kugelblitz x2). Without per-CVE dedup the counts double.
       -> This actually mis-counted "78" once; the correct number was 39.
    3. Uncredited detection: no Acknowledgments field, or all names empty,
       means uncredited. Treat this as binary (do not classify the contents).
    4. Record fetch timing: CVRF credits are filled in gradually after Patch
       Tuesday. Always record the fetch date so freshness can be judged later.
    5. NO ATTRIBUTION: this parser only tallies credit names mechanically. It
       never decides things like "Kugelblitz = MDASH", i.e. attributing an
       entity to an AI/tool. That is a human's job (must be confirmed against
       primary sources). In 2026-07 we wrongly asserted Kugelblitz=MDASH and
       were later refuted by primary sources.

Target: Python 3.12+ / deps: requests only
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

# --- CVRF schema constants (verified against the parser and real data) -------
THREAT_IMPACT = 0
THREAT_EXPLOIT_STATUS = 1
THREAT_SEVERITY = 3
REMEDIATION_VENDOR_FIX = 2

HTML_TAG = re.compile(r"<[^>]+>")

# Reboot class (same definition as msrc_action.py)
T3_RE = re.compile(r"secure\s*boot|boot\s*manager|boot\s*loader|uefi|bitlocker|"
                   r"\btpm\b|firmware|\bdbx\b", re.I)
T2_RE = re.compile(r"exchange\s*server|sharepoint|sql\s*server|dynamics|"
                   r"system\s*center|configuration\s*manager", re.I)

SEV_RANK = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}


def clean_name(raw: str | None) -> str:
    """Strip HTML tags and surrounding whitespace. Lesson #1."""
    return HTML_TAG.sub("", raw or "").strip()


def credit_names(vuln: dict) -> list[str]:
    """
    Return this CVE's list of finder names (HTML stripped, empties removed).
    Duplicates within the same CVE are kept here (reflecting the raw listing).
    Per-CVE dedup happens on the counting side. Lesson #1.
    """
    out: list[str] = []
    for ack in vuln.get("Acknowledgments") or []:
        for n in ack.get("Name") or []:
            val = n.get("Value") if isinstance(n, dict) else n
            c = clean_name(val)
            if c:
                out.append(c)
    return out


def is_credited(vuln: dict) -> bool:
    """Whether there is at least one credit. Binary. Lesson #3."""
    return len(credit_names(vuln)) > 0


def severity_of(vuln: dict) -> str:
    best, best_r = "Unrated", 0
    for t in vuln.get("Threats") or []:
        if t.get("Type") == THREAT_SEVERITY:
            v = (t.get("Description") or {}).get("Value") or ""
            if SEV_RANK.get(v, 0) > best_r:
                best, best_r = v, SEV_RANK[v]
    return best


def exploit_status(vuln: dict) -> str:
    for t in vuln.get("Threats") or []:
        if t.get("Type") == THREAT_EXPLOIT_STATUS:
            return ((t.get("Description") or {}).get("Value") or "").replace(" ", "")
    return ""


def tier_of(vuln: dict) -> str:
    title = ((vuln.get("Title") or {}).get("Value")) or ""
    if T3_RE.search(title):
        return "T3"
    if T2_RE.search(title):
        return "T2"
    return "T0/T1"


# ===========================================================================
# Population split, product classification, finder buckets
#   Ported from the --breakdown logic in msrc_action.py (the attribution
#   version); nothing is newly invented here. Everything is mechanical string
#   classification -- no guessing at the identity behind an AI/tool. Lesson #5.
# ===========================================================================

# --- Population split: products excluded from the MS-core population
#     (the ones the press treats as "separate") ---
EXCLUDE_EDGE = re.compile(r"microsoft\s*edge|chromium", re.I)
EXCLUDE_MARINER = re.compile(r"\bmariner\b|azure\s*linux|\bcbl-?mariner\b", re.I)
EXCLUDE_CLOUD = re.compile(r"azure\s+(?!stack)|microsoft\s*graph|entra|"
                          r"microsoft\s*365\s*copilot|copilot\s+studio|"
                          r"power\s*(bi|apps|automate)|dynamics\s*365\s*\(online\)", re.I)


def population_of(title: str) -> str:
    """Assign a CVE to a population: 'core' (MS-core) or 'excluded' (Edge/Mariner/Cloud)."""
    if EXCLUDE_EDGE.search(title):
        return "excluded"
    if EXCLUDE_MARINER.search(title):
        return "excluded"
    if EXCLUDE_CLOUD.search(title):
        return "excluded"
    return "core"


# --- Product category (evaluated top to bottom; put more specific ones first) ---
# The category identifiers are language-neutral internal keys (alphanumeric).
# The JA/EN display labels are rendered only via the single map in
# report/category_labels.json (never show Japanese in the English edition).
# Internal keys are not used for display (display always goes through the map).
PRODUCT_CATS: list[tuple[str, re.Pattern]] = [
    ("edge_chromium", re.compile(r"microsoft\s*edge|chromium", re.I)),
    ("office", re.compile(r"\boffice\b|word|excel|powerpoint|outlook|visio|onenote|\bpublisher\b", re.I)),
    ("sharepoint", re.compile(r"sharepoint", re.I)),
    ("exchange", re.compile(r"exchange", re.I)),
    ("sql_dynamics", re.compile(r"sql\s*server|dynamics", re.I)),
    ("boot_crypto", re.compile(r"secure\s*boot|uefi|bitlocker|\btpm\b|boot\s*(manager|loader)", re.I)),
    ("auth_identity", re.compile(r"\bad\s*fs\b|federation|kerberos|\bntlm\b|credential|authentication|\blsa\b|local\s*security\s*authority", re.I)),
    ("networking", re.compile(r"tcp/?ip|http\.sys|\bhttp/?[23]?\b|\bdhcp\b|\bdns\b|\bsmb\b|\brpc\b|netlogon|ikev?2|ipsec|rmcast|multicast|routing\s*and\s*remote|\brras\b|winsock|ancillary\s*function|\bwins\b|\bnfs\b|\bldap\b|message\s*queu|\bmsmq\b|network\s*(driver|stack|file)", re.I)),
    ("rdp_remote", re.compile(r"remote\s*desktop|\brdp\b|terminal\s*serv|remote\s*access", re.I)),
    ("hyperv_virtual", re.compile(r"hyper-?v|virtual\s*machine|\bvmbus\b|virtualization", re.I)),
    ("kernel_driver", re.compile(r"kernel|win32k|\bntfs\b|\bclfs\b|common\s*log\s*file|storage|\bdriver\b|ancillary|win32|subsystem|\bafd\b|\bwdac\b|kernel-?mode", re.I)),
    ("graphics_media", re.compile(r"graphics|\bgdi\b|\bmedia\b|codec|imaging|\bfont\b|\bdwm\b|desktop\s*window|direct\s*(x|3d|write)|\bgpu\b", re.I)),
    ("azure_cloud", re.compile(r"azure|entra|\bgraph\b|copilot|\bintune\b", re.I)),
    ("dotnet_dev", re.compile(r"\.net|visual\s*studio|\bnuget\b|powershell|\basp\.net\b", re.I)),
    ("mariner_linux", re.compile(r"mariner|azure\s*linux", re.I)),
    # Core Windows services/components (catch-all for generic EoP/RCE not matched above)
    ("win_services", re.compile(
        r"windows\s+\w+.*(service|driver|component|subsystem|manager|provider|"
        r"agent|client|host|engine|framework|runtime|store|installer|update|"
        r"telephony|brokering|search|backup|recovery|error\s*reporting|"
        r"print|spooler|task\s*scheduler|event\s*log|registry|shell|"
        r"defender|security|smart\s*card|biometric|hello|cryptographic|"
        r"win32|fax|\bcsc\b|distributed|composite|connected|cloud\s*files)", re.I)),
    ("win_services", re.compile(r"brokering|file\s*system|\bmsmq\b|"
        r"win32|telephony|spooler|task\s*scheduler", re.I)),
    ("win_services", re.compile(r"^windows\s+\w+", re.I)),  # any other Windows *
    ("microsoft_other", re.compile(r"^microsoft\s+\w+", re.I)),      # any other Microsoft *
]

# Internal key for the classification fallback (formerly "other"). Displayed via category_labels.json.
PRODUCT_CAT_FALLBACK = "other"


def product_cat(title: str) -> str:
    """Return the language-neutral internal key for the product category
    (alphanumeric), not a display name. JA/EN display is resolved through
    the map in report/category_labels.json."""
    for name, pat in PRODUCT_CATS:
        if pat.search(title):
            return name
    return PRODUCT_CAT_FALLBACK


# --- Finder buckets (to see the breakdown within "with Microsoft") ---
MS_INTERNAL_RE = re.compile(r"with\s+microsoft|microsoft\s+(internal|red\s+team|"
                           r"security|offensive)|\bMORSE\b|\bDART\b|\bMSRC\b|\bWARP\b|\bACS\b", re.I)
ANON_RE = re.compile(r"anonymous", re.I)
# 16+ hex-char string = a hash identifier anonymized by Microsoft
# (e.g. 0123456789abcdef0123456789abcdef). Human or automation is unknown.
# Lesson: keep separate from real names.
HASH_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)


def is_hash_credit(name: str) -> bool:
    """Whether the credit name is a bare hash identifier."""
    return bool(HASH_RE.match(name.strip()))


def finder_bucket(credited: bool, credits: list[str]) -> str:
    """Coarse finder bucket: uncredited / ms_internal / hash_anon / anonymous / external

    Evaluation order:
      1. No credit
      2. Internal (with Microsoft / MORSE / ACS etc.)  <- judged by name + affiliation
      3. Hash identifiers only (do not mix with named researchers)
      4. Anonymous only
      5. Otherwise = external researcher (named)
    No attribution (do not guess the identity behind an AI/tool). Mechanical
    string classification only. Lesson #5.
    """
    if not credited:
        return "uncredited"
    blob = " | ".join(credits)
    if MS_INTERNAL_RE.search(blob):
        return "ms_internal"
    non_hash = [c for c in credits if not is_hash_credit(c)]
    if not non_hash:
        return "hash_anon"
    named = [c for c in non_hash if not ANON_RE.search(c)]
    if not named:
        return "anonymous"
    return "external"


def cve_is_target(vuln: dict) -> bool:
    """Whether this CVE is a target for KEV/EPSS matching.

    Condition (any of): heavy reboot class (T2/T3) / severity Critical /
    external (named) researcher credit. Excludes the low-severity Edge long
    tail to cut API load and noise. A mechanical filter, not an attribution call.
    """
    names = credit_names(vuln)
    return (tier_of(vuln) in ("T2", "T3")
            or severity_of(vuln) == "Critical"
            or finder_bucket(bool(names), names) == "external")


def target_cves_from_doc(doc: dict) -> list[dict]:
    """Return lightweight rows for the target CVEs from a CVRF document (for KEV/EPSS matching).

    Each row is {cve, tier, severity, finder, title, category}. No attribution
    or interpretation. title/category are facts derived from the CVRF (this
    document), a different source from the KEV/EPSS values. category reuses the
    same product_cat() classification as Table 5 (by product category). The
    enrichment layer consumes this (it does not depend on frozen state).
    """
    out: list[dict] = []
    for v in doc.get("Vulnerability") or []:
        if cve_is_target(v):
            names = credit_names(v)
            title = ((v.get("Title") or {}).get("Value")) or ""
            out.append({
                "cve": v.get("CVE") or "",
                "tier": tier_of(v),
                "severity": severity_of(v),
                "finder": finder_bucket(bool(names), names),
                "title": title,
                "category": product_cat(title),
            })
    return out


def summarize(doc: dict, month: str, fetched_at: str) -> dict:
    """
    Fold a single CVRF document into a summary for monitoring.
    Contains no judgment or attribution -- fact tallies only. Lesson #5.

    The return value is the shape saved to state/{month}.json.
    """
    vulns = doc.get("Vulnerability") or []
    total = len(vulns)

    tier_count: dict[str, int] = defaultdict(int)
    sev_count: dict[str, int] = defaultdict(int)
    credited = 0

    # credit name -> set of CVEs containing it (dedup per CVE. Lesson #2)
    credit_to_cves: dict[str, set[str]] = defaultdict(set)

    zero_days: list[dict] = []

    # --- Tallies for population split / product / finder buckets (ported from msrc_action) ---
    core_total = 0
    excluded_total = 0
    sev_core: dict[str, int] = defaultdict(int)
    tier_core: dict[str, int] = defaultdict(int)
    product_count: dict[str, int] = defaultdict(int)
    finder_count: dict[str, int] = defaultdict(int)
    kugelblitz = 0
    # Tally Critical by finder bucket (counts only; do not store individual names = data minimization)
    critical_by_finder: dict[str, int] = defaultdict(int)
    kugelblitz_in_critical = 0
    # Target CVEs for KEV/EPSS matching (T2/T3 v Critical v external). For count reduction.
    target_cve_ids: list[str] = []

    for v in vulns:
        cve = v.get("CVE") or ""
        title = ((v.get("Title") or {}).get("Value")) or ""
        sev = severity_of(v)
        tr = tier_of(v)
        tier_count[tr] += 1
        sev_count[sev] += 1

        names = credit_names(v)
        if names:
            credited += 1
        # duplicate names within the same CVE collapse to one via set.add
        for nm in set(names):
            credit_to_cves[nm].add(cve)

        # Population (core / excluded), and severity / reboot class on the core side
        if population_of(title) == "core":
            core_total += 1
            sev_core[sev] += 1
            tier_core[tr] += 1
        else:
            excluded_total += 1

        # Product category (population = all)
        product_count[product_cat(title)] += 1
        # Finder bucket (population = all, per CVE)
        bucket = finder_bucket(bool(names), names)
        finder_count[bucket] += 1
        # Number of CVEs with a Kugelblitz-family credit (per CVE)
        has_kugel = any("kugelblitz" in c.lower() for c in names)
        if has_kugel:
            kugelblitz += 1
        # Critical finder breakdown (counts only; do not bake real names into state)
        if sev == "Critical":
            critical_by_finder[bucket] += 1
            if has_kugel:
                kugelblitz_in_critical += 1
        # Target CVEs for KEV/EPSS matching (T2/T3 v Critical v external)
        if tr in ("T2", "T3") or sev == "Critical" or bucket == "external":
            target_cve_ids.append(cve)

        e = exploit_status(v)
        exploited = "Exploited:Yes" in e
        disclosed = "PubliclyDisclosed:Yes" in e
        if exploited or disclosed:
            zero_days.append({
                "cve": cve,
                "title": title,
                "severity": sev,
                "exploited": exploited,
                "disclosed": disclosed,
                "credited": bool(names),
                "credits": sorted(set(names)),
            })

    # CVE count per credit name (per CVE, deduped). Lesson #2
    credit_counts = {nm: len(cves) for nm, cves in credit_to_cves.items()}

    return {
        "month": month,
        "fetched_at": fetched_at,          # Lesson #4: record freshness
        "cve_total": total,
        "credited": credited,
        "uncredited": total - credited,
        "tier_count": dict(tier_count),
        "severity_count": dict(sev_count),
        # --- Population split (MS-core vs Edge/Mariner/Cloud excluded) ---
        "core_total": core_total,
        "excluded_total": excluded_total,
        "severity_core": dict(sev_core),
        "tier_core": dict(tier_core),
        # --- By product category (population = all). Descending by count ---
        "product_count": dict(sorted(product_count.items(), key=lambda x: -x[1])),
        # --- Finder buckets (population = all). Mechanical classification, not attribution ---
        "finder_bucket": dict(finder_count),
        # Convenience field for internal (with-Microsoft) count used in trends (same as finder_bucket)
        "ms_internal": finder_count.get("ms_internal", 0),
        # --- Number of CVEs with a Kugelblitz-family credit (baseline for trend monitoring) ---
        "kugelblitz": kugelblitz,
        # --- Critical finder breakdown (counts only; no real names = data minimization) ---
        "critical_by_finder": dict(critical_by_finder),
        "kugelblitz_in_critical": kugelblitz_in_critical,
        # --- Target CVE-IDs for KEV/EPSS matching (T2/T3 v Critical v external) ---
        "target_cves": target_cve_ids,
        # Save top entries only (full list would bloat). Ordered descending by count
        "credit_counts": dict(sorted(credit_counts.items(),
                                     key=lambda x: -x[1])),
        "zero_days": zero_days,
        # meta: makes explicit that this summary is a machine tally with no interpretation
        "_note": ("machine-generated factual summary. "
                  "no attribution/interpretation. "
                  "do NOT infer tool/AI identity from credit names "
                  "(see Kugelblitz lesson 2026-07)."),
    }
