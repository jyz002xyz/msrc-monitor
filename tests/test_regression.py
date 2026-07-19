#!/usr/bin/env python3
"""
test_regression.py — regression tests locking in bugs found during the 2026-07 investigation

The goal here is not "performance" but "never falling into the same trap twice".
Each test corresponds one-to-one with a real mistake that actually occurred.
Always run this after changing any script (run_monthly.sh also runs it up front).

Run:
    cd ~/msrc_monitor
    python3 -m pytest tests/ -v
    # if pytest is unavailable: python3 tests/test_regression.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cvrf_parse as cp


# --- test helper: build a minimal CVRF vuln dict ----------------------------
def mk_vuln(cve, title, sev="Important", acks=None, exploit="", impact="Remote Code Execution"):
    v = {
        "CVE": cve,
        "Title": {"Value": title},
        "Threats": [
            {"Type": cp.THREAT_IMPACT, "Description": {"Value": impact}},
            {"Type": cp.THREAT_SEVERITY, "Description": {"Value": sev}},
        ],
    }
    if exploit:
        v["Threats"].append({"Type": cp.THREAT_EXPLOIT_STATUS, "Description": {"Value": exploit}})
    if acks is not None:
        v["Acknowledgments"] = acks
    return v


def ack(*names):
    """Build a single Acknowledgment whose Name Value holds the given strings"""
    return [{"Name": [{"Value": n} for n in names]}]


# ===========================================================================
# Lesson #1: HTML contamination — strip <a href> from credit strings before parsing
# ===========================================================================
def test_html_stripped_from_credit():
    # In real data, credit strings arrive as 'Name with <a href="https://org.example/">Org</a>',
    # mixing HTML into the credit. Strip it before parsing the name (synthetic example).
    v = mk_vuln("CVE-2026-48561", "Windows RDP RCE",
                acks=ack('Researcher Name with <a href="https://example.com/">Example Org</a>'))
    names = cp.credit_names(v)
    assert len(names) == 1
    assert "<a href" not in names[0], "HTML tag was not stripped"
    assert "example.com" not in names[0], "URL fragment remains"
    assert "Researcher Name" in names[0]


# ===========================================================================
# Lesson #2: double listing — the same name listed twice on one CVE still counts as 1 CVE
#          (we once miscounted this as 78; the correct figure is 39)
# ===========================================================================
def test_double_listing_counts_once():
    # Real-data pattern where Kugelblitz is listed twice on the same CVE
    vulns = [
        mk_vuln(f"CVE-2026-{n}", "Microsoft Edge (Chromium-based) RCE",
                acks=ack("Kugelblitz with Microsoft", "Kugelblitz with Microsoft"))
        for n in range(57974, 57994)  # 20 CVEs
    ]
    doc = {"Vulnerability": vulns}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    # Kugelblitz appears twice on each of 20 CVEs -> raw count would be 40, but 20 is correct
    assert s["credit_counts"]["Kugelblitz with Microsoft"] == 20, \
        f"double listing was double-counted: {s['credit_counts']}"


def test_double_listing_credited_flag():
    # Even with double listing, credited counts only once
    v = mk_vuln("CVE-2026-57974", "Edge RCE",
                acks=ack("Kugelblitz with Microsoft", "Kugelblitz with Microsoft"))
    doc = {"Vulnerability": [v]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    assert s["credited"] == 1
    assert s["cve_total"] == 1


# ===========================================================================
# Lesson #3: uncredited detection — missing/empty field = uncredited (binary)
# ===========================================================================
def test_no_acknowledgments_is_uncredited():
    # The Acknowledgments field itself is absent (real data: the CVE in image 1)
    v = mk_vuln("CVE-2026-90001", "Windows Kernel RCE", sev="Critical",
                exploit="Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely")
    assert cp.is_credited(v) is False
    assert cp.credit_names(v) == []


def test_empty_name_is_uncredited():
    # Acknowledgments is present but the Name Value is empty
    v = mk_vuln("CVE-2026-90002", "Windows RCE", acks=[{"Name": [{"Value": ""}]}])
    assert cp.is_credited(v) is False


def test_credited_vs_uncredited_counts():
    doc = {"Vulnerability": [
        mk_vuln("CVE-2026-1", "A", acks=ack("Alice")),
        mk_vuln("CVE-2026-2", "B"),                       # none
        mk_vuln("CVE-2026-3", "C", acks=ack("Bob")),
        mk_vuln("CVE-2026-4", "D", acks=[{"Name": [{"Value": ""}]}]),  # empty = none
    ]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    assert s["cve_total"] == 4
    assert s["credited"] == 2
    assert s["uncredited"] == 2


# ===========================================================================
# Lesson #4: recording fetch timing — fetched_at is always present in the summary
# ===========================================================================
def test_fetched_at_recorded():
    doc = {"Vulnerability": [mk_vuln("CVE-2026-1", "A")]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    assert s["fetched_at"] == "2026-07-15T07:00:00", "fetch timestamp was not recorded"


# ===========================================================================
# Lesson #5: no attribution — verify no attribution judgment leaks into the summary
#          (credit_counts is just string -> count; there are no flags like 'is_mdash')
# ===========================================================================
def test_no_attribution_flags_in_summary():
    v = mk_vuln("CVE-2026-57974", "Edge RCE", acks=ack("Kugelblitz with Microsoft"))
    doc = {"Vulnerability": [v]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    # No summary key should suggest attribution
    flat = str(s).lower()
    for forbidden in ["mdash", "is_ai", "is_tool", "attributed"]:
        assert forbidden not in [k.lower() for k in s.keys()], \
            f"attribution flag '{forbidden}' leaked into the summary"
    # _note carries the warning
    assert "kugelblitz" in s["_note"].lower()


# ===========================================================================
# Reboot-class classification (foundation of the three-tier model)
# ===========================================================================
def test_tier_classification():
    assert cp.tier_of(mk_vuln("x", "Windows Secure Boot Security Feature Bypass")) == "T3"
    assert cp.tier_of(mk_vuln("x", "Microsoft SharePoint Server RCE")) == "T2"
    assert cp.tier_of(mk_vuln("x", "Microsoft Edge (Chromium-based) RCE")) == "T0/T1"
    assert cp.tier_of(mk_vuln("x", "Windows BitLocker Bypass")) == "T3"


# ===========================================================================
# Zero-day finder capture (H3: are exploited vulns human-discovered)
# ===========================================================================
def test_zero_day_credit_capture():
    doc = {"Vulnerability": [
        mk_vuln("CVE-2026-56155", "AD FS EoP", sev="Important",
                acks=ack("Test Analyst, Microsoft DART"),
                exploit="Publicly Disclosed:No;Exploited:Yes", impact="Elevation of Privilege"),
        mk_vuln("CVE-2026-90001", "Windows Kernel RCE", sev="Critical"),  # normal
    ]}
    s = cp.summarize(doc, "2026-Jul", "2026-07-15T07:00:00")
    assert len(s["zero_days"]) == 1
    zd = s["zero_days"][0]
    assert zd["exploited"] is True
    assert zd["credited"] is True
    assert "DART" in zd["credits"][0]


# --- runner that also works without pytest ----------------------------------

# ===========================================================================
# Added (2026-07): separating hash credits
#   In real data, 32-hex-digit hashes like "0123456789abcdef0123456789abcdef"
#   were credited 47 times. Do not mix these with named (external) researchers.
#   Note: this test is a memo for the logic on the msrc_action.py (attribution) side.
#     cvrf_parse.py has no finder_bucket (aggregation is the attribution side's job).
# ===========================================================================
def test_hash_credit_shape():
    """Shape check for hash identifiers (reference-implementation memo)"""
    import re
    HASH_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
    assert HASH_RE.match("0123456789abcdef0123456789abcdef")
    assert not HASH_RE.match("Sample Researcher")
    assert not HASH_RE.match("abc")       # do not misclassify short names
    assert not HASH_RE.match("Anonymous")


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
        except Exception:
            print(f"  ERROR {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
