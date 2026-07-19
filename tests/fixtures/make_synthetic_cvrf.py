#!/usr/bin/env python3
"""
make_synthetic_cvrf.py — generate a synthetic CVRF fixture for tests.

*** This repository does not bundle any real MSRC primary data ***
    Real CVRF data contains personal information about vulnerability reporters
    (third-party researchers) -- names, social handles, emails -- so it is not
    bundled, out of privacy considerations. Tests run on the synthetic data
    (all dummy) that this script generates.

Output: tests/fixtures/2026-Jul-cvrf-reduced.json (same structure as real CVRF v3.0)
Run:    python tests/fixtures/make_synthetic_cvrf.py

No personal information is included. Researcher names are Researcher A/B..,
emails use example.com (RFC 2606 reserved domain = does not exist), and handles
are dummy values like @researcher_x.
"""
import json
import os

THREAT_IMPACT = 3      # same as cvrf_parse.THREAT_IMPACT (Type=3: Impact/Severity)
THREAT_SEVERITY = 3
THREAT_EXPLOIT = 1     # Type=1: Exploitability/Status

# --- Dummy finder credits (contain no real individuals or organizations) ---
EXTERNAL = [
    "Researcher Alpha (@researcher_alpha) with Example Security Labs",
    "Researcher Bravo with Example Research",
    "Researcher Charlie (researcher-c@example.com)",
    "Researcher Delta (https://example.com/researcher-d)",
    "Researcher Echo & Researcher Foxtrot with Example CTF Team",
    "Researcher Golf (@researcher_golf) of Example University",
]
MS_INTERNAL = ["Example Test Team with Microsoft", "Sample Analyst with Microsoft"]
ANON = "Anonymous"
HASH = "0123456789abcdef0123456789abcdef"   # cvrf_parse: hex of 16+ chars = anonymous hash identifier
KUGEL = "Kugelblitz with Microsoft"          # non-personal-name credit for an in-project lesson


def ack(*names):
    return [{"Name": [{"Value": n} for n in names]}]


def vuln(cve, title, sev, credit=None, exploit="", disclosed=False):
    threats = [
        {"Type": THREAT_IMPACT, "Description": {"Value": "Remote Code Execution"}},
        {"Type": THREAT_SEVERITY, "Description": {"Value": sev}},
    ]
    status = []
    if exploit:
        status.append("Exploited:Yes")
    if disclosed:
        status.append("PubliclyDisclosed:Yes")
    if status:
        threats.append({"Type": THREAT_EXPLOIT, "Description": {"Value": ";".join(status)}})
    v = {"CVE": cve, "Title": {"Value": title}, "Threats": threats}
    if credit is not None:
        v["Acknowledgments"] = ack(*credit) if isinstance(credit, (list, tuple)) else ack(credit)
    return v


def build():
    vulns = []
    n = [0]

    def add(title, sev, credit=None, exploit="", disclosed=False):
        n[0] += 1
        vulns.append(vuln(f"CVE-2026-{40000 + n[0]}", title, sev, credit, exploit, disclosed))

    # Edge/Chromium — largest category (the long tail). Mostly low severity, varied finders.
    for i in range(20):
        sev = "Moderate" if i % 3 else "Low"
        if i < 6:
            credit = [EXTERNAL[i % len(EXTERNAL)]]
        elif i < 9:
            credit = [KUGEL]              # Kugelblitz appears only in Edge and is never Critical
        elif i < 12:
            credit = [ANON]
        elif i < 14:
            credit = [HASH]
        elif i < 16:
            credit = [MS_INTERNAL[i % 2]]
        else:
            credit = None                 # uncredited
        add(f"Microsoft Edge (Chromium-based) Spoofing Vulnerability {i}", sev, credit)

    # Office family
    for i in range(5):
        add(f"Microsoft Office Remote Code Execution Vulnerability {i}",
            "Important", [EXTERNAL[i % len(EXTERNAL)]])

    # SharePoint (T2). One is an exploited zero-day.
    add("Microsoft SharePoint Server Elevation of Privilege Vulnerability A", "Critical",
        [EXTERNAL[0]], exploit="Exploited:Yes")
    add("Microsoft SharePoint Server Remote Code Execution Vulnerability B", "Important",
        [EXTERNAL[1]])
    add("Microsoft SharePoint Server Information Disclosure Vulnerability C", "Moderate", [ANON])

    # Networking
    for i in range(4):
        add(f"Windows TCP/IP Remote Code Execution Vulnerability {i}",
            "Critical" if i == 0 else "Important",
            [EXTERNAL[i % len(EXTERNAL)]])

    # Kernel/Driver
    for i in range(4):
        add(f"Windows Kernel Elevation of Privilege Vulnerability {i}", "Important",
            [EXTERNAL[i % len(EXTERNAL)]] if i else None)

    # Graphics/Media
    add("Windows Graphics Component Elevation of Privilege Vulnerability", "Important", [EXTERNAL[2]])
    add("Windows Media Remote Code Execution Vulnerability", "Critical", [EXTERNAL[2]])

    # Boot/Crypto (T3). One is a publicly disclosed zero-day.
    add("Windows BitLocker Security Feature Bypass Vulnerability", "Important",
        [ANON], disclosed=True)

    # Auth/Identity. One is an exploited zero-day (internally found).
    add("Active Directory Federation Services Elevation of Privilege Vulnerability", "Important",
        [MS_INTERNAL[0]], exploit="Exploited:Yes")
    add("Windows Kerberos Elevation of Privilege Vulnerability", "Important", [EXTERNAL[3]])

    # Azure/Cloud
    add("Azure Portal Spoofing Vulnerability", "Important", [EXTERNAL[4]])
    add("Azure Entra Elevation of Privilege Vulnerability", "Critical", [MS_INTERNAL[1]])

    # .NET/Dev
    add(".NET Remote Code Execution Vulnerability", "Important", [EXTERNAL[5]])

    # Win Services/Components
    for i in range(3):
        add(f"Windows Print Spooler Service Elevation of Privilege Vulnerability {i}",
            "Important", [EXTERNAL[i % len(EXTERNAL)]] if i else None)

    # SQL/Dynamics
    add("Microsoft SQL Server Remote Code Execution Vulnerability", "Important", [EXTERNAL[0]])

    # other — no matching category. A small number kept under 12%.
    add("Wireless Wide Area Network Service Elevation of Privilege Vulnerability", "Important", [ANON])
    add("Windows Widget Board Information Disclosure Vulnerability", "Low", None)

    return {"Vulnerability": vulns}


def main():
    doc = build()
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "2026-Jul-cvrf-reduced.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)
    print(f"wrote {out} ({len(doc['Vulnerability'])} synthetic vulns)")


if __name__ == "__main__":
    main()
