#!/usr/bin/env python3
"""
make_synthetic_cvrf.py — テスト用の合成 CVRF フィクスチャを生成する。

★このリポジトリには実際の MSRC 一次データを同梱しない★
    実 CVRF には脆弱性報告者(第三者研究者)の氏名・SNSハンドル・メール等の
    個人情報が含まれるため、プライバシー配慮から同梱しない。テストは本スクリプトが
    生成する「合成データ(すべてダミー)」で動作する。

生成物: tests/fixtures/2026-Jul-cvrf-reduced.json (構造は実 CVRF v3.0 と同形)
実行:   python tests/fixtures/make_synthetic_cvrf.py

含める個人情報は一切なし。研究者名は Researcher A/B..、メールは example.com
(RFC 2606 予約ドメイン=実在しない)、ハンドルは @researcher_x のダミーのみ。
"""
import json
import os

THREAT_IMPACT = 3      # cvrf_parse.THREAT_IMPACT と同値 (Type=3: Impact/Severity)
THREAT_SEVERITY = 3
THREAT_EXPLOIT = 1     # Type=1: Exploitability/Status

# --- ダミー発見者クレジット (実在の個人・組織を一切含まない) ---
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
HASH = "0123456789abcdef0123456789abcdef"   # cvrf_parse: 16桁以上hex = 匿名ハッシュ識別子
KUGEL = "Kugelblitz with Microsoft"          # プロジェクト内の教訓用の非人名クレジット


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

    # Edge/Chromium — 最大カテゴリ(裾野)。多くは低深刻度・様々な発見者。
    for i in range(20):
        sev = "Moderate" if i % 3 else "Low"
        if i < 6:
            credit = [EXTERNAL[i % len(EXTERNAL)]]
        elif i < 9:
            credit = [KUGEL]              # Kugelblitz は面(Edge)のみ・Critical でない
        elif i < 12:
            credit = [ANON]
        elif i < 14:
            credit = [HASH]
        elif i < 16:
            credit = [MS_INTERNAL[i % 2]]
        else:
            credit = None                 # uncredited
        add(f"Microsoft Edge (Chromium-based) Spoofing Vulnerability {i}", sev, credit)

    # Office 系
    for i in range(5):
        add(f"Microsoft Office Remote Code Execution Vulnerability {i}",
            "Important", [EXTERNAL[i % len(EXTERNAL)]])

    # SharePoint (T2)。1件は悪用確認ゼロデイ。
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

    # Boot/Crypto (T3)。1件は公開済み(disclosed)ゼロデイ。
    add("Windows BitLocker Security Feature Bypass Vulnerability", "Important",
        [ANON], disclosed=True)

    # Auth/Identity。1件は悪用確認ゼロデイ(社内発見)。
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

    # その他 (other) — カテゴリ未該当。<12% に収まる少数。
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
