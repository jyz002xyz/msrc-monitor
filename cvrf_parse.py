#!/usr/bin/env python3
"""
cvrf_parse.py — MSRC CVRF v3.0 の自己完結パーサ (msrc_monitor 専用)

このモジュールは msrc_action.py から独立している。監視プログラムを
単一ディレクトリで自己完結させ、Pi 上で外部依存なく動かすため。

★このパーサに焼き込んだ「教訓」(2026-07 の調査で判明したバグ群)★
    1. HTML除去: クレジット文字列に <a href=...> が混入する。
       除去してから氏名判定しないと分類が壊れる。
    2. 二重掲載の排除: 1つのCVEに同一クレジットが2回載ることがある
       (例: Kugelblitz × 2)。CVE単位で重複排除しないと件数が倍になる。
       → 実際に "78件" と誤カウントした。正しくは39件。
    3. クレジット無し判定: Acknowledgments フィールドが無い、または
       氏名が全て空 = uncredited。これは binary で扱う(中身の分類はしない)。
    4. 取得タイミングの記録: CVRFのクレジットは Patch Tuesday 後に順次
       追記される。取得日を必ず記録し、鮮度を後から判断できるようにする。
    5. ★帰属の禁止★: このパーサは「クレジット名」を機械的に集計するだけ。
       「Kugelblitz = MDASH」のような、特定エンティティをAI/ツールに
       帰属させる判断は一切しない。それは人間の仕事(一次情報での確認が必須)。
       2026-07にKugelblitz=MDASHと誤って断定し、後に一次情報で反証された。

対象: Python 3.12+ / 依存: requests のみ
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

# --- CVRF スキーマ定数 (実装済みパーサおよび実データで検証済み) -------------
THREAT_IMPACT = 0
THREAT_EXPLOIT_STATUS = 1
THREAT_SEVERITY = 3
REMEDIATION_VENDOR_FIX = 2

HTML_TAG = re.compile(r"<[^>]+>")

# 再起動クラス (msrc_action.py と同一定義)
T3_RE = re.compile(r"secure\s*boot|boot\s*manager|boot\s*loader|uefi|bitlocker|"
                   r"\btpm\b|firmware|\bdbx\b", re.I)
T2_RE = re.compile(r"exchange\s*server|sharepoint|sql\s*server|dynamics|"
                   r"system\s*center|configuration\s*manager", re.I)

SEV_RANK = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}


def clean_name(raw: str | None) -> str:
    """HTMLタグを除去し前後空白を落とす。教訓#1。"""
    return HTML_TAG.sub("", raw or "").strip()


def credit_names(vuln: dict) -> list[str]:
    """
    このCVEの発見者名リスト(HTML除去済み・空要素除去済み)を返す。
    同一CVE内の重複はここでは保持する(生の掲載を反映)。
    件数集計側でCVE単位の重複排除を行う。教訓#1。
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
    """クレジットが1つでもあるか。binary。教訓#3。"""
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
# 母集団分離・製品分類・発見者バケット
#   msrc_action.py（帰属版）の --breakdown ロジックを移植（新規発明しない）。
#   すべて機械的な文字列分類であり、AI/ツールの正体推測（帰属）はしない。教訓#5。
# ===========================================================================

# --- 母集団分離: MS本体相当(core) から除外する製品 (報道が「別枠」扱いする分) ---
EXCLUDE_EDGE = re.compile(r"microsoft\s*edge|chromium", re.I)
EXCLUDE_MARINER = re.compile(r"\bmariner\b|azure\s*linux|\bcbl-?mariner\b", re.I)
EXCLUDE_CLOUD = re.compile(r"azure\s+(?!stack)|microsoft\s*graph|entra|"
                          r"microsoft\s*365\s*copilot|copilot\s+studio|"
                          r"power\s*(bi|apps|automate)|dynamics\s*365\s*\(online\)", re.I)


def population_of(title: str) -> str:
    """CVE を母集団に振り分け: 'core'(MS本体相当) or 'excluded'(Edge/Mariner/Cloud)"""
    if EXCLUDE_EDGE.search(title):
        return "excluded"
    if EXCLUDE_MARINER.search(title):
        return "excluded"
    if EXCLUDE_CLOUD.search(title):
        return "excluded"
    return "core"


# --- 製品カテゴリ (上から順に評価。より具体的なものを先に置く) ---
# ★カテゴリ識別子は言語中立の内部キー(英数字)★。日英の表示ラベルは
# report/category_labels.json の単一マップ経由でのみ描画する(英語版に日本語を出さない)。
# 内部キーは表示に使わない(表示は必ずマップ変換を通す)。
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
    # Windows本体のサービス/コンポーネント (上記に当たらない汎用EoP/RCEの受け皿)
    ("win_services", re.compile(
        r"windows\s+\w+.*(service|driver|component|subsystem|manager|provider|"
        r"agent|client|host|engine|framework|runtime|store|installer|update|"
        r"telephony|brokering|search|backup|recovery|error\s*reporting|"
        r"print|spooler|task\s*scheduler|event\s*log|registry|shell|"
        r"defender|security|smart\s*card|biometric|hello|cryptographic|"
        r"win32|fax|\bcsc\b|distributed|composite|connected|cloud\s*files)", re.I)),
    ("win_services", re.compile(r"brokering|file\s*system|\bmsmq\b|"
        r"win32|telephony|spooler|task\s*scheduler", re.I)),
    ("win_services", re.compile(r"^windows\s+\w+", re.I)),  # その他のWindows *
    ("microsoft_other", re.compile(r"^microsoft\s+\w+", re.I)),      # その他のMicrosoft *
]

# 分類フォールバックの内部キー (旧 "その他")。表示は category_labels.json 経由。
PRODUCT_CAT_FALLBACK = "other"


def product_cat(title: str) -> str:
    """製品カテゴリの言語中立な内部キーを返す (英数字)。表示名ではない。
    日英の表示は report/category_labels.json のマップで変換する。"""
    for name, pat in PRODUCT_CATS:
        if pat.search(title):
            return name
    return PRODUCT_CAT_FALLBACK


# --- 発見者バケット (with Microsoft の内訳を見るため) ---
MS_INTERNAL_RE = re.compile(r"with\s+microsoft|microsoft\s+(internal|red\s+team|"
                           r"security|offensive)|\bMORSE\b|\bDART\b|\bMSRC\b|\bWARP\b|\bACS\b", re.I)
ANON_RE = re.compile(r"anonymous", re.I)
# 32桁以上の16進文字列 = Microsoftが匿名化したハッシュ識別子
# (例: 0123456789abcdef0123456789abcdef)。人間か自動化かは不明。教訓: 実名と別扱い。
HASH_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)


def is_hash_credit(name: str) -> bool:
    """クレジット名がハッシュ識別子単独か"""
    return bool(HASH_RE.match(name.strip()))


def finder_bucket(credited: bool, credits: list[str]) -> str:
    """発見者を大分類: uncredited / ms_internal / hash_anon / anonymous / external

    判定順:
      1. クレジット無し
      2. 社内 (with Microsoft / MORSE / ACS 等)  ← 実名+所属で判定
      3. ハッシュ識別子のみ (実名研究者と混ぜない)
      4. Anonymous のみ
      5. それ以外 = 外部研究者(実名)
    帰属はしない（AI/ツールの正体は推測しない）。文字列の機械分類のみ。教訓#5。
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
    """KEV/EPSS 照合の対象CVEか。

    条件 (いずれか): 再起動クラスが重い層 (T2/T3) / 深刻度が Critical /
    外部研究者(実名)クレジット付き。Edge 長tailの低深刻度を除外し、API負荷と
    ノイズを削減する。帰属判断ではなく機械的な絞り込み。
    """
    names = credit_names(vuln)
    return (tier_of(vuln) in ("T2", "T3")
            or severity_of(vuln) == "Critical"
            or finder_bucket(bool(names), names) == "external")


def target_cves_from_doc(doc: dict) -> list[dict]:
    """CVRF 文書から対象CVEの軽量な行リストを返す (KEV/EPSS 照合用)。

    各行は {cve, tier, severity, finder, title, category}。帰属・解釈はしない。
    title/category は CVRF(この文書)由来の事実で、KEV/EPSS の値とは別ソース。
    category は表5(製品カテゴリ別)と同一の product_cat() 分類を再利用する。
    enrichment 層がこれを使う (凍結 state に依存しない)。
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
    CVRF文書1件を、監視用の集計サマリに畳む。
    判断・帰属は一切含まない。事実の集計のみ。教訓#5。

    戻り値は state/{month}.json に保存される形。
    """
    vulns = doc.get("Vulnerability") or []
    total = len(vulns)

    tier_count: dict[str, int] = defaultdict(int)
    sev_count: dict[str, int] = defaultdict(int)
    credited = 0

    # クレジット名 -> それを含むCVEの集合 (CVE単位で重複排除。教訓#2)
    credit_to_cves: dict[str, set[str]] = defaultdict(set)

    zero_days: list[dict] = []

    # --- 母集団分離・製品・発見者バケットの集計 (msrc_action 移植) ---
    core_total = 0
    excluded_total = 0
    sev_core: dict[str, int] = defaultdict(int)
    tier_core: dict[str, int] = defaultdict(int)
    product_count: dict[str, int] = defaultdict(int)
    finder_count: dict[str, int] = defaultdict(int)
    kugelblitz = 0
    # Critical を発見者バケット別に集計 (件数のみ。個人実名は保存しない=データ最小化)
    critical_by_finder: dict[str, int] = defaultdict(int)
    kugelblitz_in_critical = 0
    # KEV/EPSS 照合の対象CVE (T2/T3 ∨ Critical ∨ external)。件数削減用。
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
        # 同一CVE内の重複名は set への add で自然に1回になる
        for nm in set(names):
            credit_to_cves[nm].add(cve)

        # 母集団 (core / excluded) と、core 側の深刻度・再起動クラス
        if population_of(title) == "core":
            core_total += 1
            sev_core[sev] += 1
            tier_core[tr] += 1
        else:
            excluded_total += 1

        # 製品カテゴリ (母集団=all)
        product_count[product_cat(title)] += 1
        # 発見者バケット (母集団=all、CVE単位)
        bucket = finder_bucket(bool(names), names)
        finder_count[bucket] += 1
        # Kugelblitz 系クレジットを含む CVE 数 (CVE単位)
        has_kugel = any("kugelblitz" in c.lower() for c in names)
        if has_kugel:
            kugelblitz += 1
        # Critical の発見者内訳 (件数のみ。実名は state に焼き込まない)
        if sev == "Critical":
            critical_by_finder[bucket] += 1
            if has_kugel:
                kugelblitz_in_critical += 1
        # KEV/EPSS 照合の対象CVE (T2/T3 ∨ Critical ∨ external)
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

    # クレジット名ごとのCVE件数 (CVE単位・重複排除済み)。教訓#2
    credit_counts = {nm: len(cves) for nm, cves in credit_to_cves.items()}

    return {
        "month": month,
        "fetched_at": fetched_at,          # 教訓#4: 鮮度の記録
        "cve_total": total,
        "credited": credited,
        "uncredited": total - credited,
        "tier_count": dict(tier_count),
        "severity_count": dict(sev_count),
        # --- 母集団分離 (MS本体相当 vs Edge/Mariner/Cloud 除外) ---
        "core_total": core_total,
        "excluded_total": excluded_total,
        "severity_core": dict(sev_core),
        "tier_core": dict(tier_core),
        # --- 製品カテゴリ別 (母集団=all)。件数降順 ---
        "product_count": dict(sorted(product_count.items(), key=lambda x: -x[1])),
        # --- 発見者バケット (母集団=all)。帰属判断ではなく機械分類 ---
        "finder_bucket": dict(finder_count),
        # 推移で使う社内(with Microsoft系)件数の便利フィールド (finder_bucket と同値)
        "ms_internal": finder_count.get("ms_internal", 0),
        # --- Kugelblitz 系クレジットを含む CVE 数 (推移監視のベースライン) ---
        "kugelblitz": kugelblitz,
        # --- Critical の発見者内訳 (件数のみ。実名なし=データ最小化) ---
        "critical_by_finder": dict(critical_by_finder),
        "kugelblitz_in_critical": kugelblitz_in_critical,
        # --- KEV/EPSS 照合の対象CVE-ID (T2/T3 ∨ Critical ∨ external) ---
        "target_cves": target_cve_ids,
        # 上位のみ保存(全件だと肥大化)。並びは件数降順
        "credit_counts": dict(sorted(credit_counts.items(),
                                     key=lambda x: -x[1])),
        "zero_days": zero_days,
        # メタ: このサマリが機械集計であり解釈を含まないことの明示
        "_note": ("machine-generated factual summary. "
                  "no attribution/interpretation. "
                  "do NOT infer tool/AI identity from credit names "
                  "(see Kugelblitz lesson 2026-07)."),
    }
