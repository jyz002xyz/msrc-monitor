#!/usr/bin/env python3
"""
enrich.py — KEV/EPSS 生成層 (凍結 state とは別のライブ層)

★役割分担 (Phase 2 の核心) ★
    - CISA KEV = 通知トリガー (離散イベント。載る/載らないで揺れない)。
      → 前回実行の kev_listed との差分 (新規収載) を edge-triggered 通知する。
    - FIRST EPSS = レポート内の分析材料 (毎日更新・値が揺れる時系列)。
      → 通知トリガーには絶対に使わない (原則②: 取得ラグで壊れる値を通知に使わない)。
      → レポートに「取得時点 (epss_asof) 付き」で提示する。最新+1世代前のみ保持。

★凍結原則の厳守★
    月次の凍結 state (state/2026-*.json) は一切書き換えない。KEV/EPSS は
    state/enrichment.json (gitignore・ライブ) に持つ。対象CVEは生CVRFから毎回導出し、
    凍結 state に依存しない。

★帰属・因果の禁止★
    KEV/EPSS の数値から発見主体や「AI発見」等を断定しない。数値と時点の事実のみ。

使い方:
    python enrich.py 2026-Jul            # 対象CVEを KEV/EPSS 照合し enrichment.json 更新
    python enrich.py 2026-Jul --fixture  # 生CVRFに fixture を使う (凍結月・オフライン用)

到達不能 (AIサンドボックス等) では取得をスキップし asof=null で残す (落ちない)。
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

import requests

import cvrf_parse as cp

CISA_KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
                "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100  # 1リクエストの CVE 数上限 (負荷・URL長対策)

FIXTURE = Path(__file__).resolve().parent / "tests" / "fixtures" / "2026-Jul-cvrf-reduced.json"


def home() -> Path:
    env = os.environ.get("MSRC_MONITOR_HOME")
    return Path(env) if env else Path(__file__).resolve().parent


def state_dir() -> Path:
    d = home() / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def enrichment_path() -> Path:
    return state_dir() / "enrichment.json"


# --- 取得 (到達不能なら None を返す。落とさない) -----------------------------
def fetch_kev(timeout: int = 30) -> set[str] | None:
    """CISA KEV カタログ全体の CVE-ID 集合。到達不能なら None。"""
    try:
        r = requests.get(CISA_KEV_URL, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        return {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}
    except Exception as e:
        print(f"[enrich] KEV 取得スキップ (到達不能): {e}", file=sys.stderr)
        return None


def fetch_epss(cve_ids: list[str], timeout: int = 30) -> dict | None:
    """対象CVEの EPSS を取得。{cve: {epss, percentile}} と date。到達不能なら None。

    戻り: (scores: dict, date: str) / 失敗時 None
    """
    if not cve_ids:
        return {"scores": {}, "date": None}
    scores: dict[str, dict] = {}
    date = None
    try:
        for i in range(0, len(cve_ids), EPSS_BATCH):
            batch = cve_ids[i:i + EPSS_BATCH]
            r = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=timeout)
            r.raise_for_status()
            data = r.json()
            for row in data.get("data", []):
                cve = row.get("cve")
                if not cve:
                    continue
                scores[cve] = {
                    "epss": float(row.get("epss", 0) or 0),
                    "percentile": float(row.get("percentile", 0) or 0),
                }
                date = row.get("date") or date
        return {"scores": scores, "date": date}
    except Exception as e:
        print(f"[enrich] EPSS 取得スキップ (到達不能): {e}", file=sys.stderr)
        return None


def load_prev() -> dict:
    p = enrichment_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def _now_iso() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def build_enrichment(month: str, targets: list[dict], kev_all: set[str] | None,
                     epss: dict | None, prev: dict, now_iso: str) -> dict:
    """対象CVE・KEV・EPSS から enrichment dict を組み立てる。

    KEV 差分 (kev_new) = 今回 kev_listed - 前回 kev_listed (edge-trigger 用)。
    EPSS は最新 (epss) と 1世代前 (epss_prev) のみ。Δは通知に使わない。
    """
    target_ids = [t["cve"] for t in targets]

    # --- KEV 照合 (対象CVEのうち KEV 収載済み) ---
    if kev_all is None:
        kev_listed = None
        kev_asof = None
    else:
        kev_listed = sorted(c for c in target_ids if c in kev_all)
        kev_asof = now_iso
    prev_kev = set(prev.get("kev_listed") or [])
    kev_new = sorted(set(kev_listed or []) - prev_kev) if kev_listed is not None else []

    # --- EPSS (最新 + 1世代前) ---
    if epss is None:
        epss_scores, epss_asof = None, None
    else:
        epss_scores, epss_asof = epss["scores"], epss["date"]
    # 1世代前 = 前回の epss (それ以前は残さない=単独指標化を防ぐ)
    epss_prev = prev.get("epss")
    epss_prev_asof = prev.get("epss_asof")

    return {
        "month": month,
        "generated_at": now_iso,
        "target_count": len(targets),
        "target_cves": targets,
        # --- KEV: 通知トリガー (離散) ---
        "kev_asof": kev_asof,
        "kev_listed": kev_listed,
        "kev_new": kev_new,
        # --- EPSS: レポート参考 (時点付き・通知に使わない) ---
        "epss_asof": epss_asof,
        "epss": epss_scores,
        "epss_prev": epss_prev,
        "epss_prev_asof": epss_prev_asof,
        "_note": ("KEV=通知トリガー(離散イベント)。EPSS=レポート参考(取得時点付き・"
                  "日々変動・通知やトレンド線に単独使用しない)。凍結 state は不変。"
                  "KEV/EPSS の数値から発見主体・因果を断定しない。"),
    }


def get_raw_doc(month: str, use_fixture: bool, fetch_fn=None) -> dict | None:
    """対象CVE導出用の生CVRF。fixture 指定時は fixture、それ以外は取得。"""
    if use_fixture:
        return json.loads(FIXTURE.read_text())
    try:
        import collect
        return (fetch_fn or collect.fetch)(month)
    except Exception as e:
        print(f"[enrich] CVRF 取得スキップ (到達不能): {e}", file=sys.stderr)
        return None


def enrich(month: str, use_fixture: bool = False, raw_doc: dict | None = None,
           kev_all=None, epss=None, fetch_kev_fn=fetch_kev,
           fetch_epss_fn=fetch_epss) -> dict | None:
    """月の対象CVEを KEV/EPSS 照合し enrichment.json を更新する。

    テスト用に raw_doc / kev_all / epss を注入可能。未注入なら実取得 (到達不能でスキップ)。
    """
    doc = raw_doc if raw_doc is not None else get_raw_doc(month, use_fixture)
    if doc is None:
        print("[enrich] 生CVRF が得られないため中止 (enrichment 未更新)")
        return None
    targets = cp.target_cves_from_doc(doc)
    target_ids = [t["cve"] for t in targets]

    if kev_all is None:
        kev_all = fetch_kev_fn()
    if epss is None:
        epss = fetch_epss_fn(target_ids)

    prev = load_prev()
    now_iso = _now_iso()
    enr = build_enrichment(month, targets, kev_all, epss, prev, now_iso)

    # 原子的書き込み
    p = enrichment_path()
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(enr, ensure_ascii=False, indent=2))
    tmp.replace(p)

    kev_n = len(enr["kev_new"])
    kl = "n/a" if enr["kev_listed"] is None else str(len(enr["kev_listed"]))
    ep = "n/a" if enr["epss"] is None else str(len(enr["epss"]))
    print(f"[enrich] {month}: target {enr['target_count']} / KEV 収載 {kl} "
          f"(新規 {kev_n}) / EPSS {ep} (asof {enr['epss_asof']})")
    return enr


def main() -> int:
    ap = argparse.ArgumentParser(description="KEV/EPSS enrichment (KEV=通知・EPSS=参考)")
    ap.add_argument("month", help="対象月 例: 2026-Jul")
    ap.add_argument("--fixture", action="store_true",
                    help="生CVRF に fixture を使う (凍結月・オフライン用)")
    args = ap.parse_args()
    enr = enrich(args.month, use_fixture=args.fixture)
    return 0 if enr is not None else 1


if __name__ == "__main__":
    sys.exit(main())
