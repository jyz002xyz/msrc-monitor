#!/usr/bin/env python3
"""
collect.py — MSRC CVRF を取得し、事実サマリを state/ に保存する (冪等)

判断・帰属は一切しない。生データを取得して畳むだけ。
Pi 上で systemd timer から月次実行される。

冪等性:
    同じ月を再取得しても安全。ただし fetched_at は更新される
    (クレジット追記の反映を取り込むため)。--no-clobber で既存を保護可。

使い方:
    python3 collect.py                # 当月を取得
    python3 collect.py 2026-Jul       # 指定月
    python3 collect.py --backfill 2026-Jan 2026-Jul   # 範囲を一括
    python3 collect.py 2026-Jul --no-clobber          # 既存があればスキップ

環境変数:
    MSRC_MONITOR_HOME  … state/ の親。未設定ならスクリプト位置。
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

import requests

import cvrf_parse as cp

CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{month}"
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def home() -> Path:
    env = os.environ.get("MSRC_MONITOR_HOME")
    return Path(env) if env else Path(__file__).resolve().parent


def state_dir() -> Path:
    d = home() / "state"
    d.mkdir(parents=True, exist_ok=True)
    return d


def current_month_tag() -> str:
    now = dt.datetime.now()
    return f"{now.year}-{MONTHS[now.month - 1]}"


def expand_range(start: str, end: str) -> list[str]:
    """'2026-Jan' '2026-Jul' -> 各月タグのリスト"""
    def parse(tag):
        y, m = tag.split("-")
        return int(y), MONTHS.index(m)
    sy, sm = parse(start)
    ey, em = parse(end)
    out = []
    y, m = sy, sm
    while (y, m) <= (ey, em):
        out.append(f"{y}-{MONTHS[m]}")
        m += 1
        if m == 12:
            m = 0
            y += 1
    return out


def fetch(month: str, timeout: int = 90, retries: int = 3) -> dict:
    """CVRF を JSON で取得。指数バックオフ付きリトライ。"""
    url = CVRF_URL.format(month=month)
    last = None
    for attempt in range(retries):
        try:
            r = requests.get(url, headers={"Accept": "application/json"}, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            last = e
            if attempt < retries - 1:
                wait = 2 ** attempt * 5
                print(f"  [retry {attempt+1}/{retries}] {month}: {e} — {wait}s待機",
                      file=sys.stderr)
                time.sleep(wait)
    raise RuntimeError(f"{month}: 取得失敗 ({retries}回) — {last}")


# 凍結スナップショットと再取得値を比較する軸 (取得ラグに頑健な実数のみ)
REVISION_KEYS = ["cve_total", "core_total", "credited", "kugelblitz", "ms_internal"]


def revisions_dir() -> Path:
    d = state_dir() / ".revisions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def detect_revision(frozen: dict, fresh: dict, detected_at: str) -> dict | None:
    """凍結値と再取得値の差分を返す (差が無ければ None)。frozen は上書きしない。"""
    diff = {}
    for k in REVISION_KEYS:
        fv = frozen.get(k)
        nv = fresh.get(k)
        if fv is not None and nv is not None and fv != nv:
            diff[k] = {"frozen": fv, "revised": nv, "delta": nv - fv}
    # severity(Critical)・重い層(T2+T3) も比較 (レポートの主要軸)
    fc = (frozen.get("severity_count") or {}).get("Critical", 0)
    nc = (fresh.get("severity_count") or {}).get("Critical", 0)
    if fc != nc:
        diff["critical"] = {"frozen": fc, "revised": nc, "delta": nc - fc}
    ft = frozen.get("tier_count") or {}
    nt = fresh.get("tier_count") or {}
    fh = ft.get("T2", 0) + ft.get("T3", 0)
    nh = nt.get("T2", 0) + nt.get("T3", 0)
    if fh != nh:
        diff["heavy"] = {"frozen": fh, "revised": nh, "delta": nh - fh}
    if not diff:
        return None
    return {
        "month": frozen.get("month"),
        "snapshot_date": frozen.get("snapshot_date"),
        "detected_at": detected_at,
        "diff": diff,
        "_note": ("MSRC が凍結後にこの月を事後改訂したことを検知。"
                  "凍結値は保持し、改訂内容はここに記録する (レポート数値は不変)。"),
    }


def collect_month(month: str, no_clobber: bool = False) -> dict | None:
    path = state_dir() / f"{month}.json"
    if no_clobber and path.exists():
        print(f"  skip (既存): {month}")
        return json.loads(path.read_text())

    # 既存が凍結済みなら上書きしない。再取得して改訂を検知・記録するのみ。
    existing = json.loads(path.read_text()) if path.exists() else None
    is_frozen = bool(existing and existing.get("frozen"))

    fetched_at = dt.datetime.now().isoformat(timespec="seconds")
    doc = fetch(month)
    summary = cp.summarize(doc, month, fetched_at)

    if is_frozen:
        rev = detect_revision(existing, summary, fetched_at)
        if rev:
            rp = revisions_dir() / f"{month}.json"
            rp.write_text(json.dumps(rev, ensure_ascii=False, indent=2))
            print(f"  FROZEN {month}: 凍結値を保持。MSRC 改訂を検知 -> {rp.name} "
                  f"({', '.join(rev['diff'].keys())})")
        else:
            print(f"  FROZEN {month}: 凍結値を保持 (改訂なし)")
        return existing

    # 未凍結 (現在月) は通常どおり上書き。frozen:false を明示。
    summary["frozen"] = False
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    tmp.replace(path)

    zd = len(summary["zero_days"])
    print(f"  OK  {month}: CVE {summary['cve_total']} / "
          f"credited {summary['credited']} / zero-days {zd} "
          f"-> {path.name}")
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="MSRC CVRF を取得しサマリ保存 (判断なし)")
    ap.add_argument("months", nargs="*", help="例: 2026-Jul (省略時は当月)")
    ap.add_argument("--backfill", nargs=2, metavar=("START", "END"),
                    help="範囲を一括取得 例: --backfill 2026-Jan 2026-Jul")
    ap.add_argument("--no-clobber", action="store_true",
                    help="既存の月ファイルがあればスキップ")
    args = ap.parse_args()

    if args.backfill:
        targets = expand_range(*args.backfill)
    elif args.months:
        targets = args.months
    else:
        targets = [current_month_tag()]

    print(f"[collect] state: {state_dir()}")
    print(f"[collect] targets: {', '.join(targets)}")

    failed = []
    for m in targets:
        try:
            collect_month(m, no_clobber=args.no_clobber)
        except Exception as e:
            print(f"  FAIL {m}: {e}", file=sys.stderr)
            failed.append(m)
        time.sleep(1)  # API への礼儀

    if failed:
        print(f"[collect] 失敗: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("[collect] 完了")
    return 0


if __name__ == "__main__":
    sys.exit(main())
