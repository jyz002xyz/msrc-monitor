#!/usr/bin/env python3
"""
notify.py — flag が立った時だけ Pushover に通知する (edge-triggered)

diff.py の結果に any_flag があるときだけ鳴らす。状態が変わった時だけ通知する
bot 群と同じ方式。月次実行なので基本は月1だが、再実行時の重複通知を防ぐため
前回通知した flag セットを記録し、同じなら再通知しない。

★このモジュールがやらないこと (設計原則) ★
    - 帰属・解釈を書かない。「変化があった」という事実と件数だけ。
    - priority は通常(0)。緊急扱いにしない (監視であって障害通知ではない)。
    - 秘匿値 (Pushover token 等) をコード・ログ・git に一切出さない。

認証情報:
    環境変数 PUSHOVER_TOKEN / PUSHOVER_USER から読む。
    どちらか未設定なら通知せず警告して正常終了 (クラッシュさせない)。
    この monitor 内で完結させる (クロスリポジトリ依存を作らない)。

使い方:
    python notify.py 2026-Jul          # flag があれば通知
    python notify.py 2026-Jul --force  # flag 無しでも通知 (テスト用)
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
    """flag が立った項目だけを、事実+件数の1行にする (帰属・解釈なし)。"""
    lines: list[str] = []
    if not rep.get("prev_available"):
        return lines
    c = rep["changes"]

    ct = c["cve_total"]
    if ct["flag"]:
        pct = "n/a" if ct["pct"] is None else f"{ct['pct']:+.0%}"
        lines.append(f"総CVE: {ct['prev']}→{ct['now']} ({pct}, 閾値超過)")

    hv = c["heavy"]
    if hv["flag"]:
        ratio = "n/a" if hv["ratio"] is None else f"{hv['ratio']:.2f}倍"
        lines.append(f"重い層 T2+T3: {hv['prev']}→{hv['now']} ({ratio}, 閾値超過)")

    zd = c["zero_days_uncredited"]
    if zd["flag"]:
        lines.append(f"ゼロデイにクレジット無し: {zd['count']}件")

    for item in rep.get("new_credits") or []:
        if item["flag"]:
            lines.append(f'新規クレジット "{item["name"]}": {item["count"]}件')

    return lines


def _last_notified_path(month: str) -> Path:
    return diff.state_dir() / f".last_notified_{month}.json"


def _already_notified(month: str, lines: list[str]) -> bool:
    """前回と同じ flag セットなら True (再通知しない)。"""
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
    """Pushover へ POST。成功で True。秘匿値はログに出さない。"""
    resp = requests.post(PUSHOVER_URL, data={
        "token": token,
        "user": user,
        "title": title,
        "message": message,
        "priority": 0,     # 通常。緊急扱いにしない
    }, timeout=20)
    resp.raise_for_status()
    return True


# ===========================================================================
# KEV 新規収載の通知 (Phase 2)。edge-triggered。
#   ★KEV のみが通知トリガー。EPSS は通知に一切使わない (原則②)。★
#   ★KEV/EPSS の数値から発見主体・因果を断定しない。事実 (CVE-ID) のみ (原則①④)。★
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
    """enrichment の KEV 新規収載を通知 (edge-triggered)。EPSS は使わない。

    通知済み CVE を .last_notified_kev.json に記録し、同じ収載を再通知しない
    (enrich の実行順に依存せず notify 側で重複排除)。
    """
    kev_listed = enrichment.get("kev_listed")
    if kev_listed is None:
        print("[notify] KEV 未取得 (到達不能)。通知しない。")
        return 0

    already = _load_kev_notified()
    new = sorted(set(kev_listed) - already)
    if force and not new:
        new = list(kev_listed[:1])  # テスト用
    if not new:
        print("[notify] KEV 新規収載なし。通知しない。")
        return 0

    month = enrichment.get("month", "")
    title = f"MSRC {month}: KEV 新規収載 {len(new)}件"
    # 事実 (CVE-ID) のみ。EPSS 値・帰属・解釈は入れない。
    message = "\n".join(f"KEV に収載: {cve}" for cve in new)

    token = os.environ.get("PUSHOVER_TOKEN")
    user = os.environ.get("PUSHOVER_USER")
    if not token or not user:
        print("[notify] 警告: PUSHOVER_TOKEN/PUSHOVER_USER 未設定。通知をスキップ。",
              file=sys.stderr)
        return 0
    try:
        send_pushover(token, user, title, message)
    except Exception as e:
        print(f"[notify] 警告: KEV 通知の送信失敗: {e}", file=sys.stderr)
        return 0

    _save_kev_notified(already | set(new))
    print(f"[notify] {month}: KEV 新規収載 {len(new)}件を通知しました")
    return 0


def notify(month: str, force: bool = False, prev_tag: str | None = None) -> int:
    """
    月タグの diff を評価し、必要なら通知する。
    戻り値は exit code (常に 0 系で正常終了。クラッシュさせない)。
    """
    rep = diff.build_report(month, prev_tag)
    lines = _flag_lines(rep)

    should_notify = bool(rep.get("any_flag")) or force
    if not should_notify:
        print(f"[notify] {month}: flag 無し。通知しない。")
        return 0

    if force and not lines:
        lines = ["(--force: flag 無しだがテスト通知)"]

    # edge-triggered: 同じ flag セットの再通知を防ぐ (--force は常に送る)
    if not force and _already_notified(month, lines):
        print(f"[notify] {month}: 前回と同じ内容。再通知しない。")
        return 0

    token = os.environ.get("PUSHOVER_TOKEN")
    user = os.environ.get("PUSHOVER_USER")
    if not token or not user:
        # 秘匿値未設定: クラッシュさせず警告して正常終了
        print("[notify] 警告: PUSHOVER_TOKEN/PUSHOVER_USER 未設定。通知をスキップ。",
              file=sys.stderr)
        return 0

    title = f"MSRC {month}: 要確認の変化 {len(lines)}件"
    message = "\n".join(lines)

    try:
        send_pushover(token, user, title, message)
    except Exception as e:
        # 通知失敗もクラッシュさせない (収集や下書きは既に済んでいる)
        # e には秘匿値は含まれない (requests の例外は URL/status のみ)
        print(f"[notify] 警告: Pushover 送信失敗: {e}", file=sys.stderr)
        return 0

    _record_notified(month, lines, rep.get("fetched_at"))
    print(f"[notify] {month}: 通知しました ({len(lines)}件)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="flag が立った時だけ Pushover 通知 (edge-triggered)")
    ap.add_argument("month", help="当月タグ 例: 2026-Jul")
    ap.add_argument("--prev", help="比較対象の月タグ (省略時は直前月)")
    ap.add_argument("--force", action="store_true",
                    help="flag 無しでも通知 (テスト用)")
    args = ap.parse_args()

    try:
        return notify(args.month, force=args.force, prev_tag=args.prev)
    except FileNotFoundError as e:
        print(f"[notify] エラー: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
