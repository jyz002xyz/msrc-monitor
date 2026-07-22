# Archive re-key record / アーカイブ再キー記録

## 2026-07-23 — `2026-07` → `2026-06`

**What / 何を:** The single archived snapshot was moved from slot key `2026-07`
to `2026-06`. Only the folder key changed; the snapshot content
(`{ja,en}.html` and bundled assets) was moved verbatim, byte-for-byte identical
(sha256 unchanged). It was not regenerated.

このアーカイブの唯一のスナップショットを、スロットキー `2026-07` から `2026-06`
へ移動した。変更したのはフォルダキーのみで、スナップショットの中身
（`{ja,en}.html` と同梱アセット）はそのまま移動しており、バイト単位で同一
（sha256 一致）。再生成はしていない。

**Why / 理由:** Unify the slot key on the report's subject-month. This snapshot's
report is about **June 2026** (`subject: 2026-06`; 1,281 CVRF, snapshot 2026-07-15),
so its slot is now `2026-06`. The old key `2026-07` is released for the upcoming
July report, whose subject-month is `2026-07`. Keeping June under `2026-07` would
have collided with Phase B's subject-month keying and silently prevented the July
report from being archived.

スロットキーをレポートの subject-month（対象月）に統一するため。このスナップショット
のレポートは **2026年6月** を対象としており（`subject: 2026-06`／1,281 CVRF、
スナップショット 2026-07-15）、スロットは `2026-06` とした。旧キー `2026-07` は、
subject-month が `2026-07` である次回7月レポート用に解放する。6月を `2026-07` の
まま残すと Phase B の subject-month キーイングと衝突し、7月レポートが静かに
アーカイブされない事態を招いていた。

**No redirect stub / リダイレクトは置かない:** The old path `archive/2026-07/` is
intentionally left as a temporary 404. A redirect stub there would be overwritten
when Phase B later freezes the July report into that same slot, silently serving
July content from a June URL — worse than a 404. Once Phase B runs, `2026-07`
becomes the correct slot for the July report.

旧パス `archive/2026-07/` は意図的に一時的な 404 とする。ここにリダイレクトを
置くと、後で Phase B が7月レポートを同じスロットに freeze する際に上書きされ、
6月の URL から7月の内容が静かに返ることになる（404 より悪い）。Phase B 稼働後、
`2026-07` は7月レポートの正しいスロットになる。
