# Archive metadata corrections / アーカイブ・メタデータ訂正記録

## 2026-07-23 — slot `2026-07`: subject-month and counts corrected `2026-06` → `2026-07`

**What was wrong / 誤り:** The archive navigation metadata for the single published
report described it as a **June** report — `manifest.json` had `subject: 2026-06`
and `counts: {cvrf: 1281, core: 724}`, and the index displayed
"June 2026 / 2026年6月" and "1,281 CVRF / 724 本体相当・core". This was **incorrect**.

公開済みレポート1件のアーカイブ・ナビゲーション用メタデータが、これを**6月**の
レポートと記述していた（`manifest.json` の `subject: 2026-06`、
`counts: {cvrf: 1281, core: 724}`、index 表示 "June 2026 / 2026年6月"、
"1,281 CVRF / 724 本体相当・core"）。これは**誤り**だった。

**The report is about July 2026 / 実際は7月レポート:** The report's own body is a
July 2026 Patch Tuesday analysis — subtitle "A situational analysis as of July 2026",
Table 1 totals of 1,150 (full CVRF) / 665 (core Microsoft), and the exploited
zero-days it discusses (AD FS / SharePoint / BitLocker) are July's. June appears only
as a comparison ("once the population is normalized, June was the peak at 724").

レポート本文は7月2026 Patch Tuesday の分析（副題 "as of July 2026"、Table 1 の
Total 1,150 CVRF / 665 本体相当、扱うゼロデイは7月分の AD FS / SharePoint /
BitLocker）。6月は「母集団を揃えるとピークは6月(724)」という比較としてのみ登場する。

**How the error arose / 経緯:** The June comparison figures in the report's trend
table (1,281 / 724) were mistaken for the subject-month values and propagated into
the index count display and the `subject` label. The **folder key `2026-07` was
correct all along** and is unchanged.

トレンド表内の6月比較行(1,281 / 724)を対象月の値と読み違え、それが index の件数
表示と `subject` ラベルに伝播した。**フォルダキー `2026-07` は元々正しく、無変更。**

**Correction / 訂正:**
- `manifest.json`: `subject` → `2026-07`; `counts` → `{cvrf: 1150, core: 665}`.
- `index.html`: month display → "July 2026 / 2026年7月"; count → "1,150 CVRF /
  665 本体相当・core" (two-value form retained; snapshot date unchanged at 2026-07-15).
- `2026-07/meta.json`: records `subject: 2026-07`.
- **The frozen snapshot `2026-07/{ja,en}.html` and its assets were NOT touched**
  (moved nor regenerated); verified byte-identical (sha256 unchanged).

**Number provenance / 数値の出典:** 1,150 (full CVRF) and 665 (core) were re-derived
from the frozen snapshot `docs/archive/2026-07/en.html` Table 1 and independently
corroborated by the private `state/2026-Jul.json` (`cve_total` / `core_total`); both
sources agree.
