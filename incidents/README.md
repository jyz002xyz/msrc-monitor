# incidents/ — disclosed cybersecurity incidents

Publishes `docs/incidents/`. Facts and links only: no interpretation, and no retelling of
press coverage.

## Two layers, never added together

| Layer | Content | Cadence | Who decides it is "big" |
|---|---|---|---|
| Automatic | SEC Form 8-K **Item 1.05** only | daily | the **company itself** — 1.05 is filed when the registrant has determined the incident is material |
| Curated | incidents an editor chose to record | when there is something to record | the editor |

No total and no per-region count is published. The two layers are measured in different ways,
and so are the jurisdictions inside the automatic layer, so any sum would compare things that
are not comparable. Where an incident appears in both layers the rows are cross-linked, not
merged, so a reader cannot count it twice.

## What this cannot see

Stated on the published page as the section's definition, not as a footnote:

- **Japan, Australia, Europe: nothing arrives automatically.** Not because fewer incidents
  happen there — no such jurisdiction publishes a structured per-incident feed. Australia's
  OAIC publishes statistics only; a zero here would mean "cannot be retrieved", never "did not
  happen".
- **Inside the US, only SEC registrants.** Item 1.05 binds listed companies. Private companies,
  government, non-profits and most healthcare providers never appear. Healthcare is missing
  wholesale because the HHS OCR breach portal was **deferred** (see below).
- **The curated layer is not comprehensive.** Nothing follows from an absence.

## Why only Item 1.05

An 8-K filed under Item 8.01 (Other Events) is one the company decided was *not* material.
Collecting those would move the materiality judgement onto us, which is the one thing this
design avoids. 8.01 is therefore not collected, and that is a deliberate omission rather than
an oversight.

## Data model

- **Incident key = `CIK` + `reportDate`.** `reportDate` is the date of the earliest reported
  event and stays constant across a filing's whole 8-K/A chain (verified on River Financial:
  five filings from 2026-06-25 to 2026-07-30, all `reportDate` 2026-06-19).
- **Statement = `adsh`** (accession number). The original 8-K and each amendment are separate
  statements. Nothing is rewritten; a correction is appended.
- EDGAR full-text search indexes each *document* inside a filing, so a filing can be returned
  several times. Dedupe is on `adsh`.

The store carries **no run timestamp**: a day with nothing new must produce a byte-identical
file, or no-op detection cannot work.

## Running it

```
SEC_USER_AGENT="you <you@example.com>" python -m incidents.run           # last 2 days
SEC_USER_AGENT="..."                   python -m incidents.run --since 2026-05-09 --until 2026-08-07
python -m incidents.run --render-only                                    # no network
python incidents/test_incidents.py                                       # offline tests
```

`SEC_USER_AGENT` is required. SEC returns **HTTP 403** without a declared User-Agent carrying
contact information, and its stated limit is 10 requests/second. It is read from the
environment so that no contact address is committed to this public repository.

The record was seeded on 2026-08-08 with the 2026-05-09..2026-08-07 window (nine incidents,
fourteen filings) so the section is not empty at launch.

## Source and terms

sec.gov states its information is public and may be copied or further distributed, asking for
appropriate citation to the SEC as the source. SEC's seal and logos are not used; "SEC" and
"EDGAR" appear only as references in text. The section is **not affiliated with, endorsed by,
or approved by the SEC**, and says so on the page.

## Deferred, and recorded as deferred

- **HHS OCR breach portal and state AG filings.** Both are JS-rendered and need browser
  automation; neither was verified in the 2026-08-07 survey. Deferred, not attempted and
  abandoned. Adding them would roughly change what the section covers, so it would be a
  decision, not an extension.
- **ICO (UK).** Reachable via `sitemap.xml`, but its enforcement actions include **named
  natural persons** (Proceeds of Crime Act cases, with the name in the URL slug). Since the
  entity name is the primary key, excluding individuals means excluding whole records, which
  needs a rule decided before any collection starts.
- **The `reportDate` split is inferred.** No company filed two separate 1.05 incidents inside
  the observed window, so separating two concurrent incidents at one company is untested
  against a real case.
- **OAIC / PPC licensing** was not established. Not needed while neither is used.
