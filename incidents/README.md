# incidents/ — disclosed cybersecurity incidents

Publishes `docs/incidents/`. Facts and links only: no interpretation, and no retelling of
press coverage.

## Three layers, never added together

| Layer | Content | Cadence | Who decides it is "big" |
|---|---|---|---|
| Automatic — SEC | SEC Form 8-K **Item 1.05** only | daily | the **company itself** — 1.05 is filed when the registrant has determined the incident is material |
| Automatic — state AG | breach notifications filed with the **California** and **Washington** Attorneys General | daily | **state law** — the filing threshold is statutory, not editorial |
| Curated | incidents an editor chose to record, plus ones a rule recorded under stated conditions | when there is something to record | the editor, or a rule the editor set |

No total and no per-region count is published. The layers are measured in different ways, and
so are the jurisdictions inside each of them, so any sum would compare things that are not
comparable. Where an incident appears in both the SEC layer and the curated layer the rows are
cross-linked, not merged, so a reader cannot count it twice.

The two state registries are **not** cross-linked — to each other or to the SEC layer. An
organisation that notified both states appears twice, and may appear a third time under
Item 1.05. Collapsing those would mean asserting they describe the same event, which is the
judgement this section exists to avoid making.

## Why the state registries, and why they came before a press-derived layer

A press-derived layer was surveyed first, in two read-only passes (2026-08-10), and measured
worse on every axis that matters here:

- The organisation could be extracted from a headline mechanically ~24% of the time, **and the
  failures were silent** — `Hackers breach TrueConf` yields "Hackers". A wrong primary key that
  looks plausible is worse than no record at all.
- A figure for the scale of the breach was present in 13% of headlines.
- "Several outlets covered it" does not measure size. In one sampled week the most-covered
  story (5 outlets) was a guilty plea, while the largest actual breach in the window
  (3.8M people) was covered by 2 and most named-organisation incidents by 1.
- Every press source surveyed is all-rights-reserved. Three publish terms naming the exact
  activity: BleepingComputer prohibits content being "stored in a computer" outside personal
  use and prohibits creating "an index" of it; Infosecurity Magazine prohibits "systematic
  retrieval ... to create or compile, directly or indirectly, a collection, compilation,
  database or directory", and makes honouring robots.txt a term of use; The Register grants use
  "solely for your personal, non-commercial use". None of those clauses is conditioned on
  publishing, so an internal-only index is not obviously outside them.
- Feed retention is 2–4 days with no backfill, so an outage of more than two days loses records
  permanently.

The registries invert all of it: the organisation, the dates and — in Washington — the number
affected and the categories of data are already separate fields; California's terms put its
site content in the public domain; and a missed day costs nothing, because California's export
is the whole list every time and one Washington page reaches about three months back.

## What this cannot see

Stated on the published page as the section's definition, not as a footnote:

- **Japan, Australia, Europe: nothing arrives automatically.** Not because fewer incidents
  happen there — no such jurisdiction publishes a structured per-incident feed. Australia's
  OAIC publishes statistics only; a zero here would mean "cannot be retrieved", never "did not
  happen". **The state registries do not change this**: they widen US coverage only.
- **The registries are two states, not a country.** A filing appears only where residents of
  that state were affected. The other forty-eight states are absent.
- **Both registries publish late.** Measured 2026-08-10: California's newest entry was 3 days
  old, Washington's 13. A recent incident being absent means it has not been published yet.
- **Healthcare has no federal source here.** The HHS OCR portal is still deferred (below), so
  healthcare appears only via California or Washington.
- **The curated layer is not comprehensive.** Nothing follows from an absence.

## Rows a rule wrote, and rows a person wrote

`recorded_by` distinguishes them. Absent means `editor`; `detector` means the private detection
layer wrote it unattended, having met every one of its published conditions.

They are different claims and the page says so. An automatic row asserts **only** that this
organisation published this announcement, on this date, of this coarse type. It does not read
the announcement: `records.py` REFUSES a `detector` record that carries `facts`, because a
machine filling that field would be paraphrasing the organisation — the same retelling this
layer refuses for press coverage, pointed at the organisation's own words instead. The prose in
an automatic row is therefore absent, not thin; a person adds it later if it is worth adding.

The six records written by hand before this field existed are not rewritten to carry it. The
record is append-only and their meaning did not change.

## The curated layer is not translated, and that is the rule not a gap

On the English page the curated rows carry Japanese organisation names, Japanese source titles
and Japanese `facts`. Only the column headings are English. That is deliberate, decided
2026-08-12 when the first six records were published.

`facts` holds **what the organisation itself stated**. Translating it would make the entry a
paraphrase of the organisation's words rather than the words — and this layer's whole discipline
is that it does not retell, it records and links. A translated figure with a translated caveat
is a retelling, however careful; the reader would be reading us, not them.

The cost is real and is accepted: an English-only reader cannot read the substance of a
Japanese entry. What they can still do is see that the incident is recorded, see its type and
date, and follow the link to the organisation's own announcement — which is the same thing the
Japanese reader does, and the only artifact either of them should be trusting.

The alternative, if this is ever revisited, is a separate translated field alongside the
original rather than in place of it — never an edit of `facts`.

## Why only Item 1.05

An 8-K filed under Item 8.01 (Other Events) is one the company decided was *not* material.
Collecting those would move the materiality judgement onto us, which is the one thing this
design avoids. 8.01 is therefore not collected, and that is a deliberate omission rather than
an oversight.

## Data model

### SEC layer (`data/disclosures.json`)

- **Incident key = `CIK` + `reportDate`.** `reportDate` is the date of the earliest reported
  event and stays constant across a filing's whole 8-K/A chain (verified on River Financial:
  five filings from 2026-06-25 to 2026-07-30, all `reportDate` 2026-06-19).
- **Statement = `adsh`** (accession number). The original 8-K and each amendment are separate
  statements. Nothing is rewritten; a correction is appended.
- EDGAR full-text search indexes each *document* inside a filing, so a filing can be returned
  several times. Dedupe is on `adsh`.

### State AG layer (`data/state_ag.json`)

One filing to one state is one row.

- **Washington key = `WA:<document id>`**, taken from the notification PDF the organisation
  itself filed (e.g. `WA:BreachA42014`) — the source's own identifier.
- **California key is composed**: `CA:<reported date>:<slug>:<breach dates>`, because
  California publishes no per-filing id and no link to the notice. Measured over the full
  export (5,242 rows, 2026-08-10): 10 keys collided, covering 12 rows (0.23%), and every
  colliding group was **identical in all three published fields** — the export's own duplicate
  rows, so collapsing them discards nothing the source distinguishes. The remaining limit is
  hypothetical rather than observed: a genuinely separate second filing sharing all three
  values would be indistinguishable.
- **A blank is not a zero.** California publishes no affected count and no notice link; those
  fields are stored as `null` and rendered blank, and the page says why.
- **Filings by a filer whose name might be a natural person are not in this file at all** until
  a human has decided. See "Filer names that might be people" below.
- **Washington's page boundaries are not exactly disjoint.** Measured 2026-08-10: three pages
  returned 150 rows but 149 distinct documents — `BreachA36331` was the last row of page 1 and
  the first row of page 2, because the sort key is the reported date alone and rows sharing a
  date can straddle a boundary. The duplicate is harmless (the store dedupes on the document
  id), but the same instability could skip a row instead of repeating one, so
  `wa_duplicate_keys` is reported in the run stats. A backfill that reports a non-zero value
  should simply be re-run: the merge is idempotent and append-only, so a second pass only adds
  what the first missed. The daily path reads page 0 only — no boundary above it, spanning
  about three months, re-read in full every day — and is not exposed to this.

Both stores carry **no run timestamp**: a day with nothing new must produce a byte-identical
file, or no-op detection cannot work.

## Running it

```
SEC_USER_AGENT="you <you@example.com>" python -m incidents.run      # SEC 2 days, registries 90
python -m incidents.run --since 2026-05-09 --until 2026-08-07       # SEC backfill
python -m incidents.run --registry-since 2024-01-01 --wa-pages 40   # registry backfill
python -m incidents.run --skip-sec                                  # registries only
python -m incidents.run --render-only                               # no network
python incidents/test_incidents.py                                  # offline tests
```

`SEC_USER_AGENT` is required for the SEC layer. SEC returns **HTTP 403** without a declared
User-Agent carrying contact information, and its stated limit is 10 requests/second. It is read
from the environment so that no contact address is committed to this public repository.

The state registries need **no secret**. Neither requires a declared User-Agent and neither
needs a browser; the collector sends a descriptive one carrying this repository's URL and no
contact address, so it can live in the source. Requests are throttled to one per second — these
are small state web servers, not EDGAR.

A run halts on either source failing, and writes nothing. That is affordable precisely because
all three sources are re-readable: EDGAR takes `--since`, California's export is the whole list,
and Washington pages back about three months. It is a property of these sources, not a general
property of daily collection.

The SEC record was seeded on 2026-08-08 with the 2026-05-09..2026-08-07 window (nine incidents,
fourteen filings). The registry record is seeded by its first run, 90 days back.

Start dates are not prose in a template: `coverage.since` is stored in each record, widened by
any earlier backfill and never narrowed by a later daily window, and the page renders it next
to the table it qualifies.

## Source and terms

Checked 2026-08-10, from the sources' own pages rather than assumed.

- **SEC.** sec.gov states its information is public and may be copied or further distributed,
  asking for appropriate citation to the SEC as the source. SEC's seal and logos are not used;
  "SEC" and "EDGAR" appear only as references in text.
- **California Attorney General.** `oag.ca.gov/conditions`, under OWNERSHIP: "Considered in the
  public domain. It may be distributed or copied as permitted by law." The list is taken from
  the office's **own CSV export** (`/privacy/databreach/list-export`) rather than scraped from
  the paginated HTML — it is the publisher's own artifact, and it is one request.
- **Washington State Attorney General.** No conditions-of-use or copyright page was located.
  The office's privacy notice frames information on the site as "a public record that may be
  subject to inspection and copying by members of the public" under the Public Disclosure Law
  (RCW 42.17). Recorded as what was found — **not** as an established licence, and not
  described on the page as though it were the same footing as California's.

The section is **not affiliated with, endorsed by, or approved by** the SEC or either
Attorney General's office, and says so on the page.

## Corrections to earlier entries in this file

- **"State AG filings are JS-rendered and need browser automation" was wrong.** That was
  recorded here after the 2026-08-07 survey, alongside HHS OCR, and it held for HHS but not for
  the states. California serves a plain CSV export; Washington serves a plain server-rendered
  HTML table with `?page=N`. Both parse with the standard library. The claim was not re-checked
  before it was written down, and it cost the section three months of coverage it could have
  had. HHS OCR **was** verified in 2026-08-10 and remains JS-rendered (see below).

## Deferred, and recorded as deferred

- **HHS OCR breach portal.** Re-verified 2026-08-10: `breach_report.jsf` returns a ~13 KB JSF
  shell with a `javax.faces.ViewState`, no data table server-rendered, every portal link
  `href="#"`, and no CSV/export/JSON link anywhere in the served HTML. Collecting it needs
  browser automation, which would end the `No pip install` property the daily workflow relies
  on and add ViewState/selector drift that breaks quietly. Deferred, not attempted and
  abandoned.
- **Maine AG.** The list URL used historically
  (`apps.web.maine.gov/online/aeviewer/ME/40/list.shtml`) returns 404, and the current Data
  Security Breaches pages carry no table and no link to a public searchable list — only a
  reporting form for authorised agents. Whether the public list was withdrawn or relocated was
  **not established**; it is recorded as not found, not as removed.
- **Other states.** Forty-six more states have notification statutes; only these two were
  surveyed. Adding a third is an extension of the same shape, not a new decision.
- **ICO (UK).** Reachable via `sitemap.xml`, but its enforcement actions include **named
  natural persons** (Proceeds of Crime Act cases, with the name in the URL slug). Since the
  entity name is the primary key, excluding individuals means excluding whole records, which
  needs a rule decided before any collection starts.
- **The `reportDate` split is inferred.** No company filed two separate 1.05 incidents inside
  the observed window, so separating two concurrent incidents at one company is untested
  against a real case.
- **OAIC / PPC licensing** was not established. Not needed while neither is used.
- **Japan has no per-incident public registry.** Checked 2026-08-11 for a medical case: the
  Personal Information Protection Commission publishes enforcement actions, sectoral alerts and
  annual reports, but not the breach reports it receives — those became mandatory in April 2022
  and are not published per incident. The regional health bureaus do not publish them either.
  So for Japanese organisations the organisation's own site is the ONLY primary-source route,
  which is why the curated layer is hand-written there and cannot be mechanised the way the
  US state registries can.

## Open: what a breach at a supplier is one record OF

Recorded rather than settled, on the case that raised it (2026-08-11).

A logistics provider was breached over 2026-07-29..08-01. The organisations that notified their
own customers were its CLIENTS — a games platform, two retailers, a football club — each of
which learned of it days later and sent its own notice. One intrusion, one set of compromised
systems, several notifying organisations.

Both readings are defensible and they give different tables:

- **Record the breached party.** The systems, the data and the retention were the supplier's,
  and the event is one event. Recording each client separately makes one intrusion appear as
  four incidents — the same multiplication the state layer already has across jurisdictions,
  arriving here along the supplier axis instead.
- **Record the notifying party.** That is who discharged the duty to tell people, and who the
  affected reader recognises. It is also the only party many readers can name.

**The schema cannot express the relation either way.** `records.py` keys a record on
`organization` and has a `supply_chain` type, but nowhere to say *whose* supply chain, or that
two records describe one intrusion. The only cross-reference that exists is `sec`, which points
at the SEC layer and nothing else.

A second obstacle is separate and may bite first: **neither party had published anything.** The
supplier's newsroom returned HTTP 403 and its confirmation reached customers privately; the
client's notice was an email. `records.py` requires every statement to carry a checkable `http`
URL, so with no public document there is nothing to record whichever party is chosen. That case
is therefore held until a public document exists, and the question above stays open.

## Filer names that might be people

The same question ICO was deferred over, reaching this layer from a different direction.
California's "Organization Name" column is not always an organisation: sole practitioners file
under their own name (`Amin Dean, CPA`, `Andrea Yaley, DDS`) and a bare personal name turns up
occasionally (`Robert Arshagouni`). `records.py` already answers this for the curated layer —
"a daily-accumulating per-person record is a different artifact" — and an unfiltered registry
table is exactly that artifact.

**A machine does not decide it.** Measured over the full California export (5,242 rows,
2026-08-10) a name-shaped heuristic flags 3.5% of rows, and most of those are companies:
`Abbott Nutrition`, `Brooks Brothers`, `Texas Capital`, `Carnival Corporation`. A filter acting
on its own verdict would drop real organisations from a public-record table. So `filers.py`
only *asks*; it is tuned for recall, because a company wrongly flagged costs one human "yes"
for all time while an individual wrongly missed is published.

**What withholding means here.** A flagged name is kept out of the published page **and out of
`data/state_ag.json`**. This repository is public, so a name in the record is published as
surely as a name in the HTML; filtering at render time would filter nothing. For the same
reason `data/filer_decisions.json` records decided organisations **by name** (they are
companies, and their names appear on the page anyway) and decided individuals **by hash only**.
That is not secrecy — the state publishes the name and anyone can hash a guess. It is so that
recording the decision "this is a person" does not itself create the per-person record the
decision exists to prevent.

The page states how many names are being held, so the omission is visible rather than silent.

Two files, and they are different kinds of thing:

| File | Kind | Shrinks? |
|---|---|---|
| `data/filer_decisions.json` | human-edited decisions, permanent | no |
| `data/filer_pending.json` | machine-maintained work queue, hashes and dates only, no names | **yes**, when a decision lands |

The queue is deliberately outside `state_ag.json` so the append-only guarantee on the record
stays absolute. A queue that could not shrink would not be a queue.

On the first run (90-day window, 2026-08-10) this held back two names.
