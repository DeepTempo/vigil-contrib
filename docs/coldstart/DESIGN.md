# Day-one cold start

Goal: a customer who connects Vigil on day one gets useful decisions that hour,
without waiting weeks to establish baselines. Vigil computes the baseline from
history the customer already has.

## What offsets the wait

| Tool | Needs | AI | State |
|---|---|---|---|
| Pull alert history from the connected source | Credentials | None | `core/coldstart/collect.py` |
| Alert-kind and entity baselines | Alert history | None, counts | `core/coldstart/baseline.py` |
| Closed-ticket precedent with label filtering | Ticket export | None, counts | `core/coldstart/tickets.py` |
| Miss-rate bound per alert kind | Labels | None, statistics | `baseline.miss_bound` |
| Judgment with the baseline as evidence | Assigned model | LLM | `core/coldstart/judge.py` |
| Flow scoring that needs no warm-up | Flows and LogLM | LogLM, optional | Flagged rows through upload |
| A person's review of one alert kind | A person | None | Not benign escalates the kind at once; agree only records |

## Data shape

`cold_start_runs` is one attempt, a state machine (`TRANSITIONS` in
`core/storage/models/cold_start.py`):

    collecting -> judging -> ready -> live
    ready -> judging       POST /judge on new alerts or tickets
    live -> ready          another run went live
    collecting, judging or ready -> failed

    run_id, source, status, history_days, review_days, judge_limit, baseline,
    progress, drops, judging_skipped, error, created_by, created_at, updated_at, live_at

Partial unique indexes hold one active run (collecting or judging) and one live run,
because two API workers can race either rule. `drops` is keyed by file hash, so
uploading a file twice does not count its drops twice.

`cold_start_alerts` is a run's alert snapshots. They never enter `findings`, so a
dry run cannot trigger triage, severity rewrites, intake or response.

    run_id, alert_id, source, signature, observed_at, title, severity, entities,
    payload, in_review_window, stage1, rule, reasons, llm, review, reviewed_by, reviewed_at

`alert_id` is the source's own id, the one tickets refer to. `payload` holds only
`description`. `llm` is `{verdict, confidence, reasoning, parsed, latency_ms, model}`
or null. A call that timed out or raised stores nothing, so a resume tries it again.

`cold_start_outcomes` is a run's closed tickets that passed label filtering:

    run_id, external_id, alert_ids, signature, disposition, closed_at, entities, source_system

Tickets can arrive before the alerts do, so the link resolves at each build. A ticket
gives one outcome per distinct alert in `alert_ids` the run holds and that was observed
by its close, and counts once per alert kind however many of them it names, else one by `signature` (source and
title) when it references no alert the run holds, else it is counted in
`tickets_unlinked`. Tickets stay out of `case_closure_info`. Agreement and autonomy
read that table, and an imported ticket is not a closure this install performed.

`run.baseline` (JSONB) holds the computed signature table. A run in state `live`
is the active baseline for new alerts.

## Windows

`history_days` is how much history the baseline reads, `review_days` how much is
reviewed after it. A source is read from now minus both.

The review window ends at the newest alert, capped at now, and `as_of` is its start.
For a source read just now that is now minus `review_days`. An export from last week
or a quiet source still has something to review.

## Running a run

A run works as an asyncio task in the API process, holding a Postgres advisory lock
(`store.WorkerLease`). The server drops that lock the moment the holder's connection
dies, so `running` and `resumable` on a run are read from evidence that stays true
however a process stopped. A run whose process died stays active, and so still blocks
a new run, until `POST /judge` finishes it. Every step reads where the run stands and
does what is left.

An upload run waits in `collecting` for its files. `POST /rebuild` or `POST /judge`
starts it. An upload run that received no file gives way to the next `POST /runs`, as
failed, so a customer without a file can still pick another source.

## API, `/api/cold-start`

`findings.read` to read and `findings.write` to act. Going live on a federation source
also needs `integrations.write`.

| Route | Purpose |
|---|---|
| `GET /sources` | `{sources: [{id, kind, configured}], model, loglm}`. `kind` is `federation`, `sample` or `upload` |
| `POST /runs` | `{source, history_days=60, review_days=7 for sample else 1, judge_limit=100}`. 202 with the run. 409 while one is active, 400 for a source that is unknown or not configured |
| `GET /runs/latest`, `GET /runs/{id}` | Status, progress and counts. 404 when there is none |
| `POST /runs/{id}/alerts` | Upload run only. Alerts: JSON, JSONL, CSV, Parquet. Returns `{kept, dropped}` by reason. LogLM rows with `incident_pred == 0` are dropped and counted, kept rows get source `loglm` |
| `POST /runs/{id}/tickets` | Upload closed tickets: JSON, JSONL, CSV. Returns `{kept, dropped}` by reason. Idempotent on `external_id` |
| `POST /runs/{id}/rebuild` | Starts an upload run still collecting. Otherwise, on ready or live, recomputes baseline and assessments and keeps reviews and LLM results |
| `POST /runs/{id}/judge` | Finish the run from wherever it stopped. Skips alerts already judged. 409 while a worker holds it |
| `GET /runs/{id}/groups` | `{groups: [...]}`, review-window alerts grouped by signature, largest first |
| `POST /runs/{id}/groups/{key}/review` | `{verdict: agree or not_benign}` as the signed-in person. Repeating a verdict changes nothing |
| `POST /runs/{id}/go-live` | Enable the source from now, make this the active baseline. Idempotent |

Going live enables a federation source through the federation store and turns on the
global federation switch, without which the row would sit enabled and nothing would
poll. A source already enabled keeps its cursor. `sample` and `upload` only mark the
run live.

Ticket reasons: `unmapped_disposition`, `no_closed_at`, `bulk_close`, `duplicate`,
`undetermined`, `unreadable`. Alert reasons: `no_time`, `unreadable`,
`loglm_not_incident`.

## Live seam

`core/coldstart/active.py` reads the live baseline with a 30-second cache. In
`services/daemon/processor.py`, a new finding's triage prompt gets the evidence lines
in a `<history>` fence and its assessment is stored under `ai_triage.baseline`
(`stage1`, `rule`, `reasons`). A known-answer probe is left out. No live baseline
means the prompt is unchanged.

## Rules

Nothing closes an alert. `dismiss_candidate` is a recommendation.
A review is an override, not a label: `not_benign` sets `marked_not_benign` on the kind,
which escalates it first, and `agree` only records the review. Go-live rebuilds first, so
the live baseline holds every review saved by then. A review that arrives during a short
build waits for it and rebuilds; a run being judged rebuilds from stored reviews at its end.
Rules that add scrutiny run before any rule that removes it (`baseline.RULES`).
A kind closes on a host it has not seen only with 59 clean tickets, and never at high.
With no tickets, frequency clears only low severity.
The baseline only reads data from before the review window.
Alert and ticket text is untrusted, and goes through `alert_text` inside a fence.
With no model assigned, judging is skipped and those alerts wait for a person.

## Measured

Synthetic SOCs from a generator that is not in this repository. Rerun with
`scripts/coldstart/eval_seeds.py`, which goes through the production ticket filter and
linker against only the alerts a run would hold. Rules were tuned on seeds 101 to 105.
The final check is seeds 401 to 410, run once with the rules and the evaluator locked:
7,567 alerts after install, 1,561 of them real. Earlier seed ranges were spent finding bugs
in the rules and the evaluator, so their results are not kept.

| History at install | Would close | Escalate | Really attacks | Needs judgment | Real alerts wrongly closed |
|---|---|---|---|---|---|
| None | 0 | 120 | 98% | 7,447 | 0 |
| 30 days of alerts, no tickets | 235 | 120 | 98% | 7,212 | 1 |
| 60 days of alerts, no tickets | 349 | 120 | 98% | 7,098 | 2 |
| 7 days of alerts and tickets | 259 | 1,109 | 42% | 6,199 | 2 |
| 14 days of alerts and tickets | 462 | 1,477 | 42% | 5,628 | 0 |
| 30 days of alerts and tickets | 982 | 1,880 | 35% | 4,705 | 0 |
| 60 days of alerts and tickets | 1,377 | 2,426 | 31% | 3,764 | 0 |

The rules before this change wrongly closed 2, 23, 20, 14 and 1 real alerts at 7, 14, 21, 30
and 60 days. A kind with 20 clean tickets could close on hosts it had never fired on, and a
ticket naming many alerts counted once per alert.

How to read this:

- "None" scores 0 because nothing closes.
- With tickets, escalate means look at this, not this is an attack: 31% to 42% are real.
- Tickets only count when their alerts are in what the run read, so read as far back as the
  source keeps. A ticket whose alert is older than that is counted as unlinked.
- The would-close alerts are mostly scanner alerts and the phishing simulation, which the
  generator makes always benign. Its attacks never imitate those kinds, so these zeros do
  not test an attacker who does.
- 5 clean tickets is thin: the 7-day misses came from that rule, whose stated bound is 45%.
  No tickets is thinner still. Both are recommendations a person sees with their reasons.

On 80 undecided alerts from seeds 401 and 402, giving the model the baseline moved benign alerts flagged from 32 of 40 to 26 of 40, and real alerts flagged from 38 of 40 to 34 of 40 (`llm-evidence-seed401.json`, `llm-evidence-seed402.json`). That sample is small.

## Known limits

Not exercised: a real SIEM (`scripts/coldstart/fake_elastic.py` is a test double), real
LogLM inference (Parquet mapping is tested with fixture rows), and the baseline refreshing
itself after go-live.

The daemon's older poll loop reads a configured source at daemon start, before go-live, so
"adds nothing to your queue" is about the build, not about a source already configured.
A review saved while another run judges for longer than the 4-second wait applies when
that run ends or at go-live.
