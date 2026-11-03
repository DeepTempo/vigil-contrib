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
| One review labels one alert kind | A person | None | Review step |

## Data shape

`cold_start_runs` is one attempt, a state machine:

    collecting -> judging -> ready -> live
    any non-terminal state -> failed

`cold_start_alerts` is a run's alert snapshots. They never enter `findings`, so a
dry run cannot trigger triage, severity rewrites, intake or response.

    run_id, alert_id, source, signature, observed_at, title, severity, entities,
    payload, in_review_window, stage1, rule, reasons, llm, review, reviewed_by, reviewed_at

`llm` is `{verdict, confidence, reasoning, parsed, latency_ms, model}` or null.

`cold_start_outcomes` is a run's closed tickets that passed label filtering:

    run_id, external_id, signature, disposition, closed_at, entities, source_system

Tickets stay out of `case_closure_info`. Agreement and autonomy read that table,
and an imported ticket is not a closure this install performed.

`run.baseline` (JSONB) holds the computed signature table. A run in state `live`
is the active baseline for new alerts.

## API, `/api/cold-start`

| Route | Purpose |
|---|---|
| `GET /sources` | Federation adapters with `configured`, plus `sample` and `upload` |
| `POST /runs` | `{source, history_days, review_days, judge_limit}`. 409 while one is active |
| `GET /runs/latest`, `GET /runs/{id}` | Status, progress and counts |
| `POST /runs/{id}/alerts` | Upload alerts: JSON, JSONL, CSV, LogLM Parquet |
| `POST /runs/{id}/tickets` | Upload closed tickets, returns kept and dropped by reason |
| `POST /runs/{id}/rebuild` | Recompute baseline and assessments, keep reviews and LLM results |
| `POST /runs/{id}/judge` | Resume judging. Skips alerts already judged |
| `GET /runs/{id}/groups` | Review-window alerts grouped by signature |
| `POST /runs/{id}/groups/{key}/review` | `{verdict: agree or not_benign}` as the signed-in person |
| `POST /runs/{id}/go-live` | Enable the source from now, make this the active baseline |

## Rules

Nothing closes an alert. `dismiss_candidate` is a recommendation.
Rules that add scrutiny run before any rule that removes it (`baseline.RULES`).
The baseline only reads data from before the review window.
Alert and ticket text is untrusted, and goes through `alert_text` inside a fence.
With no model assigned, judging is skipped and those alerts wait for a person.
