#!/usr/bin/env python3
"""How much history replaces waiting for a baseline? Held-out, synthetic SOC data.

Install is fixed at --install-day. The baseline sees only what came before it,
then stays frozen while the following days are scored against the true labels.

    PYTHONPATH=. python3 scripts/coldstart/eval_day_one.py \
      --findings <run>/findings.jsonl --tickets <run>/tickets.jsonl --manifest <evals>/manifest.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import timedelta
from pathlib import Path

from core.coldstart.baseline import (
    BENIGN_DISPOSITIONS,
    TRUE_POSITIVE,
    Outcome,
    Stage1,
    alert_from_finding,
    assess,
    build_baseline,
    parse_time,
    signature_for,
)


def load_jsonl(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def truth_by_alert(manifest):
    tickets = {t["ticket_id"]: t.get("true_disposition") for t in manifest["tickets"]}
    return {a["external_id"]: tickets.get(a["ticket_id"]) for a in manifest["alerts"]}


def outcomes_from_tickets(tickets, alerts):
    by_external = {a.alert_id: a for a in alerts}
    out = []
    for ticket in tickets:
        closed = parse_time(ticket.get("closed_at"))
        if not ticket.get("usable_label") or closed is None:
            continue
        for ref in ticket.get("alert_refs") or []:
            alert = by_external.get(ref.get("external_id"))
            if alert:
                out.append(
                    Outcome(
                        signature_for(alert),
                        ticket["disposition"],
                        closed,
                        alert.entities,
                    )
                )
    return out


def score(alerts, truth, baseline):
    row = Counter()
    misses = Counter()
    for alert in alerts:
        result = assess(alert, baseline)
        real = truth.get(alert.alert_id)
        row[result.stage1.value] += 1
        row["tp_total"] += real == TRUE_POSITIVE
        row["benign_total"] += real in BENIGN_DISPOSITIONS
        if result.stage1 is Stage1.DISMISS_CANDIDATE:
            if real == TRUE_POSITIVE:
                row["missed"] += 1
                misses[result.rule] += 1
            elif real in BENIGN_DISPOSITIONS:
                row["benign_cleared"] += 1
        if result.stage1 is Stage1.ESCALATE and real == TRUE_POSITIVE:
            row["tp_escalated"] += 1
    return row, misses


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--tickets", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--install-day", type=int, default=60)
    ap.add_argument("--test-days", type=int, default=30)
    ap.add_argument("--days", default="0,1,7,14,30,60")
    ap.add_argument("--out-json")
    args = ap.parse_args()

    findings = load_jsonl(args.findings)
    for finding in findings:
        finding["id"] = finding["external_id"]
    alerts = [a for a in map(alert_from_finding, findings) if a]
    manifest = json.load(open(args.manifest, encoding="utf-8"))
    truth = truth_by_alert(manifest)
    assert any(truth.values()), "manifest carries no true dispositions"
    start = parse_time(manifest["params"]["start"])
    install = start + timedelta(days=args.install_day)
    test_end = install + timedelta(days=args.test_days)
    test = [a for a in alerts if install <= a.observed_at < test_end]
    all_outcomes = outcomes_from_tickets(load_jsonl(args.tickets), alerts)

    print(
        "history_days tickets test_alerts dismiss_cand escalate abstain missed/tp benign_cleared/benign_total tp_escalated"
    )
    results = []
    for days in [int(d) for d in args.days.split(",")]:
        window = install - timedelta(days=days)
        history = [a for a in alerts if window <= a.observed_at < install]
        for use_tickets in (False, True):
            outcomes = (
                [o for o in all_outcomes if o.closed_at >= window]
                if use_tickets
                else []
            )
            baseline = build_baseline(history, outcomes, install)
            row, misses = score(test, truth, baseline)
            print(
                f"{days:>12} {'yes' if use_tickets else 'no':>7} {len(test):>11} "
                f"{row['dismiss_candidate']:>12} {row['escalate']:>8} {row['abstain']:>7} "
                f"{row['missed']:>4}/{row['tp_total']:<4} {row['benign_cleared']:>6}/{row['benign_total']} {row['tp_escalated']:>12}"
                f"  misses={dict(misses)}"
            )
            results.append(
                {
                    "history_days": days,
                    "tickets": use_tickets,
                    "test_alerts": len(test),
                    **row,
                    "misses_by_rule": dict(misses),
                }
            )
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
