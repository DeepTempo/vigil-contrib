#!/usr/bin/env python3
"""Compare rule variants across freshly generated synthetic SOCs.

One seed can flatter or punish a rule by luck, so this generates each seed with a
synthetic SOC generator kept outside this repository, normalizes it, and scores every
variant at every history length. Tune on one seed range and check a different range once.

    PYTHONPATH=. python3 scripts/coldstart/eval_seeds.py --seeds 101-105 \
      --tools /path/to/generator --mapping mappings/synthetic.json \
      --data /tmp/seeds --out result.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, replace
from datetime import timedelta
from pathlib import Path
from typing import Dict, FrozenSet, List

from core.coldstart import baseline as rules
from core.coldstart.baseline import alert_from_finding, build_baseline, parse_time
from scripts.coldstart.eval_common import (
    load_jsonl,
    production_outcomes,
    score,
    truth_by_alert,
)

ALL = frozenset({"info", "low", "medium", "high"})
NOT_HIGH = frozenset({"info", "low", "medium"})
LOW = frozenset({"info", "low"})
WINDOW, EVERY, NO_TICKETS = "window", "every", "none"


@dataclass(frozen=True)
class Variant:
    strong_labels: int
    strong_severities: FrozenSet[str]
    routine_severities: FrozenSet[str]
    tickets: str
    one_label_per_ticket: bool


VARIANTS: Dict[str, Variant] = {
    "before": Variant(20, ALL, NOT_HIGH, WINDOW, False),
    "after": Variant(59, NOT_HIGH, LOW, EVERY, True),
    "after_no_tickets": Variant(59, NOT_HIGH, LOW, NO_TICKETS, True),
}


def prepare(seed: int, tools: Path, mapping: str, data: Path) -> Path:
    """Generate and normalize one seed, skipping work already on disk."""
    run = data / f"seed{seed}"
    findings = run / "findings.jsonl"
    if findings.exists():
        return run
    raw = run / "raw"
    run.mkdir(parents=True, exist_ok=True)
    evals = tools / "evals"
    subprocess.run(
        [
            str(evals / ".venv/bin/python"),
            "generate.py",
            "--days",
            "90",
            "--seed",
            str(seed),
            "--out",
            str(raw),
        ],
        cwd=evals,
        check=True,
        capture_output=True,
    )
    tickets = run / "tickets.jsonl"
    subprocess.run(
        [
            sys.executable,
            str(tools / "normalize.py"),
            "--jira",
            str(raw / "jira_export.csv"),
            "--sentinel",
            str(raw / "sentinel_incidents.json"),
            "--alerts",
            str(raw / "alerts.jsonl"),
            "--mapping",
            str(tools / mapping),
            "--key-file",
            str(data / "pseudo.key"),
            "--out",
            str(tickets),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(tools / "to_vigil.py"),
            "--tickets",
            str(tickets),
            "--out",
            str(findings),
        ],
        check=True,
        capture_output=True,
    )
    return run


def apply(variant: Variant) -> None:
    rules.MIN_STRONG_LABELS = variant.strong_labels
    rules.STRONG_SEVERITIES = variant.strong_severities
    rules.ROUTINE_SEVERITIES = variant.routine_severities


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", required=True, help="first-last, for example 101-105")
    ap.add_argument("--tools", required=True, type=Path)
    ap.add_argument("--mapping", required=True, help="relative to --tools")
    ap.add_argument("--data", required=True, type=Path)
    ap.add_argument("--variants", default=",".join(VARIANTS))
    ap.add_argument("--days", default="0,7,14,21,30,60")
    ap.add_argument("--install-day", type=int, default=60)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    first, last = (int(part) for part in args.seeds.split("-"))
    days = [int(d) for d in args.days.split(",")]
    names = args.variants.split(",")

    totals: Dict[str, Dict[int, Counter]] = defaultdict(lambda: defaultdict(Counter))
    by_rule: Dict[str, Counter] = defaultdict(Counter)
    for seed in range(first, last + 1):
        run = prepare(
            seed, args.tools.expanduser().resolve(), args.mapping, args.data.resolve()
        )
        findings = load_jsonl(run / "findings.jsonl")
        for finding in findings:
            finding["id"] = finding["external_id"]
        alerts = [a for a in map(alert_from_finding, findings) if a]
        manifest = json.load(open(run / "raw/manifest.json", encoding="utf-8"))
        truth = truth_by_alert(manifest)
        assert any(truth.values()), f"seed {seed} has no true labels"
        ticket_rows = load_jsonl(run / "tickets.jsonl")
        install = parse_time(manifest["params"]["start"]) + timedelta(
            days=args.install_day
        )
        test = [a for a in alerts if a.observed_at >= install]
        assert test, f"seed {seed} has no alerts after install"
        for name in names:
            variant = VARIANTS[name]
            apply(variant)
            for history in days:
                window = install - timedelta(days=history)
                # A run holds the review window too, and links tickets against all of it.
                collected = [a for a in alerts if a.observed_at >= window]
                retained = [a for a in collected if a.observed_at < install]
                outcomes = production_outcomes(ticket_rows, collected)
                if history:
                    assert outcomes or variant.tickets == NO_TICKETS or not retained
                if variant.tickets == WINDOW:
                    outcomes = [o for o in outcomes if o.closed_at >= window]
                if variant.tickets == NO_TICKETS:
                    outcomes = []
                if not variant.one_label_per_ticket:
                    outcomes = [replace(o, ticket_id=None) for o in outcomes]
                baseline = build_baseline(retained, outcomes, install)
                row, misses = score(test, truth, baseline)
                bucket = totals[name][history]
                bucket.update(row)
                bucket["alerts"] += len(test)
                bucket["seeds"] += 1
                bucket["seeds_with_a_miss"] += row["missed"] > 0
                bucket["worst_seed"] = max(bucket["worst_seed"], row["missed"])
                by_rule[f"{name}/{history}"].update(misses)

    print(
        f"{'variant':30}{'days':>5}{'alerts':>8}{'close':>7}{'escal':>7}{'judge':>7}"
        f"{'missed':>8}{'of_tp':>7}{'seeds_miss':>11}{'worst':>7}{'esc_real%':>10}{'close_real%':>12}"
    )
    report: List[Dict] = []
    for name in names:
        for history in days:
            t = totals[name][history]
            closed = t["dismiss_candidate"]
            print(
                f"{name:30}{history:>5}{t['alerts']:>8}{closed:>7}{t['escalate']:>7}{t['abstain']:>7}"
                f"{t['missed']:>8}{t['tp_total']:>7}{t['seeds_with_a_miss']:>8}/{t['seeds']:<2}{t['worst_seed']:>7}"
                f"{100 * t['tp_escalated'] / max(t['escalate'], 1):>10.1f}"
                f"{100 * t['missed'] / max(closed, 1):>12.2f}"
            )
            report.append(
                {
                    "variant": name,
                    "history_days": history,
                    **t,
                    "misses_by_rule": dict(by_rule[f"{name}/{history}"]),
                }
            )
    if args.out:
        args.out.write_text(json.dumps({"seeds": args.seeds, "rows": report}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
