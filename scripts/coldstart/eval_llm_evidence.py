#!/usr/bin/env python3
"""Does giving the model the baseline change its verdicts? Same alerts, two prompts.

Samples alerts the baseline left undecided on held-out days, balanced by true label,
and asks the local model about each one blind and with evidence. Calls Ollama directly.

    PYTHONPATH=. python3 scripts/coldstart/eval_llm_evidence.py --findings ... --tickets ... \
      --manifest ... --per-class 20 --out-json docs/coldstart/llm-evidence-seed42.json
"""

from __future__ import annotations

import argparse
import json
import random
import time
import urllib.request
from collections import Counter
from datetime import timedelta
from pathlib import Path

from core.coldstart.baseline import (
    BENIGN_DISPOSITIONS,
    TRUE_POSITIVE,
    Stage1,
    alert_from_finding,
    assess,
    build_baseline,
    parse_time,
)
from core.coldstart.judge import build_prompt, evidence_lines, parse_verdict
from scripts.coldstart.eval_day_one import (
    load_jsonl,
    outcomes_from_tickets,
    truth_by_alert,
)

FLAG = {"investigate", "isolate", "block"}


def ask(url, model, prompt):
    body = json.dumps(
        {
            "model": model,
            "stream": False,
            "think": False,
            "messages": [{"role": "user", "content": prompt}],
            "options": {"temperature": 0, "num_predict": 400},
        }
    ).encode()
    request = urllib.request.Request(
        f"{url}/api/chat", body, {"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=300) as response:
        return json.load(response)["message"]["content"]


def summarize(rows, key):
    out = Counter()
    for row in rows:
        result = row[key]
        out["n"] += 1
        out["unparsed"] += not result["parsed"]
        out[f"verdict_{result['verdict']}"] += 1
        out["seconds"] += result["seconds"]
        flagged = result["verdict"] in FLAG
        if row["truth"] == "tp":
            out["tp"] += 1
            out["tp_flagged"] += flagged
        else:
            out["benign"] += 1
            out["benign_flagged"] += flagged
    return dict(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--tickets", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--install-day", type=int, default=60)
    ap.add_argument("--history-days", type=int, default=30)
    ap.add_argument("--per-class", type=int, default=20)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--ollama", default="http://127.0.0.1:11434")
    ap.add_argument("--model", default="nemotron-3.5-lightning:30b-a3b-mlx")
    ap.add_argument("--out-json")
    args = ap.parse_args()

    findings = load_jsonl(args.findings)
    by_id = {}
    for finding in findings:
        finding["id"] = finding["external_id"]
        by_id[finding["id"]] = finding
    alerts = [a for a in map(alert_from_finding, findings) if a]
    manifest = json.load(open(args.manifest, encoding="utf-8"))
    truth = truth_by_alert(manifest)
    install = parse_time(manifest["params"]["start"]) + timedelta(days=args.install_day)
    window = install - timedelta(days=args.history_days)
    outcomes = [
        o
        for o in outcomes_from_tickets(load_jsonl(args.tickets), alerts)
        if o.closed_at >= window
    ]
    baseline = build_baseline(
        [a for a in alerts if window <= a.observed_at < install], outcomes, install
    )
    undecided = [
        a
        for a in alerts
        if a.observed_at >= install and assess(a, baseline).stage1 is Stage1.ABSTAIN
    ]
    rng = random.Random(args.seed)
    real = [a for a in undecided if truth.get(a.alert_id) == TRUE_POSITIVE]
    benign = [a for a in undecided if truth.get(a.alert_id) in BENIGN_DISPOSITIONS]
    sample = rng.sample(real, min(args.per_class, len(real))) + rng.sample(
        benign, min(args.per_class, len(benign))
    )
    rng.shuffle(sample)
    print(
        f"undecided={len(undecided)} real={len(real)} benign={len(benign)} sample={len(sample)}",
        flush=True,
    )

    rows = []
    for index, alert in enumerate(sample):
        row = {
            "alert_id": alert.alert_id,
            "truth": "tp" if truth.get(alert.alert_id) == TRUE_POSITIVE else "benign",
        }
        description = str(by_id[alert.alert_id].get("description") or "")
        prompts = {
            "blind": build_prompt(alert, description),
            "evidence": build_prompt(
                alert, description, evidence_lines(alert, baseline)
            ),
        }
        for name, prompt in prompts.items():
            started = time.monotonic()
            verdict = parse_verdict(ask(args.ollama, args.model, prompt))
            row[name] = {**verdict.as_dict(), "seconds": time.monotonic() - started}
        rows.append(row)
        print(
            f"{index + 1}/{len(sample)} {row['truth']:6} "
            f"blind={row['blind']['verdict']} evidence={row['evidence']['verdict']}",
            flush=True,
        )
    report = {
        "model": args.model,
        "history_days": args.history_days,
        "sample": len(rows),
        "blind": summarize(rows, "blind"),
        "evidence": summarize(rows, "evidence"),
    }
    print(json.dumps(report, indent=2))
    if args.out_json:
        Path(args.out_json).write_text(json.dumps({**report, "rows": rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
