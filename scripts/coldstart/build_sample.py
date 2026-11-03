#!/usr/bin/env python3
"""Build data/coldstart/sample_history.json.gz from a cold-start replay run.

Keeps only the fields the pipeline reads. It leaves out anomaly_score, true labels
and ticket free text. The input records are already pseudonymized synthetic data.

    PYTHONPATH=. python3 scripts/coldstart/build_sample.py --run <run-dir>
"""

from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path

from core.coldstart.sample_history import FIXTURE

ALERT_FIELDS = (
    "external_id",
    "source",
    "title",
    "severity",
    "timestamp",
    "description",
    "iocs",
)
TICKET_FIELDS = (
    "ticket_id",
    "disposition",
    "usable_label",
    "label_quality",
    "duplicate_of",
    "closed_at",
    "closed_by",
    "entities",
    "source_system",
)


def _load_jsonl(path: Path) -> list:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _alert(finding: dict) -> dict:
    return {key: finding[key] for key in ALERT_FIELDS if finding.get(key) is not None}


def _ticket(ticket: dict) -> dict:
    kept = {key: ticket[key] for key in TICKET_FIELDS if ticket.get(key) is not None}
    kept["alert_refs"] = [
        {"external_id": ref["external_id"]} for ref in ticket.get("alert_refs") or []
    ]
    return kept


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--out", type=Path, default=FIXTURE)
    args = parser.parse_args()

    data = {
        "alerts": [_alert(f) for f in _load_jsonl(args.run / "findings.jsonl")],
        "tickets": [_ticket(t) for t in _load_jsonl(args.run / "tickets.jsonl")],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # mtime=0 so the same input gives the same bytes.
    with args.out.open("wb") as raw, gzip.GzipFile(
        filename="", fileobj=raw, mode="wb", mtime=0
    ) as f:
        f.write(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    print(
        f"{args.out}: {len(data['alerts'])} alerts, {len(data['tickets'])} tickets, "
        f"{args.out.stat().st_size} bytes"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
