"""Bundled sample history: pseudonymized synthetic alerts and closed tickets.

``source: "sample"`` feeds these through the same pipeline as a customer's own. Times
shift so the newest alert is now, keeping the record's day-of-week and spacing.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from core.coldstart.baseline import parse_time

SAMPLE_SOURCE = "sample"
FIXTURE = Path(__file__).resolve().parents[2] / "data/coldstart/sample_history.json.gz"


def load_fixture() -> Dict[str, List[Dict[str, Any]]]:
    with gzip.open(FIXTURE, "rt", encoding="utf-8") as f:
        return json.load(f)


def load_sample(now: datetime) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Alerts and tickets with every time moved so the newest alert is ``now``."""
    data = load_fixture()
    newest = max(parse_time(alert["timestamp"]) for alert in data["alerts"])
    shift = now - newest
    alerts = [
        {**a, "timestamp": (parse_time(a["timestamp"]) + shift).isoformat()}
        for a in data["alerts"]
    ]
    tickets = [
        {**t, "closed_at": (parse_time(t["closed_at"]) + shift).isoformat()}
        for t in data["tickets"]
    ]
    return alerts, tickets
