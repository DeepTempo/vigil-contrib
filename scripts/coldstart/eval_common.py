"""What the cold start evals share. Tickets go through the production filter and linker,
against only the alerts a run would hold, so an eval cannot claim what the product cannot do.
"""

from __future__ import annotations

import json
from collections import Counter

from core.coldstart.baseline import (
    BENIGN_DISPOSITIONS,
    TRUE_POSITIVE,
    Stage1,
    assess,
)
from core.coldstart.tickets import filter_tickets, outcomes_from


def load_jsonl(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def truth_by_alert(manifest):
    tickets = {t["ticket_id"]: t.get("true_disposition") for t in manifest["tickets"]}
    return {a["external_id"]: tickets.get(a["ticket_id"]) for a in manifest["alerts"]}


def production_outcomes(ticket_rows, retained_alerts):
    outcomes, _ = outcomes_from(
        filter_tickets(ticket_rows).kept, {a.alert_id: a for a in retained_alerts}
    )
    return outcomes


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
