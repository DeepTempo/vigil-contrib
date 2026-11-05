"""Real alerts grouped by kind, with what happened to each.

A kind is cold start's signature: source plus title with entities masked. Outcomes are
``alert_outcomes``' one state per finding. Time to outcome exists only where a stored
timestamp says when the outcome happened, so a kind with none reports none.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from statistics import median
from typing import Any, Iterable, Mapping, Optional, Sequence

from pydantic import BaseModel, Field
from sqlalchemy import select

from core.coldstart.baseline import alert_from_finding, signature_for
from core.config import is_demo_mode
from core.findings.alert_outcomes import TERMINAL_LABELS, finding_states
from core.storage.models import CaseClosureInfo, Finding
from core.storage.schemas.base import OptDateTime
from core.storage.unit_of_work import unit_of_work
from core.time import utcnow

MAX_HOURS = 24 * 30
# The newest this many in a window. A cut says so on the screen.
READ_LIMIT = 50_000
EXAMPLES = 5
RESOLVED_STATES = ("resolved_auto", "resolved_person")
DISMISSED = "dismissed"
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
# The daemon's own health checks, stored as findings. They are nobody's alert. This is
# services.daemon.probes.PROBE_DATA_SOURCE, which core can't import.
PROBE_SOURCE = "probe"


class OutcomeCount(BaseModel):
    state: str
    label: str
    alerts: int


class SeverityCount(BaseModel):
    severity: str
    alerts: int


class AlertKind(BaseModel):
    key: str
    title: str
    source: str
    alerts: int
    severities: list[SeverityCount]
    outcomes: list[OutcomeCount]
    # Median over ``timed_outcomes`` alerts. None when no alert has a stored outcome time.
    median_seconds_to_outcome: Optional[float] = None
    timed_outcomes: int = 0
    latest_at: OptDateTime = None
    finding_ids: list[str] = Field(default_factory=list)
    case_ids: list[str] = Field(default_factory=list)


class AlertTriage(BaseModel):
    hours: int
    alerts: int
    outcomes: list[OutcomeCount]
    kinds: list[AlertKind]
    truncated: bool = False


@dataclass(frozen=True)
class AlertRow:
    finding_id: str
    data_source: str
    title: Optional[str]
    severity: Optional[str]
    created_at: datetime
    timestamp: Optional[datetime] = None
    noise_marked_at: Optional[datetime] = None
    entity_context: Optional[Mapping[str, Any]] = None


def _key_of(row: AlertRow) -> str:
    alert = alert_from_finding(
        {
            "finding_id": row.finding_id,
            "data_source": row.data_source,
            "title": row.title,
            "severity": row.severity,
            "timestamp": (row.timestamp or row.created_at).isoformat(),
            "entity_context": row.entity_context,
        }
    )
    assert alert is not None, "a stored finding always has a created_at"
    return signature_for(alert)


def _seconds_to_outcome(
    row: AlertRow,
    state: str,
    case_id: Optional[str],
    closed_at: Mapping[str, datetime],
) -> Optional[float]:
    """From arrival to the stored moment of a dismissal or a close. An alert that joined
    a case after it closed has no such span."""
    ended: Optional[datetime] = None
    if state == DISMISSED:
        ended = row.noise_marked_at
    elif state in RESOLVED_STATES and case_id:
        ended = closed_at.get(case_id)
    if ended is None or ended < row.created_at:
        return None
    return (ended - row.created_at).total_seconds()


def _outcome_counts(counts: Counter) -> list[OutcomeCount]:
    return [
        OutcomeCount(state=state, label=TERMINAL_LABELS.get(state, state), alerts=n)
        for state, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def _severity_counts(counts: Counter) -> list[SeverityCount]:
    rank = {name: i for i, name in enumerate(SEVERITY_ORDER)}
    return [
        SeverityCount(severity=name, alerts=n)
        for name, n in sorted(counts.items(), key=lambda kv: rank.get(kv[0], 99))
    ]


def group_kinds(
    rows: Iterable[AlertRow],
    states: Mapping[str, tuple[str, Optional[str]]],
    closed_at: Mapping[str, datetime],
) -> list[AlertKind]:
    """Most alerts first. Pure, so a kind's numbers are only ever these rows' numbers."""
    groups: dict[str, list[AlertRow]] = defaultdict(list)
    for row in rows:
        groups[_key_of(row)].append(row)
    kinds = []
    for key, members in groups.items():
        source, _, title = key.partition("|")
        members.sort(key=lambda r: r.created_at, reverse=True)
        outcomes: Counter = Counter()
        cases: list[str] = []
        spans: list[float] = []
        for row in members:
            state, case_id = states.get(row.finding_id, ("waiting", None))
            outcomes[state] += 1
            if case_id and case_id not in cases:
                cases.append(case_id)
            span = _seconds_to_outcome(row, state, case_id, closed_at)
            if span is not None:
                spans.append(span)
        kinds.append(
            AlertKind(
                key=key,
                title=title,
                source=source,
                alerts=len(members),
                severities=_severity_counts(
                    Counter((r.severity or "unknown").lower() for r in members)
                ),
                outcomes=_outcome_counts(outcomes),
                median_seconds_to_outcome=median(spans) if spans else None,
                timed_outcomes=len(spans),
                latest_at=members[0].created_at,
                finding_ids=[r.finding_id for r in members[:EXAMPLES]],
                case_ids=cases[:EXAMPLES],
            )
        )
    kinds.sort(key=lambda k: (-k.alerts, k.key))
    return kinds


def _closed_at(session, case_ids: Sequence[str]) -> dict[str, datetime]:
    if not case_ids:
        return {}
    return dict(
        session.execute(
            select(CaseClosureInfo.case_id, CaseClosureInfo.closed_at).where(
                CaseClosureInfo.case_id.in_(case_ids)
            )
        ).all()
    )


def read_alert_triage(hours: int) -> AlertTriage:
    if is_demo_mode():
        return AlertTriage(hours=hours, alerts=0, outcomes=[], kinds=[])
    since = utcnow() - timedelta(hours=hours)
    with unit_of_work() as session:
        found = session.execute(
            select(
                Finding.finding_id,
                Finding.data_source,
                Finding.title,
                Finding.severity,
                Finding.created_at,
                Finding.timestamp,
                Finding.noise_marked_at,
                Finding.entity_context,
            )
            .where(Finding.created_at >= since, Finding.data_source != PROBE_SOURCE)
            .order_by(Finding.created_at.desc(), Finding.finding_id.desc())
            .limit(READ_LIMIT + 1)
        ).all()
    rows = [AlertRow(*row) for row in found[:READ_LIMIT]]
    states = finding_states([row.finding_id for row in rows])
    case_ids = sorted({case for _state, case in states.values() if case})
    with unit_of_work() as session:
        closed_at = _closed_at(session, case_ids)
    totals = Counter(state for state, _case in states.values())
    return AlertTriage(
        hours=hours,
        alerts=len(rows),
        outcomes=_outcome_counts(totals),
        kinds=group_kinds(rows, states, closed_at),
        truncated=len(found) > READ_LIMIT,
    )
