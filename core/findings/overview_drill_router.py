"""GET /api/overview/outcomes/{state} and /api/overview/agents/{workflow_id}.

The Overview board counts today's alerts by outcome and lists the workflows
that run. These two reads are what a click on one of them opens: the alerts
behind an outcome count (and the cases they sit in), and one workflow's steps,
live runs and recent runs.

Each field is behind the permission main's own read of that data asks for. Case
data needs ``cases.read`` on both routes, so a role that can read alerts or runs
and not cases gets those and no case.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from core.auth.current_user import get_current_user
from core.auth.permissions import missing_permission, permission_gate
from core.deps import provide_workflows
from core.findings.alert_outcomes import (
    _ID_CHUNK,
    TERMINAL_LABELS,
    terminal_states_today,
)
from core.findings.overview import CASE_STATES
from core.routing import Auth, RouterMeta
from core.storage.connection import get_db_manager
from core.storage.models import Case, Finding, User, WorkflowRun
from core.time import utcnow
from core.workflows import catalog
from core.workflows.run_rating import RATED_STATUS

router = APIRouter()

ROUTER_META = RouterMeta(prefix="/api/overview", tags=["overview"], auth=Auth.REQUIRED)

# The board's node labels, which name the dismissed node apart from its pill.
LABELS = {**TERMINAL_LABELS, "dismissed": "Dismissed as noise"}
EXPLAIN = {
    "resolved_auto": "Today's alerts whose case an agent closed without a person.",
    "resolved_person": "Today's alerts whose case an analyst closed.",
    "working": "Today's alerts in a case that is still open and has nothing waiting on a person.",
    "case_idle": "Today's alerts in an open case whose runs have all ended, so nothing is working it.",
    "needs_you": "Today's alerts in a case with an approval waiting on a person.",
    "dismissed": "Today's alerts triage dropped as noise, or someone marked as noise.",
    "excluded": "Today's alerts naming an excluded IP, which are not triaged and not in the feed.",
    "scoring": "Today's alerts queued for triage that have not been scored yet.",
    "waiting": "Today's alerts that are not in a case, not queued for triage and not dropped.",
}
RUN_WINDOW = timedelta(days=30)
RECENT_RUNS = 12


def _iso(t: Any) -> Optional[str]:
    return t.isoformat() if hasattr(t, "isoformat") else None


def _chunks(ids: list[str]) -> list[list[str]]:
    return [ids[at : at + _ID_CHUNK] for at in range(0, len(ids), _ID_CHUNK)]


def _can_read_cases(user: User) -> bool:
    return missing_permission(user.user_id, "cases.read") is None


@router.get("/outcomes/{state}", dependencies=[permission_gate("findings.read")])
def outcome_alerts(
    state: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    range: Literal["today", "all"] = Query("today"),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """One outcome's alerts for the board's range, newest first, and the cases they sit in.

    Reads the rows the board counts, so a count and its list cannot disagree.
    """
    if state not in LABELS:
        raise HTTPException(status_code=404, detail=f"Unknown outcome: {state}")
    rows = [
        r
        for r in terminal_states_today(all_time=range == "all")
        if r["terminal_state"] == state
    ]
    out: Dict[str, Any] = {
        "state": state,
        "label": LABELS[state],
        "explain": (
            EXPLAIN[state].replace("Today's alerts", "Alerts")
            if range == "all"
            else EXPLAIN[state]
        ),
        "total": len(rows),
        "offset": offset,
        "items": [],
        "cases": [],
        "by_source": [
            {"data_source": s, "count": n}
            for s, n in Counter(r["data_source"] for r in rows).most_common()
        ],
    }
    if not rows:
        return out
    can_read_cases = _can_read_cases(user)
    case_of = {r["finding_id"]: r["case_id"] for r in rows}
    ids = list(case_of)
    db = get_db_manager()
    with db.session_scope() as session:
        found = []
        for chunk in _chunks(ids):
            found += (
                session.query(
                    Finding.finding_id,
                    Finding.title,
                    Finding.description,
                    Finding.severity,
                    Finding.data_source,
                    Finding.created_at,
                )
                .filter(Finding.finding_id.in_(chunk))
                .all()
            )
        found.sort(key=lambda r: r.finding_id)
        found.sort(key=lambda r: r.created_at or datetime.min, reverse=True)
        out["items"] = [
            {
                "finding_id": r.finding_id,
                "title": r.title,
                "description": r.description,
                "severity": r.severity,
                "data_source": r.data_source,
                "created_at": _iso(r.created_at),
                "case_id": case_of[r.finding_id] if can_read_cases else None,
            }
            for r in found[offset : offset + limit]
        ]
        # The cases behind the whole outcome, not just this page.
        if can_read_cases and state in CASE_STATES:
            all_cases = Counter(c for c in case_of.values() if c)
            if all_cases:
                cases = (
                    session.query(
                        Case.case_id,
                        Case.title,
                        Case.status,
                        Case.priority,
                        Case.updated_at,
                    )
                    .filter(Case.case_id.in_(list(all_cases)))
                    .all()
                )
                out["cases"] = sorted(
                    (
                        {
                            "case_id": c.case_id,
                            "title": c.title,
                            "status": c.status,
                            "priority": c.priority,
                            "updated_at": _iso(c.updated_at),
                            "alerts": all_cases[c.case_id],
                        }
                        for c in cases
                    ),
                    key=lambda c: (-c["alerts"], c["updated_at"] or ""),
                )
    return out


def _run_row(run: WorkflowRun, rated: str, can_read_cases: bool) -> Dict[str, Any]:
    ctx = run.trigger_context or {}
    return {
        "run_id": run.run_id,
        "status": run.status,
        "rated_status": rated,
        "started_at": _iso(run.started_at),
        "duration_ms": run.duration_ms,
        "cost_usd": float(run.total_cost_usd or 0),
        "outcome": run.outcome,
        "summary": run.result_summary or run.reason or run.error,
        "case_id": ctx.get("case_id") if can_read_cases else None,
    }


@router.get("/agents/{workflow_id}", dependencies=[permission_gate("automation.read")])
def agent_detail(
    workflow_id: str,
    service=Depends(provide_workflows),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """One workflow as the board shows it: what it does, live runs, recent runs, 30-day record."""
    definition = catalog.detail(service, workflow_id)
    if definition is None:
        raise HTTPException(
            status_code=404, detail=f"Workflow not found: {workflow_id}"
        )
    can_read_cases = _can_read_cases(user)
    since = utcnow().replace(tzinfo=None) - RUN_WINDOW
    db = get_db_manager()
    with db.session_scope() as session:
        base = session.query(WorkflowRun, RATED_STATUS).filter(
            WorkflowRun.workflow_id == workflow_id, WorkflowRun.deleted_at.is_(None)
        )
        live = (
            base.filter(WorkflowRun.status.in_(("running", "paused")))
            .order_by(WorkflowRun.started_at.desc())
            .limit(RECENT_RUNS)
            .all()
        )
        recent = (
            base.filter(WorkflowRun.status.in_(("completed", "failed", "cancelled")))
            .order_by(WorkflowRun.started_at.desc())
            .limit(RECENT_RUNS)
            .all()
        )
        window = (
            base.filter(
                WorkflowRun.started_at >= since,
                WorkflowRun.status.in_(("completed", "failed", "cancelled")),
            )
            .with_entities(
                RATED_STATUS,
                WorkflowRun.duration_ms,
                WorkflowRun.total_cost_usd,
            )
            .all()
        )
        live_rows = [_run_row(r, rated, can_read_cases) for r, rated in live]
        recent_rows = [_run_row(r, rated, can_read_cases) for r, rated in recent]
    tally = Counter(status for status, _d, _c in window)
    durations = sorted(d for _s, d, _c in window if d)
    costs = [float(c) for _s, _d, c in window if c]
    # a rejected run is counted apart and stays out of the rate
    ended = sum(n for state, n in tally.items() if state != "rejected")
    return {
        "workflow": definition,
        "live": live_rows,
        "recent": recent_rows,
        "record": {
            "days": RUN_WINDOW.days,
            "runs": ended + tally.get("rejected", 0),
            "completed": tally.get("completed", 0),
            "failed": tally.get("failed", 0),
            "cancelled": tally.get("cancelled", 0),
            "rejected": tally.get("rejected", 0),
            "rate": tally.get("completed", 0) / ended if ended else None,
            "median_ms": durations[len(durations) // 2] if durations else None,
            "mean_cost_usd": sum(costs) / len(costs) if costs else None,
        },
    }
