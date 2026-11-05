"""Reads the rows a case's story is built from. An incident is a case with 2 or more alerts."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy import Text, cast, func, or_, select
from sqlalchemy.dialects.postgresql import ARRAY, array
from sqlalchemy.orm import noload

from core.cases.case_records_service import list_case_investigations, list_case_runs
from core.cases.case_status import CLOSED
from core.config import get_integration_config, is_demo_mode, is_integration_enabled
from core.incidents.story import (
    MIN_FINDINGS,
    RULE_KEYS,
    STEPS_PAGE,
    UNUSUAL_SCORE,
    CaseFacts,
    ClosureFacts,
    Coverage,
    FindingFacts,
    HuntVerdictFacts,
    IncidentList,
    IncidentRow,
    InstallFacts,
    IocFacts,
    LogFacts,
    Report,
    RuleInventory,
    SourceCount,
    Story,
    StoryFacts,
    Viewer,
    build_story,
    entity_overlap,
    step_coverage,
    verdict_of,
)
from core.response.approval_service import (
    ApprovalService,
    PendingAction,
    case_ids_for,
    needs_you,
)
from core.response.ceiling import execution_held
from core.storage.models import (
    ApprovalAction,
    Case,
    CaseClosureInfo,
    CaseIOC,
    DetectionRule,
    EpisodicVerdict,
    Finding,
    FindingMitrePrediction,
    Investigation,
    LogEvent,
    WorkflowRun,
    case_findings,
)
from core.storage.unit_of_work import unit_of_work

# More than a page can show and more than a decision needs.
APPROVALS_READ = 200
# A list counts uncovered steps only on cases up to this size.
LIST_WALK_MAX = 1000
ACTIVE_RULE = "active"
COMPLETED = "completed"


class NotAnIncident(Exception):
    """The case exists and holds fewer alerts than an incident does."""

    def __init__(self, case_id: str, alerts: int):
        super().__init__(
            f"Case {case_id} has {alerts} alert{'' if alerts == 1 else 's'}. "
            f"An incident is a case with {MIN_FINDINGS} or more. Open it under Cases."
        )


def _utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _labels_of(session, finding_ids) -> Dict[str, List[Tuple[str, Optional[float]]]]:
    labels: Dict[str, List[Tuple[str, Optional[float]]]] = defaultdict(list)
    for finding_id, technique, confidence in session.execute(
        select(
            FindingMitrePrediction.finding_id,
            FindingMitrePrediction.technique_id,
            FindingMitrePrediction.confidence,
        ).where(FindingMitrePrediction.finding_id.in_(finding_ids))
    ):
        labels[finding_id].append((technique, confidence))
    return labels


def _case_finding_facts(session, case_id: str) -> List[FindingFacts]:
    """The columns a story reads, so a large case does not load each alert's whole row."""
    in_case = select(case_findings.c.finding_id).where(
        case_findings.c.case_id == case_id
    )
    labels = _labels_of(session, in_case)
    rows = session.execute(
        select(
            Finding.finding_id,
            Finding.created_at,
            Finding.data_source,
            Finding.title,
            Finding.description,
            Finding.severity,
            Finding.timestamp,
            Finding.anomaly_score,
            Finding.entity_context,
        ).where(Finding.finding_id.in_(in_case))
    )
    return [FindingFacts(*row, labels=labels.get(row.finding_id, ())) for row in rows]


def _unmatched_counts(
    session, sizes: Mapping[str, int], rules: RuleInventory
) -> Dict[str, int]:
    """How many alerts of each case no rule covers, for cases small enough to walk in a list."""
    small = [case_id for case_id, size in sizes.items() if size <= LIST_WALK_MAX]
    if not small:
        return {}
    in_cases = select(case_findings.c.finding_id).where(
        case_findings.c.case_id.in_(small)
    )
    labels = _labels_of(session, in_cases)
    context = func.jsonb_build_object(
        *(part for key in RULE_KEYS for part in (key, Finding.entity_context[key]))
    )
    counts = dict.fromkeys(small, 0)
    for row in session.execute(
        select(
            case_findings.c.case_id,
            Finding.finding_id,
            Finding.created_at,
            Finding.data_source,
            Finding.anomaly_score,
            context.label("entity_context"),
        )
        .join(Finding, Finding.finding_id == case_findings.c.finding_id)
        .where(case_findings.c.case_id.in_(small))
    ):
        finding = FindingFacts(
            finding_id=row.finding_id,
            created_at=row.created_at,
            data_source=row.data_source,
            anomaly_score=row.anomaly_score,
            entity_context=row.entity_context,
            labels=labels.get(row.finding_id, ()),
        )
        if step_coverage(finding, rules) is Coverage.NO_RULE:
            counts[row.case_id] += 1
    return counts


def _source_counts_by_case(session, ids) -> Dict[str, List[SourceCount]]:
    rows = session.execute(
        select(case_findings.c.case_id, Finding.data_source, func.count())
        .join(Finding, Finding.finding_id == case_findings.c.finding_id)
        .where(case_findings.c.case_id.in_(ids))
        .group_by(case_findings.c.case_id, Finding.data_source)
        .order_by(func.count().desc(), Finding.data_source)
    )
    counts: Dict[str, List[SourceCount]] = defaultdict(list)
    for case_id, source, alerts in rows:
        counts[case_id].append(SourceCount(source=source, alerts=alerts))
    return counts


def _case_facts(case: Case) -> CaseFacts:
    return CaseFacts(
        case_id=case.case_id,
        title=case.title,
        status=case.status,
        created_at=case.created_at,
        priority=case.priority,
        description=case.description or "",
        activities=case.activities or [],
    )


def _closure_facts(info: Optional[CaseClosureInfo]) -> Optional[ClosureFacts]:
    if info is None:
        return None
    return ClosureFacts(
        category=info.closure_category,
        channel=info.close_channel,
        closed_by=info.closed_by_text or info.closed_by,
        notes=info.closure_notes or info.executive_summary or info.root_cause,
    )


def _rule_inventory(session) -> RuleInventory:
    by_technique: Dict[str, List[str]] = defaultdict(list)
    rows = session.execute(
        select(DetectionRule.name, DetectionRule.techniques)
        .where(DetectionRule.status == ACTIVE_RULE)
        .order_by(DetectionRule.name)
    ).all()
    for name, techniques in rows:
        for technique in techniques or []:
            by_technique[technique.upper()].append(name)
    return RuleInventory(by_technique=dict(by_technique), loaded=len(rows))


def _install_facts() -> InstallFacts:
    config = get_integration_config("cloudflare") or {}
    return InstallFacts(
        cloudflare_enabled=is_integration_enabled("cloudflare"),
        cloudflare_token=bool(config.get("api_token")),
        execution_held=execution_held(),
    )


def _log_facts(session, case_ids: Sequence[str]) -> Dict[str, LogFacts]:
    rows = session.execute(
        select(
            LogEvent.case_id,
            func.count(),
            func.count().filter(LogEvent.loglm >= UNUSUAL_SCORE),
        )
        .where(LogEvent.case_id.in_(case_ids))
        .group_by(LogEvent.case_id)
    ).all()
    return {case_id: LogFacts(events, unusual) for case_id, events, unusual in rows}


def _hunt_verdicts(session, runs_by_case: Dict[str, List[str]]) -> Dict[str, list]:
    case_of = {run: case for case, runs in runs_by_case.items() for run in runs}
    if not case_of:
        return {}
    found: Dict[str, list] = defaultdict(list)
    rows = session.query(EpisodicVerdict).filter(
        EpisodicVerdict.investigation_id.in_(list(case_of))
    )
    for row in rows:
        found[case_of[row.investigation_id]].append(
            HuntVerdictFacts(
                outcome=row.outcome,
                statement=row.statement,
                rationale=row.rationale,
                concluded_at=_utc(row.concluded_at),
                investigation_id=row.investigation_id,
            )
        )
    return found


def _run_ids_by_case(session, case_ids: Sequence[str]) -> Dict[str, List[str]]:
    runs: Dict[str, List[str]] = defaultdict(list)
    for case_id, investigation_id in session.execute(
        select(Investigation.case_id, Investigation.investigation_id).where(
            Investigation.case_id.in_(case_ids)
        )
    ):
        runs[case_id].append(investigation_id)
    named = WorkflowRun.trigger_context["case_id"].astext
    for case_id, run_id in session.execute(
        select(named, WorkflowRun.run_id).where(
            named.in_(case_ids), WorkflowRun.deleted_at.is_(None)
        )
    ):
        runs[case_id].append(run_id)
    return runs


def _report(session, case_id: str) -> Optional[Report]:
    """The newest thing a completed run wrote about this case, in its own words."""
    candidates: List[Report] = []
    for row in list_case_runs(session, case_id):
        if row.status == COMPLETED and (row.result_summary or "").strip():
            candidates.append(
                Report(
                    text=row.result_summary,
                    origin="workflow_run",
                    ref=row.run_id,
                    at=_utc(row.finished_at) or _utc(row.started_at),
                )
            )
    for row in list_case_investigations(session, case_id):
        text = (row.summary or row.master_review_notes or "").strip()
        if row.status == COMPLETED and text:
            candidates.append(
                Report(
                    text=text,
                    origin="investigation",
                    ref=row.investigation_id,
                    at=_utc(row.completed_at),
                )
            )
    if not candidates:
        return None
    return max(candidates, key=lambda r: r.at or datetime.min)


def _iocs(session, case_id: str) -> List[IocFacts]:
    """A case's indicators that some source actually said something about."""
    rows = (
        session.query(CaseIOC)
        .filter(
            CaseIOC.case_id == case_id,
            CaseIOC.is_active.is_(True),
            CaseIOC.is_false_positive.is_(False),
            or_(
                CaseIOC.threat_level.isnot(None),
                CaseIOC.reputation_score.isnot(None),
                CaseIOC.enrichment_data.isnot(None),
            ),
        )
        .order_by(CaseIOC.ioc_id)
    )
    return [
        IocFacts(
            kind=row.ioc_type,
            value=row.value,
            threat_level=row.threat_level,
            source=row.source,
            confidence=row.confidence,
            reputation=row.reputation_score,
            context=row.context,
        )
        for row in rows
    ]


def _case_approvals(
    session, case_id: str, finding_ids: Sequence[str], run_ids: Sequence[str]
) -> List[PendingAction]:
    """Every approval that resolves to this case, by the rule Home's inbox uses."""
    parameters = ApprovalAction.parameters
    clauses = [
        parameters["case_id"].astext == case_id,
        parameters["case_ids"].contains([case_id]),
    ]
    if run_ids:
        clauses += [
            ApprovalAction.workflow_run_id.in_(run_ids),
            parameters["investigation_id"].astext.in_(run_ids),
        ]
    if finding_ids:
        clauses.append(
            ApprovalAction.evidence.has_any(cast(array(finding_ids), ARRAY(Text)))
        )
    ids = session.scalars(
        select(ApprovalAction.action_id)
        .where(or_(*clauses))
        .order_by(ApprovalAction.created_at.desc())
        .limit(APPROVALS_READ)
    ).all()
    service = ApprovalService()
    actions = [service.get_action(action_id) for action_id in ids]
    return [a for a in actions if a is not None and case_id in case_ids_for(a)]


def read_story(
    case_id: str,
    viewer: Viewer,
    steps_offset: int = 0,
    steps_limit: int = STEPS_PAGE,
) -> Optional[Story]:
    """The story with one page of its steps, or None when no such case. Raises
    ``NotAnIncident``."""
    if is_demo_mode():
        return None
    with unit_of_work() as session:
        case = session.get(Case, case_id, options=[noload(Case.findings)])
        if case is None:
            return None
        findings = _case_finding_facts(session, case_id)
        if len(findings) < MIN_FINDINGS:
            raise NotAnIncident(case_id, len(findings))
        run_ids = _run_ids_by_case(session, [case_id]).get(case_id, [])
        facts = StoryFacts(
            case=_case_facts(case),
            findings=findings,
            overlap=entity_overlap(findings),
            closure=_closure_facts(session.get(CaseClosureInfo, case_id)),
            hunt_verdicts=_hunt_verdicts(session, {case_id: run_ids}).get(case_id, []),
            report=_report(session, case_id),
            approvals=(
                _case_approvals(
                    session, case_id, [f.finding_id for f in findings], run_ids
                )
                if viewer.can_read_approvals
                else []
            ),
            iocs=_iocs(session, case_id),
            logs=_log_facts(session, [case_id]).get(case_id, LogFacts()),
            rules=_rule_inventory(session),
            install=_install_facts(),
            viewer=viewer,
        )
    return build_story(facts, steps_offset, steps_limit)


def list_incidents(*, open_only: bool, limit: int, viewer: Viewer) -> IncidentList:
    """Newest activity first. Each row is projected from the case's own story."""
    if is_demo_mode():
        return IncidentList(total=0, items=[])
    enough = (
        select(case_findings.c.case_id)
        .group_by(case_findings.c.case_id)
        .having(func.count() >= MIN_FINDINGS)
    )
    wanted = [Case.case_id.in_(enough)]
    if open_only:
        wanted.append(Case.status != CLOSED)
    pending: Optional[Dict[str, int]] = None
    if viewer.can_read_approvals:
        pending = defaultdict(int)
        for item in needs_you()["items"]:
            for one in item["case_ids"]:
                pending[one] += 1
    with unit_of_work() as session:
        total = session.scalar(select(func.count()).select_from(Case).where(*wanted))
        cases = (
            session.query(Case)
            .options(noload(Case.findings))
            .filter(*wanted)
            .order_by(Case.updated_at.desc(), Case.case_id.desc())
            .limit(limit)
            .all()
        )
        ids = [case.case_id for case in cases]
        if not ids:
            return IncidentList(total=total or 0, items=[])
        closures = {
            row.case_id: row
            for row in session.query(CaseClosureInfo).filter(
                CaseClosureInfo.case_id.in_(ids)
            )
        }
        verdicts = _hunt_verdicts(session, _run_ids_by_case(session, ids))
        logs = _log_facts(session, ids)
        rules = _rule_inventory(session)
        sources = _source_counts_by_case(session, ids)
        sizes = {
            case_id: sum(count.alerts for count in counts)
            for case_id, counts in sources.items()
        }
        unmatched = _unmatched_counts(session, sizes, rules)
        items = [
            IncidentRow(
                case_id=case.case_id,
                title=case.title,
                status=case.status,
                priority=case.priority,
                opened_at=case.created_at,
                alerts=sizes.get(case.case_id, 0),
                sources=sources.get(case.case_id, []),
                verdict=verdict_of(
                    StoryFacts(
                        case=_case_facts(case),
                        findings=[],
                        closure=_closure_facts(closures.get(case.case_id)),
                        hunt_verdicts=verdicts.get(case.case_id, []),
                        logs=LogFacts(),
                        rules=rules,
                    )
                ),
                unmatched_steps=unmatched.get(case.case_id),
                log_events=logs.get(case.case_id, LogFacts()).events,
                pending_approvals=(
                    None if pending is None else pending.get(case.case_id, 0)
                ),
            )
            for case in cases
        ]
    return IncidentList(total=total or 0, items=items)
