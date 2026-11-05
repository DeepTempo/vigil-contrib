"""Per-kind policies in the database: read the record, adopt, revoke, demote, close, overturn.

``mode`` moves only through ``KindPolicy.move_to``. The one event written without a move is
an overturn on a policy already asking, which has nothing left to move.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy import text as sql_text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from core.audit import trail
from core.autonomy.track_record import (
    AUTO_SEVERITIES,
    DAILY_DAYS,
    POLICY_LIFETIME,
    POLICY_REASON_PREFIX,
    WINDOW,
    Adoption,
    CaseClosure,
    ImportedTicket,
    KindMode,
    Label,
    NoiseMark,
    Overturn,
    PolicyEventKind,
    SeenAlert,
    TrackRecord,
    Verdict,
    build_records,
    daily_counts,
    demotion_due,
    imported_labels,
    is_vigil_close,
    mode_of,
    person_labels,
    stay_reason,
    why_not,
)
from core.cases import case_trail
from core.cases.closure import (
    CHANNEL_COOKIE,
    ClosedByKind,
    ClosureCategory,
)
from core.coldstart import store as coldstart_store
from core.coldstart.baseline import (
    MIN_STRONG_LABELS,
    alert_from_finding,
    parse_time,
    signature_for,
)
from core.coldstart.store import group_key
from core.coldstart.tickets import outcomes_from
from core.response.ceiling import execution_held
from core.storage.config_service import get_config_service
from core.storage.ip_exclusion_repository import exclusion_view_filter
from core.storage.models import (
    Case,
    CaseClosureInfo,
    ColdStartRun,
    Finding,
    KindPolicy,
    KindPolicyEvent,
    PolicyMode,
    User,
)
from core.storage.models.base import case_findings
from core.storage.models.cold_start import RunStatus
from core.storage.unit_of_work import unit_of_work

logger = logging.getLogger(__name__)

VIGIL_ACTOR = "vigil"
SETTING_KEY = "kind_autonomy.settings"
_PROBE_SOURCE = "probe"
_FINDING_COLUMNS = (
    Finding.finding_id,
    Finding.data_source,
    Finding.title,
    Finding.severity,
    Finding.timestamp,
    Finding.created_at,
    Finding.entity_context,
)


class KindNotFound(Exception):
    pass


class NotEligible(Exception):
    def __init__(self, reasons: List[Dict[str, str]]):
        super().__init__(" ".join(r["why"] for r in reasons))
        self.reasons = reasons


class NotClosing(Exception):
    pass


class NotClosedByPolicy(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _naive(moment: datetime) -> datetime:
    return moment.astimezone(timezone.utc).replace(tzinfo=None)


def _iso(moment: Optional[datetime]) -> Optional[str]:
    return moment.isoformat() if moment else None


def close_enabled() -> bool:
    """Raises when the read fails, so a caller cannot take "unread" for "on"."""
    value = get_config_service().read_system_config(SETTING_KEY)
    return isinstance(value, dict) and value.get("close_enabled") is True


def set_close_enabled(enabled: bool, user_id: str) -> bool:
    return get_config_service(user_id=user_id).set_system_config(
        SETTING_KEY,
        {"close_enabled": enabled},
        description="Whether the daemon acts on adopted per-kind close policies",
        config_type="autonomy",
        change_reason=f"Per-kind closing turned {'on' if enabled else 'off'}",
    )


def _signature_of(row: Any) -> str:
    """The stored row's kind. The time only decides whether the helper returns at all."""
    alert = alert_from_finding(
        {
            "finding_id": row.finding_id,
            "data_source": row.data_source,
            "title": row.title,
            "severity": row.severity,
            "timestamp": row.timestamp or row.created_at,
            "entity_context": row.entity_context,
        }
    )
    return signature_for(alert)


def _seen_alerts(session: Session, since: datetime) -> List[SeenAlert]:
    cutoff = _naive(since)
    query = select(
        *_FINDING_COLUMNS,
        Finding.noise_marked_at,
        Finding.noise_marked_by,
        Finding.noise_marked_by_kind,
        Finding.noise_reason,
    ).where(
        Finding.data_source != _PROBE_SOURCE,
        exclusion_view_filter("hide"),
        or_(
            func.coalesce(Finding.timestamp, Finding.created_at) >= cutoff,
            Finding.noise_marked_at >= cutoff,
        ),
    )
    alerts: List[SeenAlert] = []
    for row in session.execute(query):
        mark = (
            NoiseMark(
                parse_time(row.noise_marked_at),
                row.noise_marked_by,
                row.noise_marked_by_kind,
                row.noise_reason,
            )
            if row.noise_marked_at
            else None
        )
        alerts.append(
            SeenAlert(
                finding_id=row.finding_id,
                signature=_signature_of(row),
                severity=str(row.severity or "unknown").lower(),
                observed_at=parse_time(row.timestamp or row.created_at),
                mark=mark,
            )
        )
    return alerts


def _closures(
    session: Session, since: datetime, only_real: bool = False
) -> List[CaseClosure]:
    query = (
        select(
            CaseClosureInfo.case_id,
            CaseClosureInfo.closure_category,
            CaseClosureInfo.close_channel,
            CaseClosureInfo.closed_by,
            CaseClosureInfo.closed_at,
        )
        .join(Case, Case.case_id == CaseClosureInfo.case_id)
        .where(Case.status == "closed", CaseClosureInfo.closed_at >= _naive(since))
    )
    if only_real:
        query = query.where(
            CaseClosureInfo.closure_category == ClosureCategory.RESOLVED.value,
            CaseClosureInfo.close_channel == CHANNEL_COOKIE,
        )
    closed = session.execute(query).all()
    if not closed:
        return []
    findings: Dict[str, List[Tuple[str, str]]] = {}
    members = session.execute(
        select(case_findings.c.case_id, *_FINDING_COLUMNS)
        .join(Finding, Finding.finding_id == case_findings.c.finding_id)
        .where(case_findings.c.case_id.in_([row.case_id for row in closed]))
    )
    for row in members:
        findings.setdefault(row.case_id, []).append(
            (row.finding_id, _signature_of(row))
        )
    return [
        CaseClosure(
            case_id=row.case_id,
            category=row.closure_category,
            channel=row.close_channel,
            closed_by=row.closed_by,
            closed_at=parse_time(row.closed_at),
            finding_ids=frozenset(f for f, _ in findings.get(row.case_id, ())),
            signatures=frozenset(s for _, s in findings.get(row.case_id, ())),
        )
        for row in closed
    ]


def _overturns(session: Session, signature: Optional[str] = None) -> List[Overturn]:
    query = select(KindPolicyEvent).where(
        KindPolicyEvent.evidence["event"].astext == PolicyEventKind.OVERTURN.value
    )
    if signature is not None:
        query = query.where(KindPolicyEvent.signature == signature)
    return [
        Overturn(event.signature, str(event.evidence.get("finding_id")), event.at)
        for event in session.scalars(query)
    ]


def _live_run_history(session: Session) -> Tuple[List[ImportedTicket], frozenset]:
    """Tickets and not-benign reviews from the live run. Any other run counts for nothing."""
    run = session.execute(
        select(ColdStartRun.run_id, ColdStartRun.baseline).where(
            ColdStartRun.status == RunStatus.LIVE
        )
    ).first()
    if run is None:
        return [], frozenset()
    outcomes, _ = outcomes_from(
        coldstart_store.load_tickets(run.run_id),
        {a.alert_id: a for a in coldstart_store.load_alerts(run.run_id)},
    )
    marked = frozenset(
        signature
        for signature, row in ((run.baseline or {}).get("signatures") or {}).items()
        if row.get("marked_not_benign")
    )
    return (
        [
            ImportedTicket(
                o.signature, str(o.ticket_id), o.disposition, parse_time(o.closed_at)
            )
            for o in outcomes
        ],
        marked,
    )


def _service_accounts(session: Session) -> frozenset:
    return frozenset(
        session.scalars(select(User.user_id).where(User.service_account.is_(True)))
    )


def _adoption(session: Session, signature: str) -> Optional[Adoption]:
    event = session.scalar(
        select(KindPolicyEvent)
        .where(
            KindPolicyEvent.signature == signature,
            KindPolicyEvent.to_mode == PolicyMode.CLOSE,
        )
        .order_by(KindPolicyEvent.id.desc())
        .limit(1)
    )
    if event is None:
        return None
    return Adoption(event.id, event.actor, event.reason, event.at, event.clean_labels)


def _real_after(session: Session, signature: str, since: datetime) -> List[Label]:
    labels, _ = person_labels(
        (), _closures(session, since, only_real=True), _overturns(session, signature)
    )
    return [label for label in labels if label.signature == signature]


def _settle(
    session: Session,
    policy: KindPolicy,
    now: datetime,
    imported: Iterable[Label] = (),
) -> Optional[Adoption]:
    """Demote a locked policy on close if it must fall back. Its adoption when it stays."""
    adoption = _adoption(session, policy.signature)
    if adoption is None:
        return None
    real = _real_after(session, policy.signature, adoption.at)
    real.extend(label for label in imported if label.signature == policy.signature)
    due = demotion_due(adoption, real, now)
    if due is None:
        return adoption
    policy.move_to(
        PolicyMode.ASK,
        actor=VIGIL_ACTOR,
        reason=due.reason,
        evidence={
            "event": due.kind.value,
            "policy_id": adoption.policy_id,
            **due.evidence,
        },
        clean_labels=adoption.clean_labels,
    )
    session.flush()
    logger.warning("Kind policy %s: %s", adoption.policy_id, due.kind.value)
    return None


def _records(
    session: Session,
    now: datetime,
    history: Optional[Tuple[List[ImportedTicket], frozenset]] = None,
) -> Tuple[Dict[str, TrackRecord], List[SeenAlert]]:
    since = now - WINDOW
    alerts = _seen_alerts(session, since)
    imported, marked = history or _live_run_history(session)
    records = build_records(
        alerts,
        _closures(session, since),
        imported,
        _overturns(session),
        now,
        _service_accounts(session),
        marked,
    )
    return records, alerts


def _labels_of(session: Session, ids: Iterable[str]) -> Dict[str, str]:
    wanted = {i for i in ids if i and i != VIGIL_ACTOR}
    if not wanted:
        return {}
    rows = session.execute(
        sql_text(
            "SELECT principal_id, label FROM public.principals "
            "WHERE principal_id = ANY(:ids)"
        ),
        {"ids": list(wanted)},
    ).all()
    return {pid: label.strip() for pid, label in rows if label and label.strip()}


def _track_view(record: TrackRecord) -> Dict[str, Any]:
    return {
        "alerts_seen": record.alerts_seen,
        "reviewed": record.reviewed,
        "agreed": record.clean_labels,
        "real": record.real_labels,
        "closed_here_benign": record.benign_here,
        "closed_here_real": record.real_here,
        "imported_benign": record.imported_benign,
        "imported_real": record.imported_real,
        "overturned": record.overturned,
        "closed_by_vigil": record.closed_by_vigil,
        "above_scope": record.above_scope,
        "bulk_ignored": record.bulk_ignored,
        "last_real_at": _iso(record.last_real_at),
        "miss_bound": record.miss_bound,
    }


def _event_kind(evidence: Mapping[str, Any]) -> Optional[PolicyEventKind]:
    try:
        return PolicyEventKind(evidence.get("event"))
    except ValueError:
        return None


def _kind_view(
    session: Session, policy: Optional[KindPolicy], record: TrackRecord
) -> Dict[str, Any]:
    source, _, title = record.signature.partition("|")
    close_on = policy is not None and policy.mode is PolicyMode.CLOSE
    adoption = _adoption(session, record.signature) if policy is not None else None
    latest = (
        session.scalar(
            select(KindPolicyEvent)
            .where(KindPolicyEvent.signature == record.signature)
            .order_by(KindPolicyEvent.id.desc())
            .limit(1)
        )
        if policy is not None
        else None
    )
    last_kind = _event_kind(latest.evidence) if latest else None
    reasons = why_not(record)
    names = _labels_of(session, [adoption.actor] if adoption else [])
    return {
        "key": group_key(record.signature),
        "signature": record.signature,
        "source": source,
        "title": title,
        "mode": mode_of(close_on, last_kind).value,
        "mode_reason": latest.reason if latest and not close_on else None,
        "track_record": _track_view(record),
        "eligible": not reasons,
        "why_not": reasons,
        "adoption": (
            {
                "policy_id": adoption.policy_id,
                "by": adoption.actor,
                "by_label": names.get(adoption.actor),
                "at": _iso(adoption.at),
                "expires_at": _iso(adoption.expires_at),
                "reason": adoption.reason,
                "clean_labels": adoption.clean_labels,
            }
            if adoption and close_on
            else None
        ),
    }


def _sort_key(view: Mapping[str, Any]) -> Tuple[Any, ...]:
    track = view["track_record"]
    return (
        view["mode"] != KindMode.CLOSE.value,
        not view["eligible"],
        -track["reviewed"],
        -track["alerts_seen"],
        view["signature"],
    )


def kinds_view(session: Session, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Every kind with its record. Settles first, so a suspension shows on this read."""
    now = now or _now()
    history = _live_run_history(session)
    imported_real = [
        label for label in imported_labels(history[0]) if label.verdict is Verdict.REAL
    ]
    closing = session.scalars(
        select(KindPolicy).where(KindPolicy.mode == PolicyMode.CLOSE).with_for_update()
    ).all()
    for policy in closing:
        _settle(session, policy, now, imported_real)
    policies = {p.signature: p for p in session.scalars(select(KindPolicy))}
    records, alerts = _records(session, now, history)
    for signature in policies:
        records.setdefault(signature, TrackRecord(signature=signature))
    kinds = sorted(
        (
            _kind_view(session, policies.get(signature), record)
            for signature, record in records.items()
        ),
        key=_sort_key,
    )
    closes_now = sum(k["mode"] == KindMode.CLOSE.value for k in kinds)
    return {
        "close_enabled": close_enabled(),
        "bar": MIN_STRONG_LABELS,
        "window_days": WINDOW.days,
        "lifetime_days": POLICY_LIFETIME.days,
        "auto_severities": sorted(AUTO_SEVERITIES),
        "summary": {
            "kinds": len(kinds),
            "closing": closes_now,
            "closed_by_vigil": sum(r.closed_by_vigil for r in records.values()),
            "overturned": sum(r.overturned for r in records.values()),
        },
        "daily": daily_counts(alerts, now.date(), DAILY_DAYS),
        "kinds": kinds,
    }


def _signature_from_policies(session: Session, key: str) -> Optional[str]:
    for signature in session.scalars(select(KindPolicy.signature)):
        if group_key(signature) == key:
            return signature
    return None


def _locked_policy(session: Session, signature: str) -> KindPolicy:
    session.execute(
        insert(KindPolicy)
        .values(signature=signature, mode=PolicyMode.ASK)
        .on_conflict_do_nothing(index_elements=["signature"])
    )
    return session.scalar(
        select(KindPolicy).where(KindPolicy.signature == signature).with_for_update()
    )


def adopt(
    session: Session, key: str, actor: str, reason: str, now: Optional[datetime] = None
) -> Dict[str, Any]:
    """A person adopts close, or renews a live adoption for another full lifetime."""
    now = now or _now()
    records, _ = _records(session, now)
    record = next((r for s, r in records.items() if group_key(s) == key), None)
    if record is None:
        raise KindNotFound(key)
    reasons = why_not(record)
    if reasons:
        raise NotEligible(reasons)
    policy = _locked_policy(session, record.signature)
    if policy.mode is PolicyMode.CLOSE and _settle(session, policy, now):
        policy.move_to(
            PolicyMode.ASK,
            actor=actor,
            reason="Re-adopted by a person.",
            evidence={"event": PolicyEventKind.RENEW.value},
            clean_labels=record.clean_labels,
        )
    if policy.mode is PolicyMode.ASK:
        policy.move_to(
            PolicyMode.CLOSE,
            actor=actor,
            reason=reason,
            evidence={
                "event": PolicyEventKind.ADOPT.value,
                "miss_bound": record.miss_bound,
                "closed_here_benign": record.benign_here,
                "imported_benign": record.imported_benign,
                "window_days": WINDOW.days,
            },
            clean_labels=record.clean_labels,
        )
    session.flush()
    return {
        "key": key,
        "mode": KindMode.CLOSE.value,
        "policy_id": _adoption(session, record.signature).policy_id,
    }


def revoke(
    session: Session, key: str, actor: str, reason: str, now: Optional[datetime] = None
) -> Dict[str, Any]:
    signature = _signature_from_policies(session, key)
    if signature is None:
        raise KindNotFound(key)
    now = now or _now()
    policy = _locked_policy(session, signature)
    adoption = (
        _settle(session, policy, now) if policy.mode is PolicyMode.CLOSE else None
    )
    if adoption is None:
        raise NotClosing(key)
    policy.move_to(
        PolicyMode.ASK,
        actor=actor,
        reason=reason,
        evidence={
            "event": PolicyEventKind.REVOKE.value,
            "policy_id": adoption.policy_id,
        },
        clean_labels=adoption.clean_labels,
    )
    session.flush()
    return {"key": key, "mode": KindMode.ASK.value}


def events_view(session: Session, key: str) -> List[Dict[str, Any]]:
    signature = _signature_from_policies(session, key)
    if signature is None:
        return []
    events = session.scalars(
        select(KindPolicyEvent)
        .where(KindPolicyEvent.signature == signature)
        .order_by(KindPolicyEvent.id.desc())
    ).all()
    names = _labels_of(session, [e.actor for e in events])
    return [
        {
            "id": e.id,
            "event": e.evidence.get("event"),
            "from_mode": e.from_mode.value,
            "to_mode": e.to_mode.value,
            "actor": e.actor,
            "actor_label": "Vigil" if e.actor == VIGIL_ACTOR else names.get(e.actor),
            "reason": e.reason,
            "evidence": e.evidence,
            "clean_labels": e.clean_labels,
            "at": _iso(e.at),
        }
        for e in events
    ]


def _policy_reasons(session: Session, signature: str) -> List[str]:
    ids = session.scalars(
        select(KindPolicyEvent.id).where(
            KindPolicyEvent.signature == signature,
            KindPolicyEvent.to_mode == PolicyMode.CLOSE,
        )
    )
    return [f"{POLICY_REASON_PREFIX}{i}" for i in ids]


def closed_view(
    session: Session, key: str, limit: int = 25, sample: bool = False
) -> Dict[str, Any]:
    """What this kind's policies closed. ``sample`` draws at random, for a spot check."""
    signature = _signature_from_policies(session, key)
    reasons = _policy_reasons(session, signature) if signature else []
    if not reasons:
        return {"total": 0, "alerts": []}
    match = (
        Finding.noise_marked_by_kind == ClosedByKind.AGENT.value,
        Finding.noise_reason.in_(reasons),
    )
    total = session.scalar(select(func.count()).select_from(Finding).where(*match))
    order = func.random() if sample else Finding.noise_marked_at.desc()
    rows = session.execute(
        select(
            Finding.finding_id,
            Finding.title,
            Finding.severity,
            Finding.timestamp,
            Finding.noise_marked_at,
            Finding.noise_reason,
        )
        .where(*match)
        .order_by(order)
        .limit(limit)
    )
    return {
        "total": total,
        "alerts": [
            {
                "finding_id": row.finding_id,
                "title": row.title,
                "severity": row.severity,
                "observed_at": _iso(parse_time(row.timestamp)),
                "closed_at": _iso(parse_time(row.noise_marked_at)),
                "policy_reason": row.noise_reason,
            }
            for row in rows
        ],
    }


def overturn(
    session: Session,
    key: str,
    finding_id: str,
    actor: str,
    username: str,
    reason: str,
) -> Dict[str, Any]:
    """A person says a closure was wrong: the alert goes back, and it is a real closure."""
    signature = _signature_from_policies(session, key)
    if signature is None:
        raise KindNotFound(key)
    policy = _locked_policy(session, signature)
    finding = session.get(Finding, finding_id, with_for_update=True)
    mark = (
        NoiseMark(
            finding.noise_marked_at,
            finding.noise_marked_by,
            finding.noise_marked_by_kind,
            finding.noise_reason,
        )
        if finding is not None and finding.noise_marked_at
        else None
    )
    if not is_vigil_close(mark) or mark.reason not in _policy_reasons(
        session, signature
    ):
        raise NotClosedByPolicy(finding_id)
    case_trail.append_or_legacy(
        session,
        action=trail.ACTION_FINDING_NOISE_CLEAR,
        signed_in=username,
        case_id=None,
        operator_text=reason,
        ids=lambda: {"finding_id": finding_id},
    )
    finding.noise_marked_at = None
    finding.noise_marked_by = None
    finding.noise_marked_by_kind = None
    finding.noise_reason = None
    evidence = {
        "event": PolicyEventKind.OVERTURN.value,
        "finding_id": finding_id,
        "policy_reason": mark.reason,
    }
    if policy.mode is PolicyMode.CLOSE:
        adoption = _adoption(session, signature)
        policy.move_to(
            PolicyMode.ASK,
            actor=actor,
            reason=reason,
            evidence=evidence,
            clean_labels=adoption.clean_labels,
        )
    else:
        session.add(
            KindPolicyEvent(
                signature=signature,
                from_mode=PolicyMode.ASK,
                to_mode=PolicyMode.ASK,
                actor=actor,
                reason=reason,
                evidence=evidence,
                clean_labels=0,
            )
        )
    session.flush()
    return {"finding_id": finding_id, "mode": KindMode.SUSPENDED.value}


def _on_a_case(session: Session, finding_id: str) -> bool:
    return (
        session.scalar(
            select(case_findings.c.case_id)
            .where(case_findings.c.finding_id == finding_id)
            .limit(1)
        )
        is not None
    )


def close_if_adopted(
    finding: Mapping[str, Any],
    source_severity: Any,
    now: Optional[datetime] = None,
) -> Optional[int]:
    """Mark one triaged alert noise if a live policy says so. The policy id when it did.

    Writes the noise columns and nothing else. Containment and approvals are not reachable
    from here. Every "not sure" returns None, which leaves the alert in the queue.
    """
    finding_id = finding.get("finding_id")
    if not finding_id or finding.get("data_source") == _PROBE_SOURCE:
        return None
    if stay_reason(finding, source_severity):
        return None
    if not close_enabled() or execution_held():
        return None
    now = now or _now()
    with unit_of_work() as session:
        row = session.get(Finding, finding_id)
        if row is None:
            return None
        # The policy's lock comes first, the order an overturn takes them in.
        policy = session.scalar(
            select(KindPolicy)
            .where(
                KindPolicy.signature == _signature_of(row),
                KindPolicy.mode == PolicyMode.CLOSE,
            )
            .with_for_update()
        )
        adoption = _settle(session, policy, now) if policy is not None else None
        if adoption is None:
            return None
        row = session.get(
            Finding, finding_id, with_for_update=True, populate_existing=True
        )
        if (
            row.noise_marked_at is not None
            or str(row.severity or "").lower() not in AUTO_SEVERITIES
            or _on_a_case(session, finding_id)
        ):
            return None
        reason = f"{POLICY_REASON_PREFIX}{adoption.policy_id}"
        row.noise_marked_at = _naive(now)
        row.noise_marked_by = VIGIL_ACTOR
        row.noise_marked_by_kind = ClosedByKind.AGENT.value
        row.noise_reason = reason
        case_trail.append_or_legacy(
            session,
            action=trail.ACTION_FINDING_NOISE_MARK,
            signed_in=None,
            case_id=None,
            operator_text=reason,
            ids=lambda: {"finding_id": finding_id},
        )
        return adoption.policy_id
