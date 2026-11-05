"""Per-kind policies in the database: read the record, adopt, revoke, demote, close, overturn.

``mode`` moves only through ``KindPolicy.move_to``. The one event written without a move is
an overturn on a policy already asking, which has nothing left to move.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from sqlalchemy import and_, func, literal_column, select
from sqlalchemy import text as sql_text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from core.audit import trail
from core.autonomy.track_record import (
    ABOVE_SCOPE,
    AUTO_SEVERITIES,
    DAILY_DAYS,
    POLICY_LIFETIME,
    POLICY_REASON_PREFIX,
    WINDOW,
    Adoption,
    AlertTally,
    CaseClosure,
    ImportedTally,
    KindMode,
    Label,
    MarkedAlert,
    NoiseMark,
    Origin,
    Overturn,
    PolicyEventKind,
    TrackRecord,
    Verdict,
    build_records,
    daily_counts,
    demotion_due,
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
    BENIGN_DISPOSITIONS,
    ENTITY_KEYS,
    MIN_STRONG_LABELS,
    TRUE_POSITIVE,
    parse_time,
    stored_signature,
)
from core.coldstart.store import group_key
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
from core.storage.source_rule import source_rule_column, source_rule_of
from core.storage.unit_of_work import unit_of_work

logger = logging.getLogger(__name__)

VIGIL_ACTOR = "vigil"
SETTING_KEY = "kind_autonomy.settings"
_PROBE_SOURCE = "probe"
# Past any of these, the read stops and every kind says its record is incomplete.
MAX_ALERT_GROUPS = 20_000
MAX_PERSON_MARKS = 20_000
MAX_CLOSURES = 20_000
KINDS_SHOWN = 500

# Masking needs a finding's entities only when its title names one of them. Grouping on them
# otherwise would keep one row per address, which is every row on a large install.
_ENTITIES_IN_TITLE = literal_column("""
    CASE WHEN EXISTS (
      SELECT 1
      FROM jsonb_each(
        CASE jsonb_typeof(findings.entity_context)
          WHEN 'object' THEN findings.entity_context ELSE '{}'::jsonb END
      ) AS field(key, value)
      CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE jsonb_typeof(field.value)
          WHEN 'array' THEN field.value
          WHEN 'string' THEN jsonb_build_array(field.value)
          ELSE '[]'::jsonb END
      ) AS entity(name)
      WHERE field.key IN (%s)
        AND entity.name <> ''
        AND position(lower(entity.name) IN lower(findings.title)) > 0
    ) THEN findings.entity_context END
    """ % ", ".join(f"'{key}'" for key in ENTITY_KEYS)).label("entities")
_CLOSED_BY_POLICY = and_(
    Finding.noise_marked_by_kind == ClosedByKind.AGENT.value,
    Finding.noise_reason.like(f"{POLICY_REASON_PREFIX}%"),
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


def _in_view() -> Tuple[Any, ...]:
    return (Finding.data_source != _PROBE_SOURCE, exclusion_view_filter("hide"))


def _alert_tallies(session: Session, since: datetime) -> Tuple[List[AlertTally], bool]:
    """The window's alerts counted in the database, with whether the read stopped early."""
    rule = source_rule_column(Finding.entity_context).label("rule")
    rows = session.execute(
        select(
            Finding.data_source,
            Finding.title,
            _ENTITIES_IN_TITLE,
            rule,
            func.count().label("seen"),
            func.count()
            .filter(func.lower(Finding.severity).in_(sorted(ABOVE_SCOPE)))
            .label("above_scope"),
            func.count().filter(_CLOSED_BY_POLICY).label("closed_by_vigil"),
        )
        .where(
            *_in_view(),
            func.coalesce(Finding.timestamp, Finding.created_at) >= _naive(since),
        )
        .group_by(Finding.data_source, Finding.title, sql_text("3"), sql_text("4"))
        .limit(MAX_ALERT_GROUPS + 1)
    ).all()
    return [
        AlertTally(
            stored_signature(row.data_source, row.title, row.entities),
            row.rule,
            row.seen,
            row.above_scope,
            row.closed_by_vigil,
        )
        for row in rows[:MAX_ALERT_GROUPS]
    ], len(rows) > MAX_ALERT_GROUPS


def _person_marks(session: Session, since: datetime) -> Tuple[List[MarkedAlert], bool]:
    rows = session.execute(
        select(
            Finding.finding_id,
            Finding.data_source,
            Finding.title,
            _ENTITIES_IN_TITLE,
            Finding.noise_marked_at,
            Finding.noise_marked_by,
            Finding.noise_marked_by_kind,
            Finding.noise_reason,
        )
        .where(
            *_in_view(),
            Finding.noise_marked_by_kind == ClosedByKind.PERSON.value,
            Finding.noise_marked_at >= _naive(since),
        )
        .order_by(Finding.noise_marked_at.desc())
        .limit(MAX_PERSON_MARKS + 1)
    ).all()
    return [
        MarkedAlert(
            row.finding_id,
            stored_signature(row.data_source, row.title, row.entities),
            NoiseMark(
                parse_time(row.noise_marked_at),
                row.noise_marked_by,
                row.noise_marked_by_kind,
                row.noise_reason,
            ),
        )
        for row in rows[:MAX_PERSON_MARKS]
    ], len(rows) > MAX_PERSON_MARKS


def _daily_rows(session: Session, today: Any) -> List[Tuple[Any, bool, int]]:
    observed = func.coalesce(Finding.timestamp, Finding.created_at)
    day = func.date(observed)
    by_policy = func.coalesce(_CLOSED_BY_POLICY, False)
    first = datetime.combine(today, datetime.min.time()) - timedelta(days=DAILY_DAYS)
    return [
        tuple(row)
        for row in session.execute(
            select(day, by_policy, func.count())
            .where(*_in_view(), observed >= first)
            .group_by(day, by_policy)
        )
    ]


def _closures(session: Session, since: datetime) -> Tuple[List[CaseClosure], bool]:
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
        .order_by(CaseClosureInfo.closed_at.desc())
        .limit(MAX_CLOSURES + 1)
    )
    rows = session.execute(query).all()
    closed = rows[:MAX_CLOSURES]
    if not closed:
        return [], False
    ids = [row.case_id for row in closed]
    signatures: Dict[str, set] = {}
    for row in session.execute(
        select(
            case_findings.c.case_id,
            Finding.data_source,
            Finding.title,
            _ENTITIES_IN_TITLE,
        )
        .join(Finding, Finding.finding_id == case_findings.c.finding_id)
        .where(case_findings.c.case_id.in_(ids))
        .distinct()
    ):
        signatures.setdefault(row.case_id, set()).add(
            stored_signature(row.data_source, row.title, row.entities)
        )
    # Only a person's own mark could count twice, so only those ids matter.
    marked: Dict[str, set] = {}
    for case_id, finding_id in session.execute(
        select(case_findings.c.case_id, case_findings.c.finding_id)
        .join(Finding, Finding.finding_id == case_findings.c.finding_id)
        .where(
            case_findings.c.case_id.in_(ids),
            Finding.noise_marked_by_kind == ClosedByKind.PERSON.value,
        )
    ):
        marked.setdefault(case_id, set()).add(finding_id)
    return [
        CaseClosure(
            case_id=row.case_id,
            category=row.closure_category,
            channel=row.close_channel,
            closed_by=row.closed_by,
            closed_at=parse_time(row.closed_at),
            finding_ids=frozenset(marked.get(row.case_id, ())),
            signatures=frozenset(signatures.get(row.case_id, ())),
        )
        for row in closed
    ], len(rows) > MAX_CLOSURES


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


def _live_run(session: Session) -> Optional[Any]:
    """Any run but the live one counts for nothing."""
    return session.execute(
        select(ColdStartRun.run_id, ColdStartRun.live_at).where(
            ColdStartRun.status == RunStatus.LIVE
        )
    ).first()


def _imported(
    session: Session, since: datetime
) -> Tuple[List[ImportedTally], frozenset]:
    """The live run's tickets per kind in the window, and the kinds marked not benign."""
    run = _live_run(session)
    if run is None:
        return [], frozenset()
    by_kind: Dict[str, Dict[str, Any]] = {}
    for row in coldstart_store.ticket_counts(session, run.run_id, since):
        kind = by_kind.setdefault(
            row.signature, {"benign": 0, "real": 0, "last_real_at": None}
        )
        if row.disposition == TRUE_POSITIVE:
            kind["real"] += row.tickets
            kind["last_real_at"] = row.last_closed_at
        elif row.disposition in BENIGN_DISPOSITIONS:
            kind["benign"] += row.tickets
    tallies = [
        ImportedTally(signature, kind["benign"], kind["real"], kind["last_real_at"])
        for signature, kind in by_kind.items()
    ]
    return tallies, coldstart_store.kinds_marked_not_benign(session, run.run_id)


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
    return Adoption(
        event.id,
        event.actor,
        event.reason,
        event.at,
        event.clean_labels,
        (event.evidence or {}).get("rule_id"),
    )


def _first_real_closure(
    session: Session, signature: str, since: datetime
) -> Optional[Label]:
    """The earliest case a person closed real with an alert of this kind, read in pages,
    so a close stops at the first one instead of loading them all."""
    source = signature.partition("|")[0]
    rows = session.execute(
        select(
            CaseClosureInfo.case_id,
            CaseClosureInfo.closed_at,
            Finding.title,
            _ENTITIES_IN_TITLE,
        )
        .select_from(CaseClosureInfo)
        .join(Case, Case.case_id == CaseClosureInfo.case_id)
        .join(case_findings, case_findings.c.case_id == Case.case_id)
        .join(Finding, Finding.finding_id == case_findings.c.finding_id)
        .where(
            Case.status == "closed",
            CaseClosureInfo.closure_category == ClosureCategory.RESOLVED.value,
            CaseClosureInfo.close_channel == CHANNEL_COOKIE,
            CaseClosureInfo.closed_at >= _naive(since),
            Finding.data_source == source,
        )
        .distinct()
        .order_by(CaseClosureInfo.closed_at),
        execution_options={"yield_per": 200},
    )
    try:
        for row in rows:
            if stored_signature(source, row.title, row.entities) == signature:
                return Label(
                    signature,
                    Verdict.REAL,
                    Origin.CASE,
                    row.case_id,
                    parse_time(row.closed_at),
                )
        return None
    finally:
        rows.close()


def _imported_real(
    session: Session, signature: str, adopted: datetime, now: datetime
) -> List[Label]:
    """What the live run says against this kind since adoption. A run that went live after
    adoption brings tickets nobody weighed then, however long ago they closed."""
    run = _live_run(session)
    if run is None:
        return []
    labels = []
    if coldstart_store.kind_marked_not_benign(session, run.run_id, signature):
        labels.append(Label(signature, Verdict.REAL, Origin.IMPORTED, "review", now))
    newer_run = run.live_at is not None and run.live_at > adopted
    ticket = coldstart_store.first_true_positive(
        session, run.run_id, signature, None if newer_run else adopted
    )
    if ticket is not None:
        closed = parse_time(ticket.closed_at)
        labels.append(
            Label(
                signature,
                Verdict.REAL,
                Origin.IMPORTED,
                ticket.external_id,
                max(closed, run.live_at) if newer_run else closed,
            )
        )
    return labels


def _real_after(
    session: Session, signature: str, adopted: datetime, now: datetime
) -> List[Label]:
    labels, _ = person_labels((), (), _overturns(session, signature))
    closure = _first_real_closure(session, signature, adopted)
    return [
        *labels,
        *([closure] if closure else []),
        *_imported_real(session, signature, adopted, now),
    ]


def _settle(session: Session, policy: KindPolicy, now: datetime) -> Optional[Adoption]:
    """Demote a locked policy on close if it must fall back. Its adoption when it stays.
    A failed read raises, so a caller about to close leaves the alert in the queue."""
    adoption = _adoption(session, policy.signature)
    if adoption is None:
        return None
    real = _real_after(session, policy.signature, adoption.at, now)
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


def _records(session: Session, now: datetime) -> Dict[str, TrackRecord]:
    since = now - WINDOW
    tallies, more_alerts = _alert_tallies(session, since)
    marks, more_marks = _person_marks(session, since)
    closures, more_closures = _closures(session, since)
    imported, marked = _imported(session, since)
    records = build_records(
        tallies,
        marks,
        closures,
        imported,
        _overturns(session),
        now,
        _service_accounts(session),
        marked,
    )
    if more_alerts or more_marks or more_closures:
        logger.warning("Kind records hit a read limit, so none can be adopted")
        for record in records.values():
            record.incomplete = True
    return records


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
        "rule_id": (adoption.rule_id if adoption and close_on else record.rule_id),
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
    closing = session.scalars(
        select(KindPolicy).where(KindPolicy.mode == PolicyMode.CLOSE).with_for_update()
    ).all()
    for policy in closing:
        _settle(session, policy, now)
    policies = {p.signature: p for p in session.scalars(select(KindPolicy))}
    records = _records(session, now)
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
        "incomplete": any(r.incomplete for r in records.values()),
        "kinds_shown": min(len(kinds), KINDS_SHOWN),
        "daily": daily_counts(_daily_rows(session, now.date()), now.date(), DAILY_DAYS),
        "kinds": kinds[:KINDS_SHOWN],
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
    records = _records(session, now)
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
                "rule_id": record.rule_id,
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
                KindPolicy.signature
                == stored_signature(row.data_source, row.title, row.entity_context),
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
            or not adoption.rule_id
            or source_rule_of(row.entity_context) != adoption.rule_id
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
