"""A case as one story: its steps in time, why they hang together, and what can be done.

``build_story`` is pure and calls no model. Every reason is computed from stored rows and
carries the rows it rests on, so a case with less data has fewer reasons, never a padded
one. Text a model wrote stays in ``report`` and ``verdict.model_words``, labelled as such.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from pydantic import BaseModel, Field

from core.cases.case_status import CLOSED
from core.cases.closure import CLOSURE_OUTCOMES, ClosureCategory, closed_by_person
from core.detections.gaps import TECHNIQUE_ID
from core.findings.similarity import _ENTITY_SKIP
from core.memory.recall_contract import VerdictOutcome
from core.response.approval_service import (
    ActionStatus,
    PendingAction,
)
from core.response.config import split_decision_rule
from core.storage.schemas.base import IsoDateTime, OptDateTime
from core.storage.technique_confidence import rank_by_confidence
from core.threat_intel.mitre_lookup import resolve_technique

MIN_FINDINGS = 2
# Where the console's LogLM meter turns hot.
UNUSUAL_SCORE = 0.7
HIGH_SEVERITIES = ("critical", "high")
FLAGGED_THREAT_LEVELS = ("critical", "high")
EVIDENCE_SHOWN = 6
SHARED_ENTITIES_SHOWN = 3
# How often services/daemon/executor.py passes over approved rows.
EXECUTOR_SECONDS = 30

# entity_context keys, as the sources write them, by what they name.
ENTITY_KEYS: Mapping[str, tuple[str, ...]] = {
    "ip": (
        "src_ips",
        "dest_ips",
        "dst_ips",
        "source_ips",
        "ips",
        "ip_addresses",
        "src_ip",
        "dst_ip",
    ),
    "hash": ("file_hashes", "hashes"),
    "domain": ("domains",),
    "url": ("urls",),
    "email": ("emails",),
    "host": ("hostnames", "hosts", "hostname"),
    "user": ("usernames", "users", "user"),
}
# Where a source names the rule that fired, best name first.
RULE_KEYS = (
    "rule_name",
    "rule_description",
    "search_name",
    "detection_name",
    "rule",
    "rule_id",
    "detection_id",
)


class Coverage(str, Enum):
    """Whether a rule stands behind a step."""

    RULE_FIRED = "rule_fired"  # the alert itself names the rule
    RULE_DECLARED = "rule_declared"  # an active inventory rule declares its technique
    NO_RULE = "no_rule"  # the stored data shows no rule behind it
    UNKNOWN = "unknown"  # the alert names neither a rule nor a technique


class EvidenceKind(str, Enum):
    FINDING = "finding"
    LOG_SEARCH = "log_search"
    APPROVAL = "approval"


class ReasonKind(str, Enum):
    SEVERAL_SOURCES = "several_sources"
    SHARED_ENTITY = "shared_entity"
    DAEMON_MERGE = "daemon_merge"
    UNUSUAL_SCORE = "unusual_score"
    TECHNIQUE_CHAIN = "technique_chain"
    HIGH_SEVERITY = "high_severity"
    FLAGGED_INTEL = "flagged_intel"
    LOG_EVENTS = "log_events"
    PERSON_APPROVED = "person_approved"


class VerdictValue(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNDETERMINED = "undetermined"


class ActionEffect(str, Enum):
    """What happens beyond the recorded decision, in this install."""

    CLOUDFLARE = "cloudflare"  # the daemon's executor calls Cloudflare
    NO_EXECUTOR = "no_executor"  # the executor marks it failed: no EDR is wired
    RUN_RESUMES = "run_resumes"  # a paused workflow run continues
    RECORD_ONLY = "record_only"  # nothing runs; a person carries it out


class Technique(BaseModel):
    id: str
    name: str
    tactic: Optional[str] = None
    confidence: Optional[float] = None


class Step(BaseModel):
    finding_id: str
    at: IsoDateTime
    label: str
    source: str
    severity: Optional[str] = None
    technique: Optional[Technique] = None
    other_techniques: list[Technique] = Field(default_factory=list)
    # Stored ATT&CK labels that are not technique ids: tactic names, a source's own class.
    labels: list[str] = Field(default_factory=list)
    anomaly_score: Optional[float] = None
    coverage: Coverage
    caught_by: Optional[str] = None
    coverage_note: str


class Evidence(BaseModel):
    kind: EvidenceKind
    ref: str
    label: str


class Reason(BaseModel):
    kind: ReasonKind
    text: str
    evidence: list[Evidence] = Field(min_length=1)


class Action(BaseModel):
    action_id: str
    title: str
    description: str
    target: str
    action_type: str
    status: str
    reason: str
    confidence: float
    reversibility: str
    created_at: str
    created_by: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    executed_at: Optional[str] = None
    rejection_reason: Optional[str] = None
    workflow_run_id: Optional[str] = None
    effect: ActionEffect
    # What approving does here, in words, and what is missing for it to do more.
    does: str
    missing: Optional[str] = None
    # What the executor last reported on this row.
    result: Optional[str] = None
    evidence: list[Evidence] = Field(default_factory=list)


class Entity(BaseModel):
    kind: str
    value: str
    finding_ids: list[str]


class IntelItem(BaseModel):
    kind: str
    value: str
    threat_level: Optional[str] = None
    source: Optional[str] = None
    confidence: Optional[float] = None
    reputation: Optional[float] = None
    context: Optional[str] = None


class Verdict(BaseModel):
    value: VerdictValue
    label: str
    # "person", "agent", or None when nothing has concluded.
    by: Optional[str] = None
    basis: str
    model_words: Optional[str] = None


class Report(BaseModel):
    text: str
    origin: str
    ref: str
    at: OptDateTime = None


class SourceCount(BaseModel):
    source: str
    alerts: int


class Viewer(BaseModel):
    can_read_approvals: bool = False
    can_decide: bool = False


class Story(BaseModel):
    case_id: str
    title: str
    summary: str
    status: str
    priority: str
    opened_at: IsoDateTime
    alerts: int
    sources: list[SourceCount]
    verdict: Verdict
    report: Optional[Report] = None
    steps: list[Step]
    reasons: list[Reason]
    actions: list[Action]
    entities: list[Entity]
    intel: list[IntelItem]
    unmatched_steps: list[Step]
    log_events: int
    rules_loaded: int
    viewer: Viewer = Field(default_factory=Viewer)


class IncidentRow(BaseModel):
    """One incident in a list, projected from its ``Story``."""

    case_id: str
    title: str
    status: str
    priority: str
    opened_at: IsoDateTime
    alerts: int
    sources: list[SourceCount]
    verdict: Verdict
    unmatched_steps: int
    log_events: int
    pending_approvals: Optional[int] = None


class IncidentList(BaseModel):
    total: int
    items: list[IncidentRow]


@dataclass(frozen=True)
class CaseFacts:
    case_id: str
    title: str
    status: str
    created_at: datetime
    priority: str = "medium"
    description: str = ""
    activities: Sequence[Mapping[str, Any]] = ()


@dataclass(frozen=True)
class FindingFacts:
    finding_id: str
    created_at: datetime
    data_source: str = "unknown"
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    timestamp: Optional[datetime] = None
    anomaly_score: Optional[float] = None
    entity_context: Optional[Mapping[str, Any]] = None
    # (stored ATT&CK label, confidence or None), as finding_mitre_predictions holds them.
    labels: Sequence[tuple[str, Optional[float]]] = ()


@dataclass(frozen=True)
class ClosureFacts:
    category: str
    channel: Optional[str] = None
    closed_by: Optional[str] = None
    notes: Optional[str] = None


@dataclass(frozen=True)
class HuntVerdictFacts:
    outcome: str
    statement: str
    rationale: str
    concluded_at: datetime
    investigation_id: str


@dataclass(frozen=True)
class IocFacts:
    kind: str
    value: str
    threat_level: Optional[str] = None
    source: Optional[str] = None
    confidence: Optional[float] = None
    reputation: Optional[float] = None
    context: Optional[str] = None


@dataclass(frozen=True)
class LogFacts:
    events: int = 0
    unusual: int = 0


@dataclass(frozen=True)
class InstallFacts:
    cloudflare_enabled: bool = False
    cloudflare_token: bool = False
    execution_held: bool = False


@dataclass(frozen=True)
class RuleInventory:
    """Active rules by the technique they declare, and how many are loaded at all."""

    by_technique: Mapping[str, Sequence[str]] = field(default_factory=dict)
    loaded: int = 0


@dataclass(frozen=True)
class StoryFacts:
    case: CaseFacts
    findings: Sequence[FindingFacts]
    overlap: Sequence[Entity] = ()
    closure: Optional[ClosureFacts] = None
    hunt_verdicts: Sequence[HuntVerdictFacts] = ()
    report: Optional[Report] = None
    approvals: Sequence[PendingAction] = ()
    iocs: Sequence[IocFacts] = ()
    logs: LogFacts = LogFacts()
    rules: RuleInventory = RuleInventory()
    install: InstallFacts = InstallFacts()
    viewer: Viewer = field(default_factory=Viewer)


def _values(context: Optional[Mapping[str, Any]], key: str) -> list[str]:
    raw = (context or {}).get(key)
    items = raw if isinstance(raw, (list, tuple)) else [raw]
    return [
        str(item).strip()
        for item in items
        if isinstance(item, (str, int)) and not isinstance(item, bool)
    ]


def entity_overlap(findings: Iterable[FindingFacts]) -> list[Entity]:
    """Every host, user, address, domain, URL and hash the alerts name, and who names it.

    Most-named first. Compared without case, shown as the first alert spelled it.
    """
    spelled: dict[tuple[str, str], str] = {}
    named_by: dict[tuple[str, str], list[str]] = defaultdict(list)
    for finding in findings:
        for kind, keys in ENTITY_KEYS.items():
            for key in keys:
                for value in _values(finding.entity_context, key):
                    folded = value.lower()
                    if folded in _ENTITY_SKIP:
                        continue
                    spelled.setdefault((kind, folded), value)
                    if finding.finding_id not in named_by[(kind, folded)]:
                        named_by[(kind, folded)].append(finding.finding_id)
    rank = {kind: i for i, kind in enumerate(ENTITY_KEYS)}
    ordered = sorted(
        named_by, key=lambda k: (-len(named_by[k]), rank[k[0]], spelled[k])
    )
    return [
        Entity(
            kind=kind,
            value=spelled[(kind, folded)],
            finding_ids=named_by[(kind, folded)],
        )
        for kind, folded in ordered
    ]


def _label_of(finding: FindingFacts) -> str:
    return (
        (finding.title or "").strip()
        or (finding.description or "").strip().split("\n")[0][:160]
        or finding.finding_id
    )


def _technique(technique_id: str, confidence: Optional[float]) -> Technique:
    tid, name, tactic = resolve_technique(technique_id)
    return Technique(
        id=tid,
        name=name,
        tactic=None if tactic == "Unknown" else tactic,
        confidence=confidence,
    )


def _coverage(
    finding: FindingFacts, techniques: Sequence[Technique], rules: RuleInventory
) -> tuple[Coverage, Optional[str], str]:
    for key in RULE_KEYS:
        named = _values(finding.entity_context, key)
        if named and named[0]:
            return (
                Coverage.RULE_FIRED,
                named[0],
                f"{finding.data_source} names the rule that fired: {named[0]}.",
            )
    for technique in techniques:
        declaring = rules.by_technique.get(technique.id.upper())
        if declaring:
            return (
                Coverage.RULE_DECLARED,
                declaring[0],
                f"Active rule {declaring[0]} declares {technique.id}.",
            )
    if techniques:
        ids = ", ".join(t.id for t in techniques)
        if not rules.loaded:
            return (
                Coverage.NO_RULE,
                None,
                f"No rules are loaded in the inventory, so none declares {ids}.",
            )
        return (
            Coverage.NO_RULE,
            None,
            f"No active rule in the inventory declares {ids}.",
        )
    if finding.anomaly_score is not None:
        return (
            Coverage.NO_RULE,
            None,
            "This alert carries LogLM's score and names no rule or technique.",
        )
    return (
        Coverage.UNKNOWN,
        None,
        "This alert names no rule and no ATT&CK technique, so Vigil cannot tell if a rule covers it.",
    )


def _step(finding: FindingFacts, rules: RuleInventory) -> Step:
    ranked = rank_by_confidence(
        [{"label": label, "confidence": conf} for label, conf in finding.labels]
    )
    techniques = [
        _technique(row["label"].upper(), row["confidence"])
        for row in ranked
        if TECHNIQUE_ID.match(row["label"])
    ]
    coverage, caught_by, note = _coverage(finding, techniques, rules)
    return Step(
        finding_id=finding.finding_id,
        at=finding.timestamp or finding.created_at,
        label=_label_of(finding),
        source=finding.data_source,
        severity=finding.severity,
        technique=techniques[0] if techniques else None,
        other_techniques=techniques[1:],
        labels=[r["label"] for r in ranked if not TECHNIQUE_ID.match(r["label"])],
        anomaly_score=finding.anomaly_score,
        coverage=coverage,
        caught_by=caught_by,
        coverage_note=note,
    )


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def _finding_links(steps: Iterable[Step]) -> list[Evidence]:
    return [
        Evidence(kind=EvidenceKind.FINDING, ref=step.finding_id, label=step.label)
        for step in list(steps)[:EVIDENCE_SHOWN]
    ]


def _several_sources(facts: StoryFacts, steps: Sequence[Step]) -> list[Reason]:
    by_source: dict[str, Step] = {}
    for step in steps:
        by_source.setdefault(step.source, step)
    if len(by_source) < 2:
        return []
    names = ", ".join(sorted(by_source))
    return [
        Reason(
            kind=ReasonKind.SEVERAL_SOURCES,
            text=f"{len(steps)} alerts came from {len(by_source)} separate sources: {names}.",
            evidence=_finding_links(by_source.values()),
        )
    ]


def _shared_entities(facts: StoryFacts, steps: Sequence[Step]) -> list[Reason]:
    by_id = {step.finding_id: step for step in steps}
    reasons = []
    shared = [e for e in facts.overlap if len(e.finding_ids) >= 2]
    for entity in shared[:SHARED_ENTITIES_SHOWN]:
        named = [by_id[fid] for fid in entity.finding_ids if fid in by_id]
        if len(named) < 2:
            continue
        reasons.append(
            Reason(
                kind=ReasonKind.SHARED_ENTITY,
                text=f"{len(named)} of {len(steps)} alerts name the same {entity.kind}, {entity.value}.",
                evidence=_finding_links(named),
            )
        )
    return reasons


def _daemon_merges(facts: StoryFacts, steps: Sequence[Step]) -> list[Reason]:
    """The daemon's own record of why an alert joined this case."""
    by_id = {step.finding_id: step for step in steps}
    joined: dict[str, list[Step]] = defaultdict(list)
    for activity in facts.case.activities:
        details = activity.get("details") if isinstance(activity, Mapping) else None
        if activity.get("activity_type") != "alert_added" or not isinstance(
            details, Mapping
        ):
            continue
        step = by_id.get(str(details.get("finding_id")))
        key = details.get("matched_key")
        if step and isinstance(key, str) and key:
            joined[key].append(step)
    reasons = []
    for key, merged in joined.items():
        kind, _, value = key.partition(":")
        reasons.append(
            Reason(
                kind=ReasonKind.DAEMON_MERGE,
                text=(
                    f"Vigil's daemon added {_plural(len(merged), 'alert')} to this open case "
                    f"because of the same {kind}, {value}."
                ),
                evidence=_finding_links(merged),
            )
        )
    return reasons


def _unusual_scores(facts: StoryFacts, steps: Sequence[Step]) -> list[Reason]:
    unusual = [
        s
        for s in steps
        if s.anomaly_score is not None and s.anomaly_score >= UNUSUAL_SCORE
    ]
    if not unusual:
        return []
    highest = max(s.anomaly_score for s in unusual)
    return [
        Reason(
            kind=ReasonKind.UNUSUAL_SCORE,
            text=(
                f"LogLM scored {_plural(len(unusual), 'alert')} at {UNUSUAL_SCORE:.2f} or above. "
                f"The highest is {highest:.2f}."
            ),
            evidence=_finding_links(unusual),
        )
    ]


def _technique_chain(facts: StoryFacts, steps: Sequence[Step]) -> list[Reason]:
    first_of: dict[str, Step] = {}
    for step in steps:
        if step.technique:
            first_of.setdefault(step.technique.id, step)
    if len(first_of) < 2:
        return []
    return [
        Reason(
            kind=ReasonKind.TECHNIQUE_CHAIN,
            text=f"In time order, the alerts move through {len(first_of)} ATT&CK techniques: {', '.join(first_of)}.",
            evidence=_finding_links(first_of.values()),
        )
    ]


def _high_severity(facts: StoryFacts, steps: Sequence[Step]) -> list[Reason]:
    high = [s for s in steps if (s.severity or "").lower() in HIGH_SEVERITIES]
    if not high:
        return []
    return [
        Reason(
            kind=ReasonKind.HIGH_SEVERITY,
            text=f"The sources rated {len(high)} of {len(steps)} alerts high or critical.",
            evidence=_finding_links(high),
        )
    ]


def _flagged_intel(facts: StoryFacts, steps: Sequence[Step]) -> list[Reason]:
    by_id = {step.finding_id: step for step in steps}
    named_by = {e.value.lower(): e.finding_ids for e in facts.overlap}
    reasons = []
    for ioc in facts.iocs:
        if (ioc.threat_level or "").lower() not in FLAGGED_THREAT_LEVELS:
            continue
        named = [
            by_id[fid] for fid in named_by.get(ioc.value.lower(), ()) if fid in by_id
        ]
        if not named:
            continue
        origin = f" by {ioc.source}" if ioc.source else ""
        reasons.append(
            Reason(
                kind=ReasonKind.FLAGGED_INTEL,
                text=f"{ioc.value} is rated {ioc.threat_level}{origin}, and {_plural(len(named), 'alert')} name it.",
                evidence=_finding_links(named),
            )
        )
    return reasons


def _log_events(facts: StoryFacts, steps: Sequence[Step]) -> list[Reason]:
    if not facts.logs.events:
        return []
    scored = (
        f" LogLM scored {facts.logs.unusual} of them at {UNUSUAL_SCORE:.2f} or above."
        if facts.logs.unusual
        else ""
    )
    return [
        Reason(
            kind=ReasonKind.LOG_EVENTS,
            text=f"This case has {_plural(facts.logs.events, 'stored log event')}.{scored}",
            evidence=[
                Evidence(
                    kind=EvidenceKind.LOG_SEARCH,
                    ref=facts.case.case_id,
                    label=f"{facts.logs.events} events",
                )
            ],
        )
    ]


_APPROVED_STATES = (ActionStatus.APPROVED.value, ActionStatus.EXECUTED.value)


def _person_approved(facts: StoryFacts, steps: Sequence[Step]) -> list[Reason]:
    return [
        Reason(
            kind=ReasonKind.PERSON_APPROVED,
            text=f"{action.approved_by} approved {action.title}.",
            evidence=[
                Evidence(
                    kind=EvidenceKind.APPROVAL,
                    ref=action.action_id,
                    label=action.title,
                )
            ],
        )
        for action in facts.approvals
        if action.status in _APPROVED_STATES and action.approved_by
    ]


_REASONS: Sequence[Callable[[StoryFacts, Sequence[Step]], list[Reason]]] = (
    _daemon_merges,
    _shared_entities,
    _several_sources,
    _technique_chain,
    _unusual_scores,
    _high_severity,
    _flagged_intel,
    _log_events,
    _person_approved,
)

_CLOUDFLARE_ACTS = {
    "waf_block": "adds a Cloudflare WAF block on {target}",
    "gateway_block": "adds a Cloudflare Gateway rule blocking {target}",
    "access_revoke": "revokes the Cloudflare Access sessions of {target}",
}
RECORDED = "Approving records your name on this action."
ISOLATE_HOST = "isolate_host"


def _what_approving_does(
    action: PendingAction, install: InstallFacts
) -> tuple[ActionEffect, str, Optional[str]]:
    """What the approvals route and the daemon's executor do with this row, here and now."""
    run = action.workflow_run_id
    resumes = f" Workflow run {run} then resumes." if run else ""
    held = (
        " Stop is on, so the executor holds every approved action until it is lifted."
        if install.execution_held
        else ""
    )
    template = _CLOUDFLARE_ACTS.get(action.action_type)
    if template:
        act = template.format(target=action.target)
        if not install.cloudflare_enabled:
            return (
                ActionEffect.CLOUDFLARE,
                f"{RECORDED}{resumes} The executor tries it, which {act}, and marks it failed.{held}",
                "The Cloudflare integration is off, so nothing changes. Turn it on in Settings, Integrations.",
            )
        if not install.cloudflare_token:
            return (
                ActionEffect.CLOUDFLARE,
                f"{RECORDED}{resumes} The executor tries it, which {act}, and marks it failed.{held}",
                "The Cloudflare integration has no API token, so nothing changes. Add one in Settings, Integrations.",
            )
        return (
            ActionEffect.CLOUDFLARE,
            f"{RECORDED}{resumes} While the daemon runs, its executor {act} within about "
            f"{EXECUTOR_SECONDS} seconds, and this row shows the result.{held}",
            None,
        )
    if action.action_type == ISOLATE_HOST:
        return (
            ActionEffect.NO_EXECUTOR,
            f"{RECORDED}{resumes} The daemon's executor then marks it failed, and {action.target} is not touched.",
            "Vigil has no EDR executor for host isolation. Isolate the host in your EDR.",
        )
    if run:
        return ActionEffect.RUN_RESUMES, f"{RECORDED}{resumes}", None
    return (
        ActionEffect.RECORD_ONLY,
        f"{RECORDED} Nothing in this install carries out {action.action_type}, and nothing changes on your network.",
        "A person has to carry this out in the product that enforces it.",
    )


def _result_of(action: PendingAction) -> Optional[str]:
    result = action.execution_result
    if not isinstance(result, Mapping):
        return None
    for key in ("message", "error"):
        text = result.get(key)
        if isinstance(text, str) and text.strip():
            return text
    return "The executor reported success." if result.get("success") else None


def _action(action: PendingAction, facts: StoryFacts, steps: Sequence[Step]) -> Action:
    effect, does, missing = _what_approving_does(action, facts.install)
    cited = set(action.evidence or [])
    return Action(
        action_id=action.action_id,
        title=action.title,
        description=action.description,
        target=action.target,
        action_type=action.action_type,
        status=action.status,
        reason=split_decision_rule(action.reason)[0],
        confidence=float(action.confidence),
        reversibility=action.reversibility,
        created_at=action.created_at,
        created_by=action.created_by,
        approved_by=action.approved_by,
        approved_at=action.approved_at,
        executed_at=action.executed_at,
        rejection_reason=action.rejection_reason,
        workflow_run_id=action.workflow_run_id,
        effect=effect,
        does=does,
        missing=missing,
        result=_result_of(action),
        evidence=_finding_links(s for s in steps if s.finding_id in cited),
    )


_CLOSURE_VERDICTS = {
    VerdictOutcome.PROVEN: (VerdictValue.TRUE_POSITIVE, "True positive"),
    VerdictOutcome.FALSE_POSITIVE: (VerdictValue.FALSE_POSITIVE, "False positive"),
}
_NO_VERDICT = Verdict(
    value=VerdictValue.UNDETERMINED,
    label="No verdict yet",
    basis="Nobody has closed this case and no run has proven a finding on it.",
)


def _verdict(facts: StoryFacts) -> Verdict:
    closure = facts.closure
    if facts.case.status == CLOSED and closure is not None:
        try:
            outcome = CLOSURE_OUTCOMES.get(ClosureCategory(closure.category))
        except ValueError:
            outcome = None
        value, label = _CLOSURE_VERDICTS.get(
            outcome, (VerdictValue.UNDETERMINED, "Closed with no determination")
        )
        person = closed_by_person(closure.channel)
        who = closure.closed_by or ("a person" if person else "an agent")
        return Verdict(
            value=value,
            label=label,
            by="person" if person else "agent",
            basis=f"{who} closed this case as {closure.category}."
            + (f" {closure.notes}" if closure.notes and person else ""),
            model_words=closure.notes if closure.notes and not person else None,
        )
    proven = [
        v for v in facts.hunt_verdicts if v.outcome == VerdictOutcome.PROVEN.value
    ]
    if proven:
        newest = max(proven, key=lambda v: v.concluded_at)
        return Verdict(
            value=VerdictValue.TRUE_POSITIVE,
            label="True positive",
            by="agent",
            basis=f"Run {newest.investigation_id} recorded this finding as proven. A person has not closed the case.",
            model_words=f"{newest.statement} {newest.rationale}".strip(),
        )
    return _NO_VERDICT


def _source_counts(steps: Iterable[Step]) -> list[SourceCount]:
    counts = Counter(step.source for step in steps)
    return [
        SourceCount(source=source, alerts=alerts)
        for source, alerts in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def build_story(facts: StoryFacts) -> Story:
    steps = sorted(
        (_step(finding, facts.rules) for finding in facts.findings),
        key=lambda step: (step.at, step.finding_id),
    )
    pending_first = sorted(
        facts.approvals,
        key=lambda a: (a.status != ActionStatus.PENDING.value, a.created_at),
    )
    return Story(
        case_id=facts.case.case_id,
        title=facts.case.title,
        summary=facts.case.description or "",
        status=facts.case.status,
        priority=facts.case.priority,
        opened_at=facts.case.created_at,
        alerts=len(steps),
        sources=_source_counts(steps),
        verdict=_verdict(facts),
        report=facts.report,
        steps=steps,
        reasons=[reason for read in _REASONS for reason in read(facts, steps)],
        actions=[_action(a, facts, steps) for a in pending_first],
        entities=list(facts.overlap),
        intel=[
            IntelItem(
                kind=ioc.kind,
                value=ioc.value,
                threat_level=ioc.threat_level,
                source=ioc.source,
                confidence=ioc.confidence,
                reputation=ioc.reputation,
                context=ioc.context,
            )
            for ioc in facts.iocs
        ],
        unmatched_steps=[s for s in steps if s.coverage is Coverage.NO_RULE],
        log_events=facts.logs.events,
        rules_loaded=facts.rules.loaded,
        viewer=facts.viewer,
    )


def incident_row(story: Story, pending_approvals: Optional[int]) -> IncidentRow:
    return IncidentRow(
        case_id=story.case_id,
        title=story.title,
        status=story.status,
        priority=story.priority,
        opened_at=story.opened_at,
        alerts=story.alerts,
        sources=story.sources,
        verdict=story.verdict,
        unmatched_steps=len(story.unmatched_steps),
        log_events=story.log_events,
        pending_approvals=pending_approvals,
    )
