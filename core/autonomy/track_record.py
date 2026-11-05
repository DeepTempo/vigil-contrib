"""What people have decided about each kind of alert, and what that lets Vigil do.

Pure functions over plain rows, no database. The kind is the cold start signature. A label
is one person's one decision, so a closed case is one label however many alerts it holds,
and nothing Vigil or an agent closed is ever evidence.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
)

from core.cases.closure import (
    CLOSURE_OUTCOMES,
    ClosedByKind,
    ClosureCategory,
    closed_by_person,
)
from core.coldstart.baseline import MIN_STRONG_LABELS, miss_bound
from core.coldstart.tickets import _bulk_closed
from core.memory.recall_contract import VerdictOutcome
from core.storage.source_rule import FALLBACK_TITLES

# Longer than a policy lives. A kind that closed itself for 90 days earned no new labels, so
# a window of the same length would refuse every re-adoption at expiry.
WINDOW = timedelta(days=180)
POLICY_LIFETIME = timedelta(days=90)
DAILY_DAYS = 14

# The only severities a policy may close. Anything else, unknown included, stays with a person.
AUTO_SEVERITIES = frozenset({"low", "medium"})
ABOVE_SCOPE = frozenset({"high", "critical"})
# The only triage answer a policy may act on. "monitor" asks someone to keep watching it.
DISMISS = "dismiss"

POLICY_REASON_PREFIX = "kind-policy:"


class Verdict(str, Enum):
    BENIGN = "benign"
    REAL = "real"


class Origin(str, Enum):
    CASE = "case"
    NOISE = "noise"
    OVERTURN = "overturn"
    IMPORTED = "imported"


class PolicyEventKind(str, Enum):
    ADOPT = "adopt"
    RENEW = "renew"
    REVOKE = "revoke"
    SUSPEND = "suspend"
    EXPIRE = "expire"
    OVERTURN = "overturn"


class KindMode(str, Enum):
    ASK = "ask"
    CLOSE = "close"
    SUSPENDED = "suspended"
    EXPIRED = "expired"


@dataclass(frozen=True)
class NoiseMark:
    at: datetime
    by: Optional[str]
    by_kind: Optional[str]
    reason: Optional[str]


@dataclass(frozen=True)
class AlertTally:
    """Alerts in the window that share a kind and a source rule, counted in the database."""

    signature: str
    rule: Optional[str]
    seen: int = 1
    above_scope: int = 0
    closed_by_vigil: int = 0


@dataclass(frozen=True)
class MarkedAlert:
    finding_id: str
    signature: str
    mark: NoiseMark


@dataclass(frozen=True)
class CaseClosure:
    case_id: str
    category: str
    channel: Optional[str]
    closed_by: Optional[str]
    closed_at: datetime
    finding_ids: FrozenSet[str]
    signatures: FrozenSet[str]


@dataclass(frozen=True)
class ImportedTally:
    """Tickets of one kind from the live cold start run. People decided them, somewhere else."""

    signature: str
    benign: int = 0
    real: int = 0
    last_real_at: Optional[datetime] = None


@dataclass(frozen=True)
class Overturn:
    signature: str
    finding_id: str
    at: datetime


@dataclass(frozen=True)
class Label:
    signature: str
    verdict: Verdict
    origin: Origin
    ref: str
    at: datetime


@dataclass
class TrackRecord:
    signature: str
    alerts_seen: int = 0
    above_scope: int = 0
    closed_by_vigil: int = 0
    benign_here: int = 0
    real_here: int = 0
    imported_benign: int = 0
    imported_real: int = 0
    overturned: int = 0
    bulk_ignored: int = 0
    marked_not_benign: bool = False
    last_real_at: Optional[datetime] = None
    rule_ids: Set[str] = field(default_factory=set)
    alerts_without_rule: int = 0
    # The database held more than one read may take, so these counts are a lower bound.
    incomplete: bool = False

    @property
    def rule_id(self) -> Optional[str]:
        """The one source rule this kind is, when it is one."""
        if len(self.rule_ids) == 1 and not self.alerts_without_rule:
            return next(iter(self.rule_ids))
        return None

    @property
    def clean_labels(self) -> int:
        return self.benign_here + self.imported_benign

    @property
    def real_labels(self) -> int:
        return self.real_here + self.imported_real + self.overturned

    @property
    def reviewed(self) -> int:
        return self.clean_labels + self.real_labels

    @property
    def miss_bound(self) -> Optional[float]:
        return miss_bound(self.clean_labels) if self.real_labels == 0 else None


def is_vigil_close(mark: Optional[NoiseMark]) -> bool:
    return bool(
        mark
        and mark.by_kind == ClosedByKind.AGENT.value
        and (mark.reason or "").startswith(POLICY_REASON_PREFIX)
    )


def _person_mark(mark: Optional[NoiseMark], service_accounts: FrozenSet[str]) -> bool:
    return bool(
        mark
        and mark.by_kind == ClosedByKind.PERSON.value
        and mark.by not in service_accounts
    )


def _closure_verdict(category: str) -> Optional[Verdict]:
    try:
        outcome = CLOSURE_OUTCOMES.get(ClosureCategory(category))
    except ValueError:
        return None
    if outcome is VerdictOutcome.PROVEN:
        return Verdict.REAL
    if outcome is VerdictOutcome.FALSE_POSITIVE:
        return Verdict.BENIGN
    return None


def person_labels(
    marks: Iterable[MarkedAlert],
    closures: Iterable[CaseClosure],
    overturns: Iterable[Overturn] = (),
    service_accounts: FrozenSet[str] = frozenset(),
) -> Tuple[List[Label], Counter]:
    """Labels people made here, with how many benign ones per kind were ignored as a burst.

    A burst of closes by one person is dropped as it is for imported tickets: 59 alerts
    marked in a minute are not 59 decisions. Only benign ones drop, so a real closure made
    in a burst still counts.
    """
    decisions: List[Tuple[Dict[str, Any], List[Label]]] = []
    labelled_findings = set()
    for closure in closures:
        verdict = _closure_verdict(closure.category)
        if verdict is None or not closed_by_person(closure.channel):
            continue
        labelled_findings.update(closure.finding_ids)
        decisions.append(
            (
                {"closed_at": closure.closed_at, "closed_by": closure.closed_by},
                [
                    Label(s, verdict, Origin.CASE, closure.case_id, closure.closed_at)
                    for s in closure.signatures
                ],
            )
        )
    for marked in marks:
        if (
            _person_mark(marked.mark, service_accounts)
            and marked.finding_id not in labelled_findings
        ):
            decisions.append(
                (
                    {"closed_at": marked.mark.at, "closed_by": marked.mark.by},
                    [
                        Label(
                            marked.signature,
                            Verdict.BENIGN,
                            Origin.NOISE,
                            marked.finding_id,
                            marked.mark.at,
                        )
                    ],
                )
            )
    bulk = _bulk_closed([row for row, _ in decisions])
    labels: List[Label] = []
    ignored: Counter = Counter()
    for index, (_, made) in enumerate(decisions):
        for label in made:
            if index in bulk and label.verdict is Verdict.BENIGN:
                ignored[label.signature] += 1
            else:
                labels.append(label)
    labels.extend(
        Label(o.signature, Verdict.REAL, Origin.OVERTURN, o.finding_id, o.at)
        for o in overturns
    )
    return labels, ignored


_LABEL_FIELDS: Mapping[Tuple[Origin, Verdict], str] = {
    (Origin.CASE, Verdict.BENIGN): "benign_here",
    (Origin.CASE, Verdict.REAL): "real_here",
    (Origin.NOISE, Verdict.BENIGN): "benign_here",
    (Origin.OVERTURN, Verdict.REAL): "overturned",
}


def build_records(
    tallies: Iterable[AlertTally],
    marks: Iterable[MarkedAlert],
    closures: Iterable[CaseClosure],
    imported: Iterable[ImportedTally],
    overturns: Iterable[Overturn],
    now: datetime,
    service_accounts: FrozenSet[str] = frozenset(),
    marked_not_benign: FrozenSet[str] = frozenset(),
) -> Dict[str, TrackRecord]:
    since = now - WINDOW
    records: Dict[str, TrackRecord] = {}

    def record(signature: str) -> TrackRecord:
        return records.setdefault(signature, TrackRecord(signature=signature))

    for tally in tallies:
        row = record(tally.signature)
        row.alerts_seen += tally.seen
        row.above_scope += tally.above_scope
        row.closed_by_vigil += tally.closed_by_vigil
        if tally.rule:
            row.rule_ids.add(tally.rule)
        else:
            row.alerts_without_rule += tally.seen

    for tally in imported:
        row = record(tally.signature)
        row.imported_benign += tally.benign
        row.imported_real += tally.real
        if tally.last_real_at:
            row.last_real_at = max(
                row.last_real_at or tally.last_real_at, tally.last_real_at
            )

    here, ignored = person_labels(marks, closures, overturns, service_accounts)
    for label in here:
        if label.at < since:
            continue
        row = record(label.signature)
        name = _LABEL_FIELDS[(label.origin, label.verdict)]
        setattr(row, name, getattr(row, name) + 1)
        if label.verdict is Verdict.REAL:
            row.last_real_at = max(row.last_real_at or label.at, label.at)
    for signature, count in ignored.items():
        record(signature).bulk_ignored += count
    for signature in marked_not_benign:
        if signature in records:
            records[signature].marked_not_benign = True
    return records


@dataclass(frozen=True)
class EligibilityRule:
    name: str
    passes: Callable[[TrackRecord], bool]
    why_not: Callable[[TrackRecord], str]


def _why_no_rule(record: TrackRecord) -> str:
    if not record.rule_ids:
        return (
            "Known only by its title, which an alert's content can change. "
            "Only a kind with a rule identifier from its source can be adopted."
        )
    if len(record.rule_ids) > 1:
        return (
            f"{len(record.rule_ids)} different source rules share this title, "
            "so it is not one detection."
        )
    return f"{record.alerts_without_rule} alerts with this title name no source rule."


def _names_a_detection(record: TrackRecord) -> bool:
    return record.signature.partition("|")[2] not in FALLBACK_TITLES


ELIGIBILITY_RULES: Tuple[EligibilityRule, ...] = (
    EligibilityRule(
        "one_source_rule",
        lambda r: r.rule_id is not None,
        _why_no_rule,
    ),
    EligibilityRule(
        "names_a_detection",
        _names_a_detection,
        lambda r: "This is a connector's fallback title. It names no detection.",
    ),
    EligibilityRule(
        "whole_record_read",
        lambda r: not r.incomplete,
        lambda r: "This install holds more alerts than one read may take, so this record is incomplete.",
    ),
    EligibilityRule(
        "enough_clean_labels",
        lambda r: r.clean_labels >= MIN_STRONG_LABELS,
        lambda r: f"{r.clean_labels} of {MIN_STRONG_LABELS} clean labels from people.",
    ),
    EligibilityRule(
        "none_real",
        lambda r: r.real_labels == 0,
        lambda r: f"{r.real_labels} closed real in the last {WINDOW.days} days.",
    ),
    EligibilityRule(
        "nothing_above_scope",
        lambda r: r.above_scope == 0,
        lambda r: f"{r.above_scope} high or critical alerts of this kind in the last {WINDOW.days} days.",
    ),
    EligibilityRule(
        "not_marked_not_benign",
        lambda r: not r.marked_not_benign,
        lambda r: "A person reviewed this kind during cold start and marked it not benign.",
    ),
)


def why_not(record: TrackRecord) -> List[Dict[str, str]]:
    return [
        {"rule": rule.name, "why": rule.why_not(record)}
        for rule in ELIGIBILITY_RULES
        if not rule.passes(record)
    ]


@dataclass(frozen=True)
class Adoption:
    policy_id: int
    actor: str
    reason: str
    at: datetime
    clean_labels: int
    rule_id: Optional[str] = None

    @property
    def expires_at(self) -> datetime:
        return self.at + POLICY_LIFETIME


@dataclass(frozen=True)
class Demotion:
    kind: PolicyEventKind
    reason: str
    evidence: Mapping[str, Any] = field(default_factory=dict)


def demotion_due(
    adoption: Adoption, real_labels: Iterable[Label], now: datetime
) -> Optional[Demotion]:
    """Why a policy on close must fall back to asking. A real closure wins over expiry."""
    real = [
        label
        for label in real_labels
        if label.verdict is Verdict.REAL and label.at > adoption.at
    ]
    if real:
        first = min(real, key=lambda label: label.at)
        return Demotion(
            PolicyEventKind.SUSPEND,
            "A person closed an alert of this kind as real after adoption.",
            {"origin": first.origin.value, "ref": first.ref},
        )
    if now >= adoption.expires_at:
        return Demotion(
            PolicyEventKind.EXPIRE,
            f"The adoption passed {POLICY_LIFETIME.days} days without a person re-adopting it.",
            {"expired_at": adoption.expires_at.isoformat()},
        )
    return None


def mode_of(close_on: bool, last_event: Optional[PolicyEventKind]) -> KindMode:
    if close_on:
        return KindMode.CLOSE
    if last_event in (PolicyEventKind.SUSPEND, PolicyEventKind.OVERTURN):
        return KindMode.SUSPENDED
    if last_event is PolicyEventKind.EXPIRE:
        return KindMode.EXPIRED
    return KindMode.ASK


def _text(value: Any) -> str:
    return str(value or "").strip().lower()


def _triage_failed(f: Mapping[str, Any], _source: Any) -> bool:
    return not f.get("ai_triage") or bool(f.get("ai_triage_error"))


def _severity_out_of_scope(f: Mapping[str, Any], source: Any) -> bool:
    return (
        _text(f.get("severity")) not in AUTO_SEVERITIES
        or _text(source) not in AUTO_SEVERITIES
    )


def _triage_did_not_dismiss(f: Mapping[str, Any], _source: Any) -> bool:
    return _text(f.get("recommended_action")) != DISMISS


def _threat_intel_hit(f: Mapping[str, Any], _source: Any) -> bool:
    return bool((f.get("enrichment") or {}).get("threat_indicators"))


def _precedent_escalates(f: Mapping[str, Any], _source: Any) -> bool:
    baseline = (f.get("ai_triage") or {}).get("baseline") or {}
    return baseline.get("stage1") == "escalate"


# Any match keeps the alert in the queue, whatever the policy says. The source's severity
# counts as well as triage's: alert text can talk a model into calling a high alert low.
STAY_RULES: Tuple[Tuple[str, Callable[[Mapping[str, Any], Any], bool]], ...] = (
    ("triage_failed", _triage_failed),
    ("severity_out_of_scope", _severity_out_of_scope),
    ("triage_did_not_dismiss", _triage_did_not_dismiss),
    ("threat_intel_hit", _threat_intel_hit),
    ("precedent_escalates", _precedent_escalates),
)


def stay_reason(finding: Mapping[str, Any], source_severity: Any) -> Optional[str]:
    for name, matches in STAY_RULES:
        if matches(finding, source_severity):
            return name
    return None


def daily_counts(
    rows: Iterable[Tuple[date, bool, int]], today: date, days: int = DAILY_DAYS
) -> List[Dict[str, Any]]:
    """Per day, alerts left for a person and alerts a policy closed. A row is (day,
    whether a policy closed them, how many)."""
    start = today - timedelta(days=days - 1)
    asked: Counter = Counter()
    closed: Counter = Counter()
    for day, by_policy, count in rows:
        if day >= start:
            (closed if by_policy else asked)[day] += count
    return [
        {
            "day": (start + timedelta(days=i)).isoformat(),
            "asked": asked[start + timedelta(days=i)],
            "closed": closed[start + timedelta(days=i)],
        }
        for i in range(days)
    ]
