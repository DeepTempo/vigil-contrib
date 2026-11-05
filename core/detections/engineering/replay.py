"""Replay a rule on the rows ``log_events`` holds, counting hits and false positives.

Attack rows are the ones a person names, else the case's rows, else rows labelled with the
rule's technique. Benign rows are every other row no case claims: Vigil assumes they are normal,
so a false positive here may be a real attack nobody linked, and evidence says so.

Vigil's own evaluator runs first. A rule it refuses (``|cidr``, ``|gt``, ``|exists``) falls back
to the condition tree pySigma parses, ported from the detection write-back tool, when pySigma is
installed. That tree never runs a rule with ``|re``: the write-back tool needs a child process
with a timeout for it, and Vigil's evaluator already handles and bounds ``|re``.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from core.detections.engineering import sigma_text
from core.detections.engineering.targets import PYSIGMA_MISSING, pysigma_installed
from core.detections.tools import _compile_rule, _Unevaluable
from core.storage.models import LogEvent

MAX_ATTACK_ROWS = 2000
MAX_BENIGN_ROWS = 5000
MAX_FIELD_SAMPLE_ROWS = 2000
SAMPLES = 20
DEFAULT_WINDOW_DAYS = 30

_COLUMNS = (
    "event_id",
    "source",
    "event_class",
    "severity",
    "src_ip",
    "src_host",
    "dst_ip",
    "dst_host",
    "dst_port",
    "user_name",
    "action",
    "summary",
    "mitre",
)

Matcher = Callable[[Dict[str, Any]], bool]


class NotReplayable(Exception):
    """The rule cannot be evaluated; the message names the construct."""


def _flatten(record: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in record.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, f"{name}."))
        elif isinstance(value, (list, tuple)):
            out[name] = " ".join(map(str, value))
        else:
            out[name] = value
    return out


def event_of(row: LogEvent) -> Dict[str, Any]:
    """The row as a rule sees it: the source's own record, then the one schema around it."""
    columns = {name: getattr(row, name) for name in _COLUMNS}
    return {**columns, **_flatten(row.raw or {})}


def logged_fields(session: Session) -> Optional[Set[str]]:
    """Every field recent rows hold, or None when log_events is empty."""
    rows = session.scalars(
        select(LogEvent).order_by(LogEvent.time.desc()).limit(MAX_FIELD_SAMPLE_ROWS)
    ).all()
    if not rows:
        return None
    fields: Set[str] = set(_COLUMNS)
    for row in rows:
        fields.update(_flatten(row.raw or {}))
    return fields


class _Tree:
    """Sigma's own semantics over the condition tree pySigma parses."""

    def __init__(self, rule: Any):
        from sigma import conditions, types

        self.c, self.t = conditions, types
        self.trees = [cond.parsed for cond in rule.detection.parsed_condition]
        self.patterns: Dict[int, re.Pattern] = {}

    def __call__(self, event: Dict[str, Any]) -> bool:
        return any(self._node(tree, event) for tree in self.trees)

    def _node(self, node: Any, event: Dict[str, Any]) -> bool:
        c = self.c
        if isinstance(node, c.ConditionOR):
            return any(self._node(a, event) for a in node.args)
        if isinstance(node, c.ConditionAND):
            return all(self._node(a, event) for a in node.args)
        if isinstance(node, c.ConditionNOT):
            return not self._node(node.args[0], event)
        if isinstance(node, c.ConditionFieldEqualsValueExpression):
            return self._field(node.field, node.value, event)
        if isinstance(node, c.ConditionValueExpression):
            return self._keyword(node.value, event)
        raise NotReplayable(f"condition element {type(node).__name__} is not replayed")

    def _field(self, field: str, value: Any, event: Dict[str, Any]) -> bool:
        t = self.t
        if isinstance(value, t.SigmaExpansion):
            return any(self._field(field, v, event) for v in value.values)
        present = event.get(field) is not None
        if isinstance(value, t.SigmaNull):
            return not present
        if isinstance(value, t.SigmaExists):
            return present == bool(value)
        return present and self._value(value, event[field], event, False)

    def _keyword(self, value: Any, event: Dict[str, Any]) -> bool:
        t = self.t
        if isinstance(value, t.SigmaExpansion):
            return any(self._keyword(v, event) for v in value.values)
        return any(
            self._value(value, v, event, True) for v in event.values() if v is not None
        )

    def _pattern(self, s: Any, substring: bool) -> re.Pattern:
        key = id(s) * 2 + substring
        pattern = self.patterns.get(key)
        if pattern is None:
            t = self.t
            parts = []
            for p in s.s:
                if p is t.SpecialChars.WILDCARD_MULTI:
                    parts.append(".*")
                elif p is t.SpecialChars.WILDCARD_SINGLE:
                    parts.append(".")
                elif isinstance(p, str):
                    parts.append(re.escape(p))
                else:
                    raise NotReplayable("a placeholder value needs a pipeline")
            body = "".join(parts)
            cased = isinstance(s, t.SigmaCasedString)
            flags = re.DOTALL | (0 if cased else re.IGNORECASE)
            pattern = re.compile(body if substring else f"^{body}\\Z", flags)
            self.patterns[key] = pattern
        return pattern

    def _value(
        self, value: Any, actual: Any, event: Dict[str, Any], substring: bool
    ) -> bool:
        t = self.t
        if isinstance(value, t.SigmaString):
            return bool(self._pattern(value, substring).search(_text(actual)))
        if isinstance(value, t.SigmaBool):
            return _text(actual).lower() == ("true" if bool(value) else "false")
        if isinstance(value, t.SigmaNumber):
            number = _number(actual)
            return number is not None and number == float(value.number)
        if isinstance(value, t.SigmaCIDRExpression):
            try:
                address = ipaddress.ip_address(_text(actual).strip())
                return address in ipaddress.ip_network(value.cidr, strict=False)
            except ValueError:
                return False
        if isinstance(value, t.SigmaCompareExpression):
            number = _number(actual)
            if number is None:
                return False
            ref = float(value.number.number)
            return {
                "LT": number < ref,
                "LTE": number <= ref,
                "GT": number > ref,
                "GTE": number >= ref,
            }[value.op.name]
        if isinstance(value, t.SigmaFieldReference):
            other = event.get(value.field)
            return other is not None and _text(other).lower() == _text(actual).lower()
        raise NotReplayable(f"value type {type(value).__name__} is not replayed")


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _tree_matcher(text: str, refused_because: str) -> Matcher:
    if "|re" in text:
        raise NotReplayable(refused_because)
    if not pysigma_installed():
        raise NotReplayable(f"{refused_because}. {PYSIGMA_MISSING}")
    from sigma.collection import SigmaCollection

    try:
        rules = [
            r for r in SigmaCollection.from_yaml(text).rules if hasattr(r, "detection")
        ]
        if not rules:
            raise NotReplayable("correlation rules are not replayed")
        return _Tree(rules[0])
    except NotReplayable:
        raise
    except Exception as exc:  # noqa: BLE001 -- rule text from a model or a paste
        raise NotReplayable(f"rule did not evaluate: {exc}") from None


def matcher_for(text: str) -> Tuple[Matcher, str]:
    """A row test for ``text`` and which engine made it."""
    try:
        return _compile_rule(text), "vigil"
    except _Unevaluable as exc:
        return _tree_matcher(text, str(exc)), "sigma-tree"
    except (RecursionError, ValueError) as exc:
        raise NotReplayable(f"rule could not be replayed: {exc}") from None


def _matching(matcher: Matcher, rows: Iterable[LogEvent]) -> List[LogEvent]:
    try:
        return [row for row in rows if matcher(event_of(row))]
    except (_Unevaluable, RecursionError, ValueError) as exc:
        raise NotReplayable(str(exc)) from None


def _holding(rows: Iterable[LogEvent], fields: Set[str]) -> int:
    """Rows holding a field the rule reads: only those can show it stays quiet."""
    if not fields:
        return sum(1 for _ in rows)
    held = 0
    for row in rows:
        event = event_of(row)
        if any(event.get(name) is not None for name in fields):
            held += 1
    return held


def _sample(row: LogEvent) -> Dict[str, Any]:
    return {
        "event_id": row.event_id,
        "time": row.time.isoformat(),
        "source": row.source,
        "src_host": row.src_host,
        "user_name": row.user_name,
        "summary": row.summary[:300],
    }


def _attack_rows(
    session: Session,
    case_id: Optional[str],
    technique: Optional[str],
    event_ids: Optional[List[str]],
) -> Tuple[List[LogEvent], str]:
    base = select(LogEvent).order_by(LogEvent.time.desc()).limit(MAX_ATTACK_ROWS)
    if event_ids:
        rows = session.scalars(base.where(LogEvent.event_id.in_(event_ids))).all()
        return list(rows), "named by a person"
    if case_id:
        rows = session.scalars(base.where(LogEvent.case_id == case_id)).all()
        return list(rows), f"linked to case {case_id}"
    if technique:
        rows = session.scalars(base.where(LogEvent.mitre == technique)).all()
        return list(rows), f"labelled {technique}"
    return [], "none: no case, named events or technique"


def _benign_rows(
    session: Session,
    since: datetime,
    technique: Optional[str],
    attack_ids: Set[str],
) -> Tuple[List[LogEvent], bool]:
    statement = (
        select(LogEvent)
        .where(LogEvent.case_id.is_(None), LogEvent.time >= since)
        .order_by(LogEvent.time.desc())
        .limit(MAX_BENIGN_ROWS + len(attack_ids) + 1)
    )
    if technique:
        statement = statement.where(
            or_(LogEvent.mitre.is_(None), LogEvent.mitre != technique)
        )
    rows = [row for row in session.scalars(statement) if row.event_id not in attack_ids]
    return rows[:MAX_BENIGN_ROWS], len(rows) > MAX_BENIGN_ROWS


def run(
    session: Session,
    text: str,
    *,
    case_id: Optional[str],
    technique: Optional[str],
    event_ids: Optional[List[str]] = None,
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> Dict[str, Any]:
    """The replay's evidence. ``evaluated`` False carries ``reason`` and no counts."""
    now = datetime.now(timezone.utc)
    if session.scalar(select(LogEvent.event_id).limit(1)) is None:
        return {
            "evaluated": False,
            "reason": "log_events holds no rows. Ingest events on the Logs screen first.",
        }
    try:
        matcher, engine = matcher_for(text)
        attack, basis = _attack_rows(session, case_id, technique, event_ids)
        attack_ids = {row.event_id for row in attack}
        benign, truncated = _benign_rows(
            session, now - timedelta(days=window_days), technique, attack_ids
        )
        hits = _matching(matcher, attack)
        false_positives = _matching(matcher, benign)
    except NotReplayable as exc:
        return {"evaluated": False, "reason": str(exc)}
    doc = sigma_text.parse(text) or {}
    holding = _holding(benign, sigma_text.fields_read(doc))
    proven = bool(hits) and not false_positives and holding > 0
    unproven_because = None if proven else _why_unproven(attack, hits, false_positives)
    return {
        "evaluated": True,
        "engine": engine,
        "attack_basis": basis,
        "attack_rows": len(attack),
        "hits": len(hits),
        "hit_samples": [_sample(r) for r in hits[:SAMPLES]],
        "benign_rows": len(benign),
        "benign_rows_holding_fields": holding,
        "benign_truncated": truncated,
        "false_positives": len(false_positives),
        "false_positive_samples": [_sample(r) for r in false_positives[:SAMPLES]],
        "window_days": window_days,
        "event_ids": event_ids or [],
        "proven": proven,
        "unproven_because": unproven_because,
    }


def _why_unproven(
    attack: List[LogEvent],
    hits: List[LogEvent],
    false_positives: List[LogEvent],
) -> str:
    if not attack:
        return "No attack rows to test against. Link events to the case or name them."
    if not hits:
        return "The rule matched none of the attack rows."
    if false_positives:
        return "The rule matched rows no case claims."
    return "No benign row holds a field the rule reads, so zero matches proves nothing."


def since(
    session: Session,
    text: str,
    *,
    entered: datetime,
    case_id: Optional[str],
) -> Dict[str, Any]:
    """What the rule would have matched on rows that arrived since it entered shadow."""
    try:
        matcher, engine = matcher_for(text)
        rows = session.scalars(
            select(LogEvent)
            .where(LogEvent.time >= entered)
            .order_by(LogEvent.time.desc())
            .limit(MAX_BENIGN_ROWS)
        ).all()
        matched = _matching(matcher, rows)
    except NotReplayable as exc:
        return {"evaluated": False, "reason": str(exc)}
    in_case = [r for r in matched if case_id and r.case_id == case_id]
    return {
        "evaluated": True,
        "engine": engine,
        "since": entered.isoformat(),
        "rows": len(rows),
        "matches": len(matched),
        "matches_in_case": len(in_case),
        "matches_unclaimed": sum(1 for r in matched if r.case_id is None),
        "samples": [_sample(r) for r in matched[:SAMPLES]],
    }
