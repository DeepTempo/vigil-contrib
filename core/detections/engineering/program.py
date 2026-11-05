"""The program view: threat model, log sources, the heat map, rule health and red team runs.

One install is one client. Each answer reads what is stored and says what it cannot know.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.detections.engineering import proposals, sigma_text
from core.detections.engineering.replay import absent_from_sample, logged_fields
from core.detections.inventory import catalog
from core.detections.inventory.readers import OVERLAY_SOURCE
from core.detections.reconstruction import (
    _entities_from_step,
    _has_entity,
    _window,
    coverage_report,
)
from core.detections.tools import get_security_detection_tools
from core.federation import store as federation_store
from core.storage.config_service import ConfigService, get_config_service
from core.storage.models import (
    DetectionProposal,
    DetectionRule,
    DetectionRuleVersion,
    Finding,
    FindingMitrePrediction,
    LogEvent,
)
from core.storage.models.detection_proposal import ProposalState
from core.storage.unit_of_work import unit_of_work
from core.threat_intel.mitre_lookup import resolve_technique

THREAT_MODEL_KEY = "detection_engineering.threat_model"
RED_TEAM_KEY = "detection_engineering.red_team"
MAX_RED_TEAM_RUNS = 10
MAX_RED_TEAM_STEPS = 2000
FIRES_WINDOW_DAYS = 90
RULE_ROWS = 300
UNMAPPED_TACTIC = "Unmapped"

TACTIC_ORDER = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    UNMAPPED_TACTIC,
)
_TACTIC_NAMES = {name.lower(): name for name in TACTIC_ORDER}

THREAT_MODEL_FIELDS = ("sector", "crown_jewels", "exposure", "advisories", "notes")

# What a detection engineer asks of a client's logs. Matched as whole words of stored source and
# class names. "authentication" and "process" are absent: every Windows host logs those classes,
# and they say nothing about an identity provider or an EDR.
LOG_KINDS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("Windows events", ("winsec", "windows", "wineventlog", "sysmon")),
    ("Process and EDR", ("sysmon", "edr", "crowdstrike", "defender")),
    ("Linux syslog", ("syslog", "linux", "auditd")),
    ("Identity", ("entra", "okta", "active directory", "ldap")),
    ("Firewall", ("firewall", "paloalto", "fortinet", "pfsense")),
    ("Network flow", ("zeek", "flow", "network activity", "netflow")),
    ("DNS", ("dns",)),
    ("Web proxy and WAF", ("proxy", "waf", "http")),
    ("Mail", ("mail", "m365", "exchange", "smtp")),
    ("Cloud", ("cloudtrail", "aws", "azure", "gcp")),
)


def threat_model() -> Dict[str, Any]:
    stored = get_config_service().get_system_config(THREAT_MODEL_KEY) or {}
    return {
        **{name: str(stored.get(name) or "") for name in THREAT_MODEL_FIELDS},
        "priority_techniques": list(stored.get("priority_techniques") or []),
        "updated_by": stored.get("updated_by"),
        "updated_at": stored.get("updated_at"),
    }


def save_threat_model(fields: Dict[str, Any], actor: str) -> Dict[str, Any]:
    """A person's notes, kept in system_config. Vigil does not generate these."""
    priorities = []
    for raw in fields.get("priority_techniques") or []:
        value = str(raw).strip().upper()
        if not sigma_text.TECHNIQUE_ID.match(value):
            raise proposals.Refused(f"{raw!r} is not an ATT&CK technique id.")
        if value not in priorities:
            priorities.append(value)
    value = {
        **{name: str(fields.get(name) or "").strip() for name in THREAT_MODEL_FIELDS},
        "priority_techniques": priorities,
        "updated_by": actor,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    saved = ConfigService(actor).set_system_config(
        THREAT_MODEL_KEY, value, description="Detection engineering threat model"
    )
    if not saved:
        raise RuntimeError("The threat model could not be saved.")
    return threat_model()


def _active_rules(session: Session) -> Dict[str, Set[int]]:
    rows = session.execute(
        select(DetectionRule.id, DetectionRule.techniques).where(
            DetectionRule.status == "active"
        )
    ).all()
    by_technique: Dict[str, Set[int]] = {}
    for rule_id, techniques in rows:
        for technique in techniques or []:
            by_technique.setdefault(technique, set()).add(rule_id)
    return by_technique


def _rule_of_copy(session: Session) -> Dict[int, Tuple[Any, ...]]:
    """Which rule each stored copy belongs to, so one rule's copies count once.

    A linked SIEM copy belongs to its origin. The overlay saves one rule's copies under one name.
    """
    rows = session.execute(
        select(
            DetectionRule.id,
            DetectionRule.source,
            DetectionRule.name,
            DetectionRule.origin_rule_id,
            DetectionRule.link_kind,
        )
    ).all()
    own = {
        row.id: (
            (OVERLAY_SOURCE, row.name) if row.source == OVERLAY_SOURCE else (row.id,)
        )
        for row in rows
    }
    return {
        row.id: (
            own[row.origin_rule_id]
            if row.origin_rule_id is not None and row.link_kind != "declined"
            else own[row.id]
        )
        for row in rows
    }


def _rule_tactics(session: Session) -> Dict[str, str]:
    """A technique's tactic where a rule declares exactly one, for ids the lookup lacks."""
    out: Dict[str, str] = {}
    rows = session.execute(
        select(DetectionRule.techniques, DetectionRule.tactics).where(
            DetectionRule.status == "active"
        )
    )
    for techniques, tactics in rows:
        if tactics and len(tactics) == 1:
            for technique in techniques or []:
                out.setdefault(technique, tactics[0])
    return out


def _tactic_of(technique: str, declared: Dict[str, str]) -> Tuple[str, str]:
    _, name, tactic = resolve_technique(technique)
    if tactic == "Unknown":
        tactic = declared.get(technique, UNMAPPED_TACTIC)
    return name, _TACTIC_NAMES.get(tactic.lower(), UNMAPPED_TACTIC)


def _seen(session: Session) -> Dict[str, int]:
    """How often each technique was seen, on stored alerts and on stored log rows."""
    seen: Dict[str, int] = {}
    for column in (FindingMitrePrediction.technique_id, LogEvent.mitre):
        rows = session.execute(
            select(column, func.count()).where(column.is_not(None)).group_by(column)
        )
        for label, count in rows:
            value = str(label).strip().upper()
            if sigma_text.TECHNIQUE_ID.match(value):
                seen[value] = seen.get(value, 0) + count
    return seen


def _open_proposals(session: Session) -> Dict[str, Dict[str, Any]]:
    rows = session.execute(
        select(
            DetectionProposal.technique,
            DetectionProposal.proposal_id,
            DetectionProposal.state,
        )
        .where(
            DetectionProposal.technique.is_not(None),
            DetectionProposal.state != ProposalState.REJECTED,
        )
        .order_by(DetectionProposal.created_at)
    )
    return {
        technique: {"proposal_id": proposal_id, "state": state.value}
        for technique, proposal_id, state in rows
    }


def coverage() -> Dict[str, Any]:
    """One row per technique a rule declares, alerts or logs show, or a person prioritised.

    Validated: an active rule whose proposal's latest replay of its current text proved it.
    Unproven: an active rule and no such replay. No rule: no active rule declares it.
    """
    model = threat_model()
    proven = proposals.proven_rules()
    with unit_of_work() as session:
        by_technique = _active_rules(session)
        declared = _rule_tactics(session)
        seen = _seen(session)
        open_by_technique = _open_proposals(session)
        rule_of = _rule_of_copy(session)
        active = session.scalars(
            select(DetectionRule.id).where(DetectionRule.status == "active")
        ).all()
    priorities = set(model["priority_techniques"])
    siem_checks = catalog.siem_checks_by_technique()
    validated_by_rule = {row["rule_id"]: row for row in proven}
    rows = []
    for technique in sorted({*by_technique, *seen, *priorities}):
        rule_ids = by_technique.get(technique, set())
        proof = next(
            (validated_by_rule[i] for i in sorted(rule_ids) if i in validated_by_rule),
            None,
        )
        state = "validated" if proof else "unproven" if rule_ids else "no_rule"
        name, tactic = _tactic_of(technique, declared)
        rows.append(
            {
                "technique": technique,
                "name": name,
                "tactic": tactic,
                "state": state,
                "rules": len({rule_of[i] for i in rule_ids}),
                "rules_failing_checks": (siem_checks.get(technique) or {}).get(
                    "failing", 0
                ),
                "seen": seen.get(technique, 0),
                "priority": technique in priorities,
                "proof": proof,
                "proposal": open_by_technique.get(technique),
            }
        )
    tactics = [t for t in TACTIC_ORDER if any(row["tactic"] == t for row in rows)]
    return {
        "techniques": rows,
        "tactics": tactics,
        "summary": _summary(rows, priorities),
        "rule_total": len({rule_of[i] for i in active}),
    }


def _summary(rows: List[Dict[str, Any]], priorities: Set[str]) -> Dict[str, Any]:
    basis = "priority" if priorities else "all"
    counted = [row for row in rows if row["priority"]] if priorities else rows
    validated = sum(1 for row in counted if row["state"] == "validated")
    return {
        "validated": sum(1 for row in rows if row["state"] == "validated"),
        "unproven": sum(1 for row in rows if row["state"] == "unproven"),
        "no_rule": sum(1 for row in rows if row["state"] == "no_rule"),
        "basis": basis,
        "counted": len(counted),
        "counted_validated": validated,
        # Rounded down, so 100 means every one of them.
        "percent_validated": 100 * validated // len(counted) if counted else None,
    }


def _fires(session: Session) -> Dict[str, int]:
    """Findings per rule name in the window, read from what the alert named."""
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(
        days=FIRES_WINDOW_DAYS
    )
    named = func.coalesce(Finding.entity_context["rule_name"].astext, Finding.title)
    rows = session.execute(
        select(named, func.count())
        .where(Finding.timestamp >= since, named.is_not(None))
        .group_by(named)
    )
    return {name: count for name, count in rows}


def _health(
    status: str,
    checks: Dict[str, Any],
    missing: Optional[List[str]],
    fires: int,
) -> Tuple[str, str]:
    """(health, why), the first that holds, worst first."""
    runs = checks.get("runs") or {}
    sees = checks.get("sees") or {}
    if status == "disabled":
        return "disabled", "Switched off in the SIEM."
    if runs.get("result") == "fail":
        return "fails_to_run", str(runs.get("reason") or "Its last run failed.")
    if sees.get("result") == "fail":
        return "data_silent", str(sees.get("reason") or "Its data is not arriving.")
    if missing:
        return "missing_field", absent_from_sample(missing)
    if fires:
        return "fires", f"Fired {fires} times in {FIRES_WINDOW_DAYS} days."
    return "never_fired", f"No finding named it in {FIRES_WINDOW_DAYS} days."


_HEALTH_ORDER = (
    "fails_to_run",
    "data_silent",
    "missing_field",
    "disabled",
    "never_fired",
    "fires",
)


def rule_health() -> Dict[str, Any]:
    """The inventory, each rule's health, worst first, the first ``RULE_ROWS`` listed."""
    proven = {row["rule_id"] for row in proposals.proven_rules()}
    with unit_of_work() as session:
        logged = logged_fields(session)
        fires = _fires(session)
        rule_of = _rule_of_copy(session)
        rows = session.execute(
            select(
                DetectionRule, DetectionRuleVersion.content, DetectionRuleVersion.checks
            )
            .join(
                DetectionRuleVersion,
                (DetectionRuleVersion.rule_id == DetectionRule.id)
                & (DetectionRuleVersion.version == DetectionRule.latest_version),
            )
            .where(DetectionRule.status.in_(("active", "disabled")))
            .order_by(DetectionRule.id)
        ).all()
        listed = []
        counts = dict.fromkeys(_HEALTH_ORDER, 0)
        mapped = set()
        for rule, content, checks in rows:
            if rule.techniques:
                mapped.add(rule_of[rule.id])
            missing = None
            if rule.language == "sigma" and logged is not None:
                read = sigma_text.fields_read(content or {})
                missing = sorted(read - logged)
            count = fires.get(rule.name, 0)
            health, why = _health(rule.status, checks or {}, missing, count)
            counts[health] += 1
            listed.append(
                {
                    "rule_id": rule.id,
                    "name": rule.name,
                    "language": rule.language,
                    "source": rule.source,
                    "tool": catalog.tool_of(rule.source),
                    "status": rule.status,
                    "techniques": list(rule.techniques or []),
                    "health": health,
                    "why": why,
                    "fires": count,
                    "missing_fields": missing,
                    "runs": (checks or {}).get("runs"),
                    "sees": (checks or {}).get("sees"),
                    "validated": rule.id in proven,
                }
            )
    listed.sort(key=lambda row: (_HEALTH_ORDER.index(row["health"]), row["rule_id"]))
    return {
        "total": len(listed),
        "rule_total": len({rule_of[row["rule_id"]] for row in listed}),
        "mapped": len(mapped),
        "counts": counts,
        "validated": len({rule_of[r["rule_id"]] for r in listed if r["validated"]}),
        "rules": listed[:RULE_ROWS],
        "fires_window_days": FIRES_WINDOW_DAYS,
        "fields_known": logged is not None,
        "limits": (
            "Fires counts findings that name the rule, so a rule firing in a SIEM whose alerts "
            "do not reach Vigil counts zero. Missing fields are known only for Sigma rules, "
            "against what log_events holds. Runs and Sees results exist only for rules Vigil "
            "reads from Kibana and Wazuh."
        ),
    }


def _whole_words(*names: str) -> str:
    """Names padded with spaces, so a test for `` word `` cannot match inside another word."""
    return " ".join(
        ["", *(" ".join(re.findall(r"[a-z0-9]+", name.lower())) for name in names), ""]
    )


def log_sources() -> Dict[str, Any]:
    """Configured federation sources, and what log_events actually holds."""
    configured = [
        {
            "source_id": row["source_id"],
            "enabled": bool(row.get("enabled")),
            "last_success_at": row.get("last_success_at"),
            "last_error": row.get("last_error"),
        }
        for row in federation_store.read_sources()
    ]
    with unit_of_work() as session:
        rows = session.execute(
            select(
                LogEvent.source,
                LogEvent.event_class,
                func.count(),
                func.min(LogEvent.time),
                func.max(LogEvent.time),
            )
            .group_by(LogEvent.source, LogEvent.event_class)
            .order_by(func.count().desc())
        ).all()
    stored = [
        {
            "source": source,
            "event_class": event_class,
            "rows": count,
            "first": first.isoformat(),
            "last": last.isoformat(),
        }
        for source, event_class, count, first, last in rows
    ]
    haystack = [
        (_whole_words(row["source"], row["event_class"]), row["rows"]) for row in stored
    ]
    configured_words = [_whole_words(row["source_id"]) for row in configured]
    kinds = []
    for kind, words in LOG_KINDS:
        wanted = [f" {word} " for word in words]
        held = sum(n for text, n in haystack if any(w in text for w in wanted))
        kinds.append(
            {
                "kind": kind,
                "rows": held,
                "configured": any(
                    w in text for text in configured_words for w in wanted
                ),
            }
        )
    return {
        "configured": configured,
        "stored": stored,
        "total_rows": sum(row["rows"] for row in stored),
        "kinds": kinds,
        "kinds_basis": "Matched on the names of stored sources and event classes.",
    }


_STEP_ALIASES = {
    "technique_id": ("technique_id", "Technique", "technique"),
    "hostname": ("hostname", "Hostname", "host", "computer_name"),
    "user": ("user", "Username", "username"),
    "src_ip": ("src_ip", "IP Address"),
    "started_at": ("started_at", "start", "timestamp", "Execution Time (UTC)"),
    "ended_at": ("ended_at", "end"),
    "id": ("id", "step_id", "GUID"),
    "name": ("name", "Test Name", "test_name", "command"),
}


def _normal_step(raw: Any, index: int, window_minutes: int) -> Dict[str, Any]:
    """One run event as a trace step. Accepts Vigil's keys and Invoke-AtomicRedTeam's log."""
    if not isinstance(raw, dict):
        raise proposals.Refused(f"Event {index + 1} is not a JSON object.")
    step: Dict[str, Any] = {}
    for key, aliases in _STEP_ALIASES.items():
        for alias in aliases:
            value = raw.get(alias)
            if value not in (None, ""):
                step[key] = value
                break
    window = _window(step)
    if window is not None and "ended_at" not in step:
        step["ended_at"] = (
            (window[0] + timedelta(minutes=window_minutes))
            .replace(tzinfo=timezone.utc)
            .isoformat()
        )
    technique = step.get("technique_id")
    if isinstance(technique, str):
        step["technique_id"] = technique.strip().upper()
    return step


async def run_red_team(
    *, name: str, events: List[Any], actor: str, window_minutes: int = 15
) -> Dict[str, Any]:
    """Mark each uploaded step rule, loglm, both or missed. Vigil did not run these steps.

    A step with no time or no host, address or user cannot be joined to a finding, so it reads
    missed; ``could_not_correlate`` tells that apart from a real miss.
    """
    if not events:
        raise proposals.Refused("Upload at least one run event.")
    if len(events) > MAX_RED_TEAM_STEPS:
        raise proposals.Refused(f"A run holds at most {MAX_RED_TEAM_STEPS} events.")
    steps = [_normal_step(raw, i, window_minutes) for i, raw in enumerate(events)]
    reconstructed = await get_security_detection_tools().reconstruct_run(steps=steps)
    rows = []
    for step, record in zip(steps, reconstructed["steps"]):
        correlatable = _window(step) is not None and _has_entity(
            _entities_from_step(step)
        )
        rows.append(
            {
                "index": record["index"],
                "id": step.get("id"),
                "name": step.get("name"),
                "technique_id": step.get("technique_id"),
                "hostname": step.get("hostname"),
                "user": step.get("user"),
                "started_at": step.get("started_at"),
                "verdict": record["verdict"],
                "could_not_correlate": not correlatable,
                "citations": record["citations"][:5],
            }
        )
    counts = {
        verdict: sum(1 for row in rows if row["verdict"] == verdict)
        for verdict in ("rule", "loglm", "both", "missed")
    }
    run = {
        "name": name.strip() or "Uploaded run",
        "uploaded_by": actor,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "window_minutes": window_minutes,
        "steps": rows,
        "counts": counts,
        "techniques": [
            {"technique_id": row["technique_id"], "verdict": row["verdict"]}
            for row in coverage_report(steps, reconstructed)["techniques"]
        ],
    }
    _remember_run(run, actor)
    return run


def _remember_run(run: Dict[str, Any], actor: str) -> None:
    runs = red_team_runs()["runs"]
    saved = ConfigService(actor).set_system_config(
        RED_TEAM_KEY,
        {"runs": [run, *runs][:MAX_RED_TEAM_RUNS]},
        description="Detection engineering red team run results",
    )
    if not saved:
        raise RuntimeError("The run could not be saved.")


def red_team_runs() -> Dict[str, Any]:
    stored = get_config_service().get_system_config(RED_TEAM_KEY) or {}
    return {"runs": list(stored.get("runs") or [])}


def without_citations(runs: Dict[str, Any]) -> Dict[str, Any]:
    """A step cites the findings it joined to, which need findings.read."""
    return {
        "runs": [
            {
                **run,
                "steps": [{**step, "citations": []} for step in run.get("steps") or []],
                "citations_withheld": True,
            }
            for run in runs["runs"]
        ]
    }
