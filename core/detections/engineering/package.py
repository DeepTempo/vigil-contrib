"""Wrap a backend's output into the file a SIEM's detections-as-code repo expects, disabled.

Ported from the detection write-back tool, whose eval measured the rates in targets.py on these
exact packagers. Backends that emit a whole artifact pass through; Panther and Kusto emit only
the query, so they get the surrounding metadata here. Panther's LogTypes are left for a person.

``splunk_copy`` and ``elastic_copy`` build the form Vigil's overlay reads. A copy's id comes from
the Sigma id, so a tuned rule lands on the same overlay rule as a new version.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Callable, Dict, List, Tuple

import yaml

from core.detections.inventory.rollout import PERSON_PROMOTES

_LEVEL_TO_PANTHER = {
    "informational": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}
_LEVEL_TO_SENTINEL = {
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "High",
}
_LEVEL_TO_RISK = {
    "informational": 21,
    "low": 21,
    "medium": 47,
    "high": 73,
    "critical": 99,
}
_TACTICS = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "ResourceDevelopment",
    "initial_access": "InitialAccess",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "PrivilegeEscalation",
    "defense_evasion": "DefenseEvasion",
    "credential_access": "CredentialAccess",
    "discovery": "Discovery",
    "lateral_movement": "LateralMovement",
    "collection": "Collection",
    "command_and_control": "CommandAndControl",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")[:80] or "detection"


def attack_ids(rule: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """(tactic names, technique ids) from Sigma ``attack.*`` tags."""
    tactics, techniques = [], []
    for tag in rule.get("tags") or []:
        tag = str(tag).lower()
        if not tag.startswith("attack."):
            continue
        rest = tag[len("attack.") :]
        if re.fullmatch(r"t\d{4}(\.\d{3})?", rest):
            techniques.append(rest.upper())
        elif rest.replace("-", "_") in _TACTICS:
            tactics.append(_TACTICS[rest.replace("-", "_")])
    return tactics, techniques


def _panther(rule: Dict[str, Any], output: str, raw: Any = None) -> str:
    detection = yaml.safe_load(output)
    if isinstance(detection, dict) and len(detection) == 1 and "Detection" in detection:
        detection = detection["Detection"]
    _, techniques = attack_ids(rule)
    doc = {
        "AnalysisType": "rule",
        "RuleID": f"Vigil.{slug(rule.get('title', 'detection')).title().replace('_', '.')}",
        "DisplayName": rule.get("title", ""),
        "Enabled": False,
        "LogTypes": ["TODO.SetLogType"],
        "Severity": _LEVEL_TO_PANTHER.get(str(rule.get("level", "medium")), "Medium"),
        "Description": rule.get("description", ""),
        "Reports": {"MITRE ATT&CK": techniques} if techniques else {},
        "Tags": ["Vigil", "Sigma"],
        "Detection": detection if isinstance(detection, list) else [detection],
    }
    if rule.get("falsepositives"):
        doc["Runbook"] = "Known false positives: " + "; ".join(
            map(str, rule["falsepositives"])
        )
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


def _sentinel(rule: Dict[str, Any], output: str, raw: Any = None) -> str:
    tactics, techniques = attack_ids(rule)
    doc = {
        "id": str(rule.get("id", "")),
        "name": rule.get("title", ""),
        "description": rule.get("description", ""),
        "severity": _LEVEL_TO_SENTINEL.get(str(rule.get("level", "medium")), "Medium"),
        "requiredDataConnectors": [],
        "queryFrequency": "1h",
        "queryPeriod": "1h",
        "triggerOperator": "gt",
        "triggerThreshold": 0,
        "tactics": tactics,
        "relevantTechniques": [t.split(".")[0] for t in techniques],
        "query": output.rstrip() + "\n",
        "version": "1.0.0",
        "kind": "Scheduled",
        "status": "Disabled",
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=1000)


def _rules_of(raw: Any) -> List[Dict[str, Any]]:
    """JSON rule objects from a backend's output: a dict, a list, or text holding some."""
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [doc for item in raw for doc in _rules_of(item)]
    if not isinstance(raw, str):
        return []
    out: List[Dict[str, Any]] = []
    decoder, text, i = json.JSONDecoder(), raw.strip(), 0
    while i < len(text):
        try:
            doc, end = decoder.raw_decode(text, i)
        except ValueError:
            return out
        if isinstance(doc, list):
            out.extend(_rules_of(doc))
        elif isinstance(doc, dict):
            out.append(doc)
        i = end
        while i < len(text) and text[i].isspace():
            i += 1
    return out


def _elastic(rule: Dict[str, Any], output: str, raw: Any = None) -> str:
    """Kibana's rule import wants one compact JSON object per line."""
    docs = _rules_of(raw) or _rules_of(output)
    for doc in docs:
        doc["enabled"] = False
    compact = (json.dumps(doc, separators=(",", ":")) + "\n" for doc in docs)
    return "".join(compact) or output


def _opensearch(rule: Dict[str, Any], output: str, raw: Any = None) -> str:
    docs = _rules_of(raw) or _rules_of(output)
    for doc in docs:
        if "enabled" in doc:
            doc["enabled"] = False
    if not docs:
        return output
    return json.dumps(docs[0] if len(docs) == 1 else docs, indent=2) + "\n"


def _splunk(rule: Dict[str, Any], output: str, raw: Any = None) -> str:
    lines = []
    for line in output.splitlines():
        lines.append(line)
        if line.startswith("[") and line.strip() != "[default]":
            lines += ["disabled = 1", "enableSched = 1", "cron_schedule = */15 * * * *"]
    return "\n".join(lines) + "\n"


def _fix_meta(meta: str) -> str:
    """Rewrite each ``key = "value"`` in a YARA-L meta block with the value escaped.
    The backend leaves quotes raw and lets long descriptions run over several lines."""
    out: List[str] = []
    lines = meta.split("\n")
    i = 0
    while i < len(lines):
        m = re.match(r'^(\s*\w+\s*=\s*)"(.*)$', lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue
        prefix, value = m.group(1), m.group(2)
        while not re.search(r'(?<!\\)"\s*$', value) and i + 1 < len(lines):
            i += 1
            value += "\n" + lines[i].strip()
        value = re.sub(r'"\s*$', "", value)
        value = (
            value.replace('\\"', '"')
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
        )
        out.append(f'{prefix}"{value}"')
        i += 1
    return "\n".join(out)


def _chronicle(rule: Dict[str, Any], output: str, raw: Any = None) -> str:
    """Repair what the secops backend gets wrong against the YARA-L 2.0 grammar."""

    def name(m: re.Match) -> str:
        ident = re.sub(r"[^A-Za-z0-9_]", "_", m.group(2))
        return (
            m.group(1)
            + (ident if not ident[:1].isdigit() else "r_" + ident)
            + m.group(3)
        )

    text = re.sub(r"^(\s*rule\s+)(\S+?)(\s*\{)", name, output, count=1, flags=re.M)
    if "meta:" in text and "events:" in text:
        head, rest = text.split("meta:", 1)
        meta, tail = rest.split("events:", 1)
        text = head + "meta:" + _fix_meta(meta) + "events:" + tail
    return re.sub(r"^(\s*)conditions:", r"\1condition:", text, flags=re.M)


def _raw(comment: str) -> Callable[..., str]:
    def wrap(rule: Dict[str, Any], output: str, raw: Any = None) -> str:
        header = (
            f"{comment} {rule.get('title', '')}, generated from Sigma rule "
            f"{rule.get('id', '')}\n"
        )
        return header + output

    return wrap


_PACKAGERS: Dict[str, Callable[..., str]] = {
    "panther": _panther,
    "elastic": _elastic,
    "opensearch": _opensearch,
    "splunk": _splunk,
    "chronicle": _chronicle,
    "sentinel": _sentinel,
    "defender": _raw("//"),
    "elastic-lucene": _raw("#"),
    "qradar": _raw("--"),
    "datadog": _raw("#"),
    "crowdstrike": _raw("//"),
    "sentinelone": _raw("//"),
}


def package(target: str, rule: Dict[str, Any], output: str, raw: Any = None) -> str:
    packer = _PACKAGERS.get(target)
    return packer(rule, output, raw) if packer else output


def _copy_id(rule: Dict[str, Any], language: str) -> str:
    return str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"vigil-copy:{language}:{rule.get('id')}")
    )


def splunk_copy(rule: Dict[str, Any], query: str) -> str:
    _, techniques = attack_ids(rule)
    return yaml.safe_dump(
        {
            "id": _copy_id(rule, "splunk"),
            "name": rule.get("title", ""),
            "description": rule.get("description", ""),
            "type": "TTP",
            "search": query,
            "mitre_attack_id": techniques,
        },
        sort_keys=False,
        allow_unicode=True,
    )


ELASTIC_INDEX = "logs-*"


def elastic_copy(rule: Dict[str, Any], query: str, language: str) -> str:
    """detection-rules TOML. A JSON string is a valid TOML basic string.

    The rollout runs this copy. A person moves a proposal to live, so the copy says the rollout
    may not.
    """
    _, techniques = attack_ids(rule)
    level = str(rule.get("level", "medium"))
    lines = [
        "[rule]",
        f"rule_id = {json.dumps(_copy_id(rule, 'elastic'))}",
        f"name = {json.dumps(str(rule.get('title', '')))}",
        f"description = {json.dumps(str(rule.get('description', '')))}",
        f'type = {json.dumps("esql" if language == "esql" else "query")}',
        f"language = {json.dumps(language)}",
        *([] if language == "esql" else [f"index = {json.dumps([ELASTIC_INDEX])}"]),
        f"query = {json.dumps(query)}",
        f"{PERSON_PROMOTES} = true",
        f"severity = {json.dumps(level if level != 'informational' else 'low')}",
        f"risk_score = {_LEVEL_TO_RISK.get(level, 47)}",
    ]
    for technique in techniques:
        lines += [
            "",
            "[[rule.threat]]",
            'framework = "MITRE ATT&CK"',
            "[[rule.threat.technique]]",
            f"id = {json.dumps(technique)}",
        ]
    return "\n".join(lines) + "\n"
