"""Files of log rows into ``log_events``.

A row's shape is found by the table of ``Shape``s, whose field maps say which of the
source's own fields fill each column. Adding a source is adding a row to ``SHAPES``.

``event_id`` hashes the record without its ``loglm`` and ``case_id`` columns, so sending
a file twice stores nothing new, and sending it again with scores or a case fills them in.
"""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

from sqlalchemy import func, literal_column, or_, select
from sqlalchemy.dialects.postgresql import insert

from core.log_events.query import search_text
from core.log_events.retention import cutoff, sweep
from core.storage.models.case import Case
from core.storage.models.log_event import LOG_SEVERITIES, LogEvent
from core.storage.unit_of_work import unit_of_work

BATCH_ROWS = 1000
MAX_RECORD_CHARS = 1_000_000
MAX_SUMMARY_CHARS = 2_000
MAX_FLATTEN_DEPTH = 8
FUTURE_SLACK = timedelta(days=1)
GENERIC_SOURCE = "generic"

# Why a row was not stored.
DROP_NOT_PARSEABLE = "not_parseable"
DROP_NOT_OBJECT = "not_object"
DROP_NO_TIME = "no_time"
DROP_TOO_LARGE = "too_large"
DROP_PAST_RETENTION = "past_retention"
DROP_FUTURE_TIME = "future_time"

# What was left out of a row that was stored.
NOTE_BAD_SCORE = "bad_score"
NOTE_UNKNOWN_CASE = "unknown_case"
NOTE_REDACTED = "credentials_redacted"
NOTE_JSON_TOO_LARGE = "json_too_large_to_check"

REDACTED = "[redacted]"
TOO_LARGE_TO_CHECK = "[JSON too large to check for credentials]"
REDACTED_TAG = "redacted"
MAX_EMBEDDED_JSON_CHARS = 200_000
MAX_EMBEDDED_JSON_DEPTH = 4
MAX_EMBEDDED_JSON_TRIES = 64
_JSON = json.JSONDecoder()
_JSON_OPENS = re.compile(r"[{\[]")
# What a JSON object or a list of strings starts with, escaped or not.
_LOOKS_LIKE_JSON = re.compile(r'[{\[]\s*\\*"')
# A field is a credential when its name ends in one of these. "token_type" and
# "password_changed" name something about a credential and keep their values.
_CREDENTIAL_NAME = re.compile(
    r"(password|passwd|pwd|secret|token|api_?key|authorization|cookie"
    r"|secret_access_key|private_key)$"
)
_BEARER = re.compile(r"\b(bearer)\s+[a-z0-9._~+/=-]+", re.I)
# These headers run to the end of the line or its closing quote: "Cookie: a=1; b=2" holds two.
# No \b before a name: as in _CREDENTIAL_NAME, it may end a longer one, such as client_secret.
# A boolean or null says nothing secret, as in _redacted, which keeps them.
_HEADER_IN_TEXT = re.compile(
    r"(authorization|cookie)"
    r"(\\*[\"']?\s*[=:]\s*\\*[\"']?)"
    r"(?!\s*(?:true|false|null)\b)[^\r\n'\"]+",
    re.I,
)
_CREDENTIAL_IN_TEXT = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key"
    r"|secret[_-]?access[_-]?key|private[_-]?key)"
    r"(\\*[\"']?\s*[=:]\s*)"
    r"(?!(?:true|false|null)\b)"
    r"(\\*\"[^\"]*\"|'[^']*'|[^\s&;,]+)",
    re.I,
)

SCORE_FIELDS = ("loglm", "loglm_score")
CASE_FIELDS = ("case_id",)
# Wrappers around an array of rows: Graph's value, Azure diagnostics' records, and so on.
ENVELOPES = ("value", "records", "events", "logs", "data", "items", "results")
UNSET = ("", "-", "(empty)", "(unset)", "n/a", "null", "none")

SEVERITY_WORDS = {
    "critical": "critical",
    "crit": "critical",
    "fatal": "critical",
    "emergency": "critical",
    "alert": "critical",
    "high": "high",
    "error": "high",
    "err": "high",
    "severe": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "low": "low",
    "notice": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "debug": "info",
}

_TIME_FORMATS = (
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y, %I:%M:%S %p",
)
_MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_SOURCE_KEY = re.compile(r"[^a-z0-9_.-]+")
_TEMPLATE_VAR = re.compile(r"\{([a-z_]+)\}")


@dataclass(frozen=True)
class Outcome:
    """What one of a source's codes means."""

    what: str
    action: Optional[str] = None
    event_class: Optional[str] = None
    # The column for the machine that wrote the event. On a logon it is the target.
    host_role: str = "src_host"


@dataclass(frozen=True)
class Shape:
    key: str
    source: str
    label: str
    # A row is this shape when every field of any one clause is there, with that value if not None.
    detect: Tuple[Mapping[str, Optional[str]], ...]
    event_class: str
    # Column or template name to the source's fields, first one with a value wins, all lower case.
    fields: Mapping[str, Tuple[str, ...]]
    # Each segment shows only when its names have values.
    summary: Tuple[str, ...] = ()
    codes: Mapping[str, Outcome] = field(default_factory=dict)
    severity_codes: Mapping[str, str] = field(default_factory=dict)


def _win(*names: str) -> Tuple[str, ...]:
    """A Windows field, flat or in the nestings exporters and Winlogbeat write."""
    prefixes = (
        "",
        "eventdata.",
        "event.eventdata.",
        "winlog.event_data.",
        "event_data.",
    )
    return tuple(f"{p}{n}" for n in names for p in prefixes)


_WIN_SYSTEM = {
    "time": (
        "timecreated",
        "timecreated.systemtime",
        "system.timecreated.systemtime",
        "event.system.timecreated.systemtime",
        "utctime",
        "eventtime",
        "@timestamp",
    ),
    "host": (
        "computer",
        "system.computer",
        "event.system.computer",
        "winlog.computer_name",
        "host.name",
        "hostname",
    ),
    "code": (
        "eventid",
        "system.eventid",
        "event.system.eventid",
        "winlog.event_id",
        "event.code",
    ),
}


def _channel(name: str) -> Tuple[Dict[str, Optional[str]], ...]:
    return tuple(
        {path: name.lower()}
        for path in (
            "channel",
            "system.channel",
            "event.system.channel",
            "winlog.channel",
        )
    )


def _ent(*names: str) -> Tuple[str, ...]:
    """An Entra field, flat as Graph sends it or under Azure diagnostics' properties."""
    return tuple(f"{p}{n}" for n in names for p in ("", "properties."))


def _logon(what: str, action: str) -> Outcome:
    return Outcome(what, action, "Authentication", host_role="dst_host")


_SIGNIN_OK = Outcome("Sign-in succeeded", "signin_ok")
_SIGNIN_FAILED = Outcome("Sign-in failed", "signin_failed")

SHAPES: Tuple[Shape, ...] = (
    Shape(
        key="sysmon",
        source="sysmon",
        label="Sysmon",
        detect=(
            *_channel("Microsoft-Windows-Sysmon/Operational"),
            {"utctime": None, "processguid": None},
        ),
        event_class="Process",
        fields={
            **_WIN_SYSTEM,
            "user_name": _win("user"),
            "src_ip": _win("sourceip"),
            "dst_ip": _win("destinationip"),
            "dst_host": _win("destinationhostname", "queryname"),
            "dst_port": _win("destinationport"),
            "image": _win("image"),
            "cmdline": _win("commandline"),
            "query": _win("queryname"),
            "target": _win("targetfilename"),
        },
        summary=(
            "{what}",
            "{image}",
            "{cmdline}",
            "{query}",
            "{target}",
            "to {dst_ip}",
            "port {dst_port}",
        ),
        codes={
            "1": Outcome("Process started", "process_start", "Process"),
            "3": Outcome("Network connection", "network_connect", "Network"),
            "5": Outcome("Process ended", "process_end", "Process"),
            "7": Outcome("Image loaded", "image_load", "Process"),
            "8": Outcome("Remote thread created", "remote_thread", "Process"),
            "10": Outcome("Process accessed", "process_access", "Process"),
            "11": Outcome("File created", "file_create", "File"),
            "13": Outcome("Registry value set", "registry_set", "Registry"),
            "22": Outcome("DNS query", "dns_query", "DNS"),
        },
    ),
    Shape(
        key="windows_security",
        source="winsec",
        label="Windows Security",
        detect=(
            *_channel("Security"),
            {"eventid": None, "targetusername": None},
            {"eventid": None, "subjectusername": None},
        ),
        event_class="Windows event",
        fields={
            **_WIN_SYSTEM,
            "user_name": _win("targetusername", "subjectusername"),
            "src_ip": _win("ipaddress"),
            "src_host": _win("workstationname"),
            "logon_type": _win("logontype"),
            "process": _win("newprocessname", "processname"),
            "cmdline": _win("commandline"),
        },
        summary=(
            "{what}",
            "for {user_name}",
            "from {src_ip}",
            "logon type {logon_type}",
            "{process}",
            "{cmdline}",
        ),
        codes={
            "4624": _logon("Logon succeeded", "logon_success"),
            "4625": _logon("Logon failed", "logon_failed"),
            "4634": _logon("Logged off", "logoff"),
            "4648": _logon("Logon with explicit credentials", "logon_explicit"),
            "4672": _logon("Special privileges assigned", "privilege_assigned"),
            "4688": Outcome("Process started", "process_start", "Process"),
            "4698": Outcome("Scheduled task created", "task_created", "Persistence"),
            "4720": Outcome("User created", "user_created", "Account"),
            "4726": Outcome("User deleted", "user_deleted", "Account"),
            "4728": Outcome(
                "Member added to a global group", "group_member_added", "Account"
            ),
            "4732": Outcome(
                "Member added to a local group", "group_member_added", "Account"
            ),
            "4740": Outcome("Account locked out", "account_locked", "Account"),
            "4768": _logon("Kerberos ticket requested", "kerberos_tgt"),
            "4769": _logon("Kerberos service ticket requested", "kerberos_service"),
            "4776": _logon("Credentials validated", "credential_validate"),
            "1102": Outcome("Audit log cleared", "audit_cleared", "Defense evasion"),
        },
    ),
    Shape(
        key="zeek_dns",
        source="dns",
        label="DNS",
        detect=({"id.orig_h": None, "query": None},),
        event_class="DNS",
        fields={
            "time": ("ts",),
            "src_ip": ("id.orig_h",),
            "dst_ip": ("id.resp_h",),
            "dst_host": ("query",),
            "dst_port": ("id.resp_p",),
            "action": ("rcode_name",),
            "query": ("query",),
            "qtype": ("qtype_name",),
            "answers": ("answers",),
        },
        summary=("{qtype} query", "{query}", "answered {answers}"),
    ),
    Shape(
        key="dns",
        source="dns",
        label="DNS",
        detect=({"query_name": None}, {"qname": None}, {"dns.question.name": None}),
        event_class="DNS",
        fields={
            "time": ("time", "timestamp", "@timestamp", "ts", "event_time"),
            "src_ip": ("client_ip", "src_ip", "source.ip", "client"),
            "dst_ip": ("server_ip", "dst_ip", "destination.ip", "resolver"),
            "dst_host": ("query_name", "qname", "dns.question.name"),
            "action": ("rcode", "response_code", "dns.response_code"),
            "src_host": ("host", "hostname", "host.name"),
            "query": ("query_name", "qname", "dns.question.name"),
            "qtype": ("query_type", "qtype", "dns.question.type"),
            "answers": ("answer", "answers", "dns.answers.data"),
        },
        summary=("{qtype} query", "{query}", "answered {answers}"),
    ),
    Shape(
        key="zeek_conn",
        source="zeek",
        label="Zeek",
        detect=({"id.orig_h": None, "id.resp_h": None},),
        event_class="Network",
        fields={
            "time": ("ts",),
            "src_ip": ("id.orig_h",),
            "dst_ip": ("id.resp_h",),
            "dst_port": ("id.resp_p",),
            "code": ("conn_state",),
            "proto": ("proto",),
            "service": ("service",),
            "sent": ("orig_bytes",),
            "received": ("resp_bytes",),
        },
        summary=(
            "{proto}",
            "{service}",
            "{src_ip} to {dst_ip}",
            "port {dst_port}",
            "{what}",
            "{sent} bytes out",
            "{received} bytes in",
        ),
        codes={
            "SF": Outcome("completed", "completed"),
            "S0": Outcome("no reply", "no_reply"),
            "S1": Outcome("established", "established"),
            "REJ": Outcome("rejected", "rejected"),
            "RSTO": Outcome("reset by the source", "reset"),
            "RSTR": Outcome("reset by the destination", "reset"),
            "OTH": Outcome("no handshake seen", "partial"),
        },
    ),
    Shape(
        key="paloalto",
        source="paloalto",
        label="Palo Alto",
        detect=(
            {"receive time": None, "source address": None},
            {"receive_time": None, "src": None},
            {"receive_time": None, "source_address": None},
        ),
        event_class="Firewall",
        fields={
            "time": (
                "receive time",
                "receive_time",
                "generated time",
                "time_generated",
            ),
            "src_ip": ("source address", "source_address", "src"),
            "dst_ip": ("destination address", "destination_address", "dst"),
            "dst_port": ("destination port", "destination_port", "dport"),
            "user_name": ("source user", "source_user", "srcuser"),
            "action": ("action",),
            "severity": ("severity",),
            "src_host": ("device name", "device_name"),
            "app": ("application", "app"),
            "rule": ("rule", "rule_name"),
            "threat": ("threat/content name", "threat_name", "threatid"),
        },
        summary=(
            "{action}",
            "{app}",
            "{src_ip} to {dst_ip}",
            "port {dst_port}",
            "by rule {rule}",
            "{threat}",
        ),
    ),
    Shape(
        key="crowdstrike",
        source="crowdstrike",
        label="CrowdStrike",
        detect=(
            {"event_simplename": None},
            {"metadata.eventtype": None, "event.computername": None},
            {"detectname": None, "computername": None},
        ),
        event_class="Endpoint",
        fields={
            "time": (
                "timestamp",
                "contexttimestamp",
                "metadata.eventcreationtime",
                "created_timestamp",
                "@timestamp",
            ),
            "src_host": ("computername", "event.computername", "device.hostname"),
            "src_ip": ("localaddressip4", "localip", "event.localip", "aip"),
            "dst_ip": ("remoteaddressip4", "remoteip"),
            "dst_host": ("domainname",),
            "dst_port": ("remoteport",),
            "user_name": ("username", "event.username", "user_name"),
            "severity": ("severity", "event.severity", "severity_name"),
            "mitre": ("techniqueid", "event.techniqueid", "technique"),
            "code": ("event_simplename", "metadata.eventtype"),
            "detect": ("detectname", "event.detectname"),
            "image": ("imagefilename", "filename", "event.filename"),
            "cmdline": ("commandline", "event.commandline"),
            "query": ("domainname",),
        },
        summary=(
            "{detect}",
            "{what}",
            "{image}",
            "{cmdline}",
            "{query}",
            "to {dst_ip}",
            "port {dst_port}",
        ),
        codes={
            "ProcessRollup2": Outcome("Process started", "process_start", "Process"),
            "SyntheticProcessRollup2": Outcome(
                "Process started", "process_start", "Process"
            ),
            "NetworkConnectIP4": Outcome(
                "Network connection", "network_connect", "Network"
            ),
            "DnsRequest": Outcome("DNS query", "dns_query", "DNS"),
            "UserLogon": Outcome("Logon succeeded", "logon_success", "Authentication"),
            "UserLogonFailed2": Outcome(
                "Logon failed", "logon_failed", "Authentication"
            ),
            "DetectionSummaryEvent": Outcome("Detection", "detection", "Detection"),
            "*": Outcome("Sensor event"),
        },
        severity_codes={
            "5": "critical",
            "4": "high",
            "3": "medium",
            "2": "low",
            "1": "info",
            "0": "info",
        },
    ),
    Shape(
        key="entra",
        source="entra",
        label="Entra ID",
        detect=(
            {"userprincipalname": None, "createddatetime": None},
            {"properties.userprincipalname": None, "properties.createddatetime": None},
            {"date (utc)": None, "username": None, "ip address": None},
        ),
        event_class="Sign-in",
        fields={
            "time": (*_ent("createddatetime"), "date (utc)", "time"),
            "user_name": (*_ent("userprincipalname"), "username"),
            "src_ip": (*_ent("ipaddress"), "ip address", "calleripaddress"),
            "src_host": _ent("devicedetail.displayname"),
            "dst_host": (*_ent("appdisplayname"), "application"),
            "severity": _ent("riskleveldurinsignin"),
            "code": (*_ent("status.errorcode"), "sign-in error code"),
            "app": (*_ent("appdisplayname"), "application"),
            "reason": (*_ent("status.failurereason"), "failure reason"),
            "city": (*_ent("location.city"), "location"),
        },
        summary=(
            "{what}",
            "for {user_name}",
            "to {app}",
            "from {src_ip}",
            "{city}",
            "{reason}",
        ),
        codes={"0": _SIGNIN_OK, "*": _SIGNIN_FAILED},
    ),
    Shape(
        key="generic",
        source=GENERIC_SOURCE,
        label="Other",
        detect=({},),
        event_class="",
        fields={
            "time": (
                "time",
                "timestamp",
                "@timestamp",
                "ts",
                "event_time",
                "eventtime",
                "datetime",
                "date",
            ),
            "source": (
                "source",
                "source_type",
                "sourcetype",
                "log_source",
                "product",
                "event.module",
                "event.dataset",
            ),
            "src_ip": ("src_ip", "source_ip", "srcip", "src", "source.ip", "client_ip"),
            "src_host": (
                "src_host",
                "source_host",
                "host",
                "hostname",
                "host.name",
                "computer",
                "device",
            ),
            "dst_ip": (
                "dst_ip",
                "dest_ip",
                "destination_ip",
                "dstip",
                "dst",
                "dest",
                "destination.ip",
                "server_ip",
            ),
            "dst_host": (
                "dst_host",
                "dest_host",
                "destination_host",
                "destination.domain",
                "server",
            ),
            "dst_port": (
                "dst_port",
                "dest_port",
                "destination_port",
                "dport",
                "destination.port",
                "port",
            ),
            "user_name": ("user_name", "user", "username", "user.name", "account"),
            "action": ("action", "event.action", "outcome", "event.outcome", "status"),
            "severity": (
                "severity",
                "level",
                "log.level",
                "event.severity",
                "priority",
            ),
            "event_class": (
                "event_class",
                "class",
                "category",
                "event.category",
                "type",
                "event.type",
            ),
            "mitre": (
                "mitre",
                "technique",
                "technique_id",
                "threat.technique.id",
                "attack.technique",
            ),
            "summary": (
                "summary",
                "message",
                "msg",
                "description",
                "event.original",
                "title",
            ),
        },
    ),
)

_COLUMN_LIMITS = {
    c.name: c.type.length
    for c in LogEvent.__table__.columns
    if getattr(c.type, "length", None)
}


class Dropped(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class IngestReport:
    rows: int = 0
    stored: int = 0
    updated: int = 0
    unchanged: int = 0
    swept: int = 0
    dropped: Counter = field(default_factory=Counter)
    notes: Counter = field(default_factory=Counter)
    shapes: Counter = field(default_factory=Counter)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rows": self.rows,
            "stored": self.stored,
            "updated": self.updated,
            "unchanged": self.unchanged,
            "swept": self.swept,
            "dropped": dict(self.dropped),
            "notes": dict(self.notes),
            "shapes": dict(self.shapes),
        }


def source_label(source: str) -> str:
    """A stored source's name to show: the shape's, or its own key for any other source."""
    for shape in SHAPES:
        if shape.source == source and source != GENERIC_SOURCE:
            return shape.label
    return source


def _clean(value: Any) -> Any:
    """What JSONB and Postgres text can hold: no NUL, no lone surrogate, no NaN or infinity."""
    if isinstance(value, str):
        return value.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {_clean(str(k)): _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _names_a_credential(key: str) -> bool:
    words = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key).lower().replace("-", "_")
    return _CREDENTIAL_NAME.search(words) is not None


def _redact_embedded_json(text: str, depth: int) -> str:
    """``text`` with each JSON object or array in it redacted as data. A value with nothing to
    redact keeps its exact bytes. JSON past these bounds goes unread, and text it held cannot be
    known safe, so the marker replaces it.
    """
    if depth >= MAX_EMBEDDED_JSON_DEPTH or len(text) > MAX_EMBEDDED_JSON_CHARS:
        return TOO_LARGE_TO_CHECK if _LOOKS_LIKE_JSON.search(text) else text
    pieces: List[str] = []
    copied = 0
    at = 0
    for _ in range(MAX_EMBEDDED_JSON_TRIES):
        found = _JSON_OPENS.search(text, at)
        if found is None:
            break
        start = found.start()
        try:
            value, end = _JSON.raw_decode(text, start)
        except (ValueError, RecursionError):
            at = start + 1
            continue
        at = end
        clean = _redacted(value, depth + 1)
        if clean != value:
            pieces += [text[copied:start], json.dumps(clean, ensure_ascii=False)]
            copied = end
    else:
        if _LOOKS_LIKE_JSON.search(text, at):
            return TOO_LARGE_TO_CHECK
    return "".join([*pieces, text[copied:]])


def _with_large_json_replaced(value: Any) -> Any:
    """``value`` with each string that looks like JSON, and is too long to parse, replaced."""
    if isinstance(value, str):
        too_large = len(value) > MAX_EMBEDDED_JSON_CHARS and _LOOKS_LIKE_JSON.search(
            value
        )
        return TOO_LARGE_TO_CHECK if too_large else value
    if isinstance(value, list):
        return [_with_large_json_replaced(item) for item in value]
    if isinstance(value, dict):
        return {key: _with_large_json_replaced(item) for key, item in value.items()}
    return value


def _masked(match: re.Match) -> str:
    """Keeps a value's quotes, so redacted JSON stays JSON and redacting twice changes nothing."""
    value = match.group(3)
    quote = value[0] if value[0] in "\"'" else ""
    return f"{match.group(1)}{match.group(2)}{quote}{REDACTED}{quote}"


def _redact_text(text: str, depth: int = 0) -> str:
    text = _redact_embedded_json(text, depth)
    text = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    text = _HEADER_IN_TEXT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return _CREDENTIAL_IN_TEXT.sub(_masked, text)


def _redacted(value: Any, depth: int = 0) -> Any:
    """``value`` with every credential in it replaced, field by field and inside text."""
    if isinstance(value, str):
        return _redact_text(value, depth)
    if isinstance(value, list):
        return [_redacted(item, depth) for item in value]
    if isinstance(value, dict):
        kept: Dict[str, Any] = {}
        for key, item in value.items():
            held = item is not None and not isinstance(item, bool)
            kept[key] = (
                REDACTED
                if held and _names_a_credential(key)
                else _redacted(item, depth)
            )
        return kept
    return value


def _gained(marker: str, before: Any, after: Any) -> bool:
    return str(after).count(marker) > str(before).count(marker)


def _flatten(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Every value by its lower-cased dotted path. A literal dotted key, as Zeek writes, stays as it is."""
    flat: Dict[str, Any] = {}

    def walk(node: Mapping[str, Any], prefix: str, depth: int) -> None:
        for key, value in node.items():
            path = f"{prefix}{key}".lower()
            if isinstance(value, dict):
                if depth < MAX_FLATTEN_DEPTH:
                    walk(value, f"{path}.", depth + 1)
            else:
                flat.setdefault(path, value)

    walk(record, "", 0)
    return flat


def _text(value: Any) -> Optional[str]:
    """The value as a string to show, or None when the source means there is none."""
    if value is None or isinstance(value, (bool, dict)):
        return None
    if isinstance(value, list):
        parts = [_text(v) for v in value if not isinstance(v, (list, dict))]
        return ", ".join(p for p in parts if p) or None
    text = str(value).strip()
    return None if text.lower() in UNSET else text


def _lookup(flat: Mapping[str, Any], paths: Iterable[str]) -> Optional[str]:
    for path in paths:
        text = _text(flat.get(path))
        if text is not None:
            return text
    return None


def _shape_of(flat: Mapping[str, Any]) -> Shape:
    for shape in SHAPES:
        for clause in shape.detect:
            if all(
                path in flat and (want is None or str(flat[path]).lower() == want)
                for path, want in clause.items()
            ):
                return shape
    raise AssertionError("the generic shape matches every row")


def parse_time(value: Optional[str]) -> Optional[datetime]:
    """A UTC time from epoch seconds or milliseconds, ISO 8601, or the exporters' own formats."""
    if not value:
        return None
    parsed: Optional[datetime] = None
    try:
        number = float(value)
    except ValueError:
        number = None
    if number is not None:
        if not math.isfinite(number) or number <= 0:
            return None
        seconds = number / 1000 if number >= 1e11 else number
        try:
            return datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        for form in _TIME_FORMATS:
            try:
                parsed = datetime.strptime(value, form)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if not parsed.tzinfo:
        return parsed.replace(tzinfo=timezone.utc)
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError:
        return None


def _port(value: Optional[str]) -> Optional[int]:
    try:
        port = int(float(value)) if value else None
    except (ValueError, OverflowError):
        return None
    return port if port is not None and 0 <= port <= 65535 else None


def _severity(value: Optional[str], shape: Shape) -> str:
    key = (value or "").strip()
    word = shape.severity_codes.get(key) or SEVERITY_WORDS.get(key.lower())
    return word if word in LOG_SEVERITIES else "info"


def _address(value: Optional[str]) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(value or "")
    except ValueError:
        return None
    return str(getattr(ip, "ipv4_mapped", None) or ip)


def _score(flat: Mapping[str, Any], notes: Counter) -> Optional[float]:
    text = _lookup(flat, SCORE_FIELDS)
    if text is None:
        return None
    try:
        score = float(text)
    except ValueError:
        score = math.nan
    if not 0 <= score <= 1:
        notes[NOTE_BAD_SCORE] += 1
        return None
    return score


def _source_key(value: Optional[str]) -> str:
    return _SOURCE_KEY.sub("-", (value or "").lower()).strip("-")[
        : _COLUMN_LIMITS["source"]
    ]


def _render(shape: Shape, values: Mapping[str, Optional[str]]) -> str:
    kept = []
    for segment in shape.summary:
        names = _TEMPLATE_VAR.findall(segment)
        if all(values.get(n) for n in names):
            kept.append(_TEMPLATE_VAR.sub(lambda m: str(values[m.group(1)]), segment))
    return " ".join(kept)


def _fit(column: str, value: Optional[str]) -> Optional[str]:
    return value[: _COLUMN_LIMITS[column]] if value else None


def normalize(
    record: Any,
    *,
    source: Optional[str],
    case_id: Optional[str],
    now: datetime,
    oldest: datetime,
    notes: Counter,
) -> Tuple[Shape, Dict[str, Any]]:
    """One row in the one schema, or ``Dropped`` with the reason."""
    if not isinstance(record, dict):
        raise Dropped(DROP_NOT_OBJECT)
    cleaned = _clean(record)
    checkable = _with_large_json_replaced(cleaned)
    raw = _redacted(checkable)
    unread = _gained(TOO_LARGE_TO_CHECK, checkable, raw)
    if checkable != cleaned or unread:
        notes[NOTE_JSON_TOO_LARGE] += 1
    if _gained(REDACTED, checkable, raw) if unread else raw != checkable:
        notes[NOTE_REDACTED] += 1
    identity = {
        k: v for k, v in raw.items() if k.lower() not in (*SCORE_FIELDS, *CASE_FIELDS)
    }
    canonical = json.dumps(
        identity, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    if len(canonical) > MAX_RECORD_CHARS:
        raise Dropped(DROP_TOO_LARGE)

    flat = _flatten(raw)
    shape = _shape_of(flat)
    values = {name: _lookup(flat, paths) for name, paths in shape.fields.items()}

    when = parse_time(values.get("time"))
    # A connector's exported detection dates itself here, and a bare record of something else
    # does not become an event for having a creation time.
    if when is None and shape.source == GENERIC_SOURCE and flat.get("detection_id"):
        when = parse_time(_lookup(flat, ("created_timestamp",)))
    if when is None:
        raise Dropped(DROP_NO_TIME)
    if when < oldest:
        raise Dropped(DROP_PAST_RETENTION)
    if when > now + FUTURE_SLACK:
        raise Dropped(DROP_FUTURE_TIME)

    code = values.get("code")
    outcome = None
    if code is not None:
        outcome = shape.codes.get(code) or shape.codes.get("*")
    values["what"] = (
        outcome.what if outcome else (f"{shape.label} event {code}" if code else None)
    )
    host_role = outcome.host_role if outcome else "src_host"
    values[host_role] = values.get(host_role) or values.get("host")

    src_ip, dst_ip = _address(values.get("src_ip")), _address(values.get("dst_ip"))
    # A name in an address field, as generic logs often have, is still the host.
    src_host = values.get("src_host") or (None if src_ip else values.get("src_ip"))
    dst_host = values.get("dst_host") or (None if dst_ip else values.get("dst_ip"))
    values.update(src_ip=src_ip, dst_ip=dst_ip, src_host=src_host, dst_host=dst_host)

    stored_source = shape.source
    if shape.source == GENERIC_SOURCE:
        stored_source = (
            _source_key(values.get("source")) or _source_key(source) or GENERIC_SOURCE
        )
    mitre = _MITRE.search(values.get("mitre") or "")
    tags = record.get("tags")
    summary = values.get("summary") or _render(shape, values) or canonical

    event: Dict[str, Any] = {
        "event_id": hashlib.sha256(
            f"{stored_source}\n{canonical}".encode("utf-8")
        ).hexdigest(),
        "time": when,
        "source": stored_source,
        "event_class": _fit(
            "event_class",
            (outcome.event_class if outcome else None)
            or values.get("event_class")
            or shape.event_class,
        )
        or "",
        "severity": _severity(values.get("severity"), shape),
        "src_ip": _fit("src_ip", src_ip),
        "src_host": _fit("src_host", src_host),
        "dst_ip": _fit("dst_ip", dst_ip),
        "dst_host": _fit("dst_host", dst_host),
        "dst_port": _port(values.get("dst_port")),
        "user_name": _fit("user_name", values.get("user_name")),
        "action": _fit(
            "action", (outcome.action if outcome else None) or values.get("action")
        ),
        "summary": summary[:MAX_SUMMARY_CHARS],
        "mitre": mitre.group(0).upper() if mitre else None,
        "loglm": _score(flat, notes),
        "case_id": case_id or _fit("case_id", _lookup(flat, CASE_FIELDS)),
        "tags": [
            *(
                [t for t in tags if isinstance(t, str)]
                if isinstance(tags, list)
                else []
            ),
            *([REDACTED_TAG] if raw != cleaned else []),
        ],
        "raw": raw,
    }
    event["search_text"] = search_text(event)
    return shape, event


def _json_rows(path: Path, dropped: Counter) -> Iterator[Any]:
    try:
        with path.open(encoding="utf-8-sig", errors="replace") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as error:
        # A .json file is often one object a line.
        if error.msg != "Extra data":
            dropped[DROP_NOT_PARSEABLE] += 1
            return
        yield from _jsonl_rows(path, dropped)
        return
    except RecursionError:
        dropped[DROP_NOT_PARSEABLE] += 1
        return
    if isinstance(data, dict):
        wrapped = next(
            (data[k] for k in ENVELOPES if isinstance(data.get(k), list)), None
        )
        data = wrapped if wrapped is not None else [data]
    if not isinstance(data, list):
        dropped[DROP_NOT_OBJECT] += 1
        return
    yield from data


def _jsonl_rows(path: Path, dropped: Counter) -> Iterator[Any]:
    with path.open(encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except (ValueError, RecursionError):
                dropped[DROP_NOT_PARSEABLE] += 1


def _csv_rows(path: Path, dropped: Counter) -> Iterator[Any]:
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle, restkey="_extra")
        while True:
            try:
                yield next(reader)
            except StopIteration:
                return
            except csv.Error:
                dropped[DROP_NOT_PARSEABLE] += 1


_READERS = {"json": _json_rows, "jsonl": _jsonl_rows, "csv": _csv_rows}
FORMATS = tuple(_READERS)


def known_cases(case_ids: Iterable[str]) -> set:
    wanted = {c for c in case_ids if c}
    if not wanted:
        return set()
    with unit_of_work() as session:
        return set(
            session.execute(
                select(Case.case_id).where(Case.case_id.in_(wanted))
            ).scalars()
        )


def _merged(batch: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One row per event, because one upsert cannot touch a row twice. Sorted, so two
    uploads of overlapping files take row locks in the same order."""
    merged: Dict[str, Dict[str, Any]] = {}
    for event in batch:
        seen = merged.get(event["event_id"])
        if seen is None:
            merged[event["event_id"]] = event
            continue
        seen["loglm"] = event["loglm"] if event["loglm"] is not None else seen["loglm"]
        seen["case_id"] = event["case_id"] or seen["case_id"]
    return [merged[k] for k in sorted(merged)]


def _store(batch: List[Dict[str, Any]], report: IngestReport) -> None:
    if not batch:
        return
    cases = known_cases(e["case_id"] for e in batch)
    for event in batch:
        if event["case_id"] and event["case_id"] not in cases:
            report.notes[NOTE_UNKNOWN_CASE] += 1
            event["case_id"] = None

    rows = _merged(batch)
    statement = insert(LogEvent).values(rows)
    score = func.coalesce(statement.excluded.loglm, LogEvent.loglm)
    case = func.coalesce(statement.excluded.case_id, LogEvent.case_id)
    upsert = statement.on_conflict_do_update(
        index_elements=[LogEvent.event_id],
        set_={"loglm": score, "case_id": case},
        where=or_(
            score.is_distinct_from(LogEvent.loglm),
            case.is_distinct_from(LogEvent.case_id),
        ),
    ).returning(literal_column("(log_events.xmax = 0)"))
    with unit_of_work() as session:
        touched = session.execute(upsert).scalars().all()
    inserted = sum(1 for was_insert in touched if was_insert)
    report.stored += inserted
    report.updated += len(touched) - inserted
    report.unchanged += len(batch) - len(touched)


def ingest_file(
    path: Path,
    fmt: str,
    *,
    case_id: Optional[str] = None,
    source: Optional[str] = None,
) -> IngestReport:
    """Store a file's rows, then sweep what retention has aged out. Each batch commits on
    its own, so a failure partway keeps what it stored and sending the file again finishes it.
    """
    report = IngestReport()
    now = datetime.now(timezone.utc)
    oldest = cutoff(now)
    unread: Counter = Counter()
    batch: List[Dict[str, Any]] = []
    for record in _READERS[fmt](path, unread):
        report.rows += 1
        try:
            shape, event = normalize(
                record,
                source=source,
                case_id=case_id,
                now=now,
                oldest=oldest,
                notes=report.notes,
            )
        except Dropped as drop:
            report.dropped[drop.reason] += 1
            continue
        except RecursionError:
            report.dropped[DROP_TOO_LARGE] += 1
            continue
        report.shapes[shape.key] += 1
        batch.append(event)
        if len(batch) >= BATCH_ROWS:
            _store(batch, report)
            batch = []
    _store(batch, report)
    report.rows += sum(unread.values())
    report.dropped.update(unread)
    report.swept = sweep(now)
    return report
