"""The Logs search language, read into SQL over ``log_events``.

Free words match anywhere in an event (summary, hosts, user, its raw record);
"quoted words" match as a phrase; ``key:value`` narrows one field; a leading
``-`` excludes; ``a,b`` and ``key:a,b`` match either; ``loglm>0.7`` keeps events
LogLM scored at least that unusual. Keys: source, host, ip, user, port, case,
mitre, sev, class, action, id. Unknown keys are read as free text, so nothing
typed is ignored.
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from datetime import timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, false, func, not_, or_

from core.storage.models.log_event import LogEvent

KEYS = (
    "source",
    "host",
    "ip",
    "user",
    "port",
    "case",
    "mitre",
    "sev",
    "class",
    "action",
    "id",
)
_SCORE = re.compile(r"^loglm([<>]=?)([0-9.]+)$", re.I)
_KEYED = re.compile(r"^([a-z]+):(.+)$", re.I)

# The words people use for the sources the normalizer names. Any other stored source
# is matched by its own key.
SOURCE_ALIASES = {
    "sysmon": ("sysmon",),
    "zeek": ("zeek", "network"),
    "paloalto": ("paloalto", "palo", "pan", "firewall", "ngfw"),
    "dns": ("dns",),
    "winsec": ("winsec", "windows", "security", "ad", "identity"),
    "crowdstrike": ("crowdstrike", "falcon", "edr"),
    "entra": ("entra", "azuread", "aad", "signin"),
}


@dataclass
class Term:
    key: Optional[str]
    value: str
    negate: bool = False
    op: Optional[str] = None


def _tokens(q: str) -> List[str]:
    lex = shlex.shlex(q, posix=True)
    lex.whitespace_split = True
    lex.escape = ""  # keep backslashes: CORP\jdoe, C:\Windows\Temp
    lex.commenters = ""
    return list(lex)


def parse(q: str) -> List[Term]:
    try:
        tokens = _tokens(q or "")
    except ValueError:  # an unclosed quote reads as plain words
        tokens = (q or "").replace('"', " ").split()
    terms: List[Term] = []
    for tok in tokens:
        negate = tok.startswith("-") and len(tok) > 1
        if negate:
            tok = tok[1:]
        m = _SCORE.match(tok)
        if m:
            terms.append(Term("loglm", m.group(2), negate, m.group(1)))
            continue
        m = _KEYED.match(tok)
        if m and m.group(1).lower() in KEYS:
            terms.append(Term(m.group(1).lower(), m.group(2), negate))
        else:
            terms.append(Term(None, tok, negate))
    return terms


def _source_keys(value: str) -> List[str]:
    v = value.lower()
    # "fire" finds firewall and "firewalls" too, but a short alias is no prefix of other words: "admin" is not "ad"
    return [
        k
        for k, words in SOURCE_ALIASES.items()
        if k == v
        or any(w.startswith(v) or (len(w) >= 4 and v.startswith(w)) for w in words)
    ] or [v]


def _like(col, value: str):
    return col.icontains(
        value, autoescape=True
    )  # "_" and "%" in svc_backup are letters, not wildcards


def _ip(v: str):
    if ":" in v or (
        v.count(".") == 3 and not v.endswith(".")
    ):  # a whole address (IPv6 is compared whole)
        return or_(LogEvent.src_ip == v, LogEvent.dst_ip == v)
    p = (
        v if v.endswith(".") else f"{v}."
    )  # a prefix ends on a dot, so 10.0.10 does not take in 10.0.100.x
    return or_(
        LogEvent.src_ip.startswith(p, autoescape=True),
        LogEvent.dst_ip.startswith(p, autoescape=True),
    )


def _score(v: str, op: Optional[str]):
    try:
        n = float(v)
    except ValueError:
        n = 0.0
    E = LogEvent
    return {">": E.loglm > n, ">=": E.loglm >= n, "<": E.loglm < n, "<=": E.loglm <= n}[
        op or ">="
    ]


def _words(v: str):
    w = v.lower()
    c = LogEvent.search_text.contains(w, autoescape=True)
    if "\\" in w:  # the raw record is stored as JSON, which doubles each backslash
        c = or_(
            c, LogEvent.search_text.contains(w.replace("\\", "\\\\"), autoescape=True)
        )
    return c


_FIELD = {
    "source": lambda v: LogEvent.source.in_(_source_keys(v)),
    "host": lambda v: or_(_like(LogEvent.src_host, v), _like(LogEvent.dst_host, v)),
    "ip": _ip,
    "user": lambda v: _like(LogEvent.user_name, v),
    # not a port: nothing matches
    "port": lambda v: (
        LogEvent.dst_port == int(v) if v.isdigit() and int(v) <= 65535 else false()
    ),
    "case": lambda v: func.lower(LogEvent.case_id) == v.lower(),
    "mitre": lambda v: LogEvent.mitre.istartswith(v, autoescape=True),
    "sev": lambda v: LogEvent.severity == v.lower(),
    "class": lambda v: LogEvent.event_class.istartswith(v, autoescape=True),
    "action": lambda v: func.lower(LogEvent.action) == v.lower(),
    "id": lambda v: LogEvent.event_id == v,
}


def condition(t: Term):
    if (
        t.key != "loglm" and "," in t.value and " " not in t.value
    ):  # sev:high,critical means either
        parts = [condition(Term(t.key, v)) for v in t.value.split(",") if v]
        c = or_(*parts) if parts else false()
    elif t.key == "loglm":
        c = _score(t.value, t.op)
    elif t.key is None:
        c = _words(t.value)
    else:
        c = _FIELD[t.key](t.value)
    # NOT, where an event without the field counts as not matching (SQL's NOT NULL is NULL)
    return not_(func.coalesce(c, false())) if t.negate else c


def where(q: str):
    terms = parse(q)
    return and_(*[condition(t) for t in terms]) if terms else None


def search_text(e: Dict[str, Any]) -> str:
    """What free words match: the readable fields and the raw record."""
    parts = [
        e.get("summary"),
        e.get("src_host"),
        e.get("dst_host"),
        e.get("src_ip"),
        e.get("dst_ip"),
        e.get("user_name"),
        e.get("action"),
        e.get("event_class"),
        e.get("mitre"),
        e.get("source"),
        " ".join(e.get("tags") or []),
        json.dumps(e.get("raw") or {}, ensure_ascii=False),
    ]
    return " ".join(str(p) for p in parts if p not in (None, "")).lower()


def to_row(e: LogEvent) -> Dict[str, Any]:
    """The event as the console's LogRow."""
    t = e.time.astimezone(timezone.utc)
    return {
        "id": e.event_id,
        "time": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ts": int(t.timestamp()),
        "source": e.source,
        "class": e.event_class,
        "severity": e.severity,
        "srcIp": e.src_ip,
        "srcHost": e.src_host,
        "dstIp": e.dst_ip,
        "dstHost": e.dst_host,
        "dstPort": e.dst_port,
        "user": e.user_name,
        "action": e.action,
        "summary": e.summary,
        "loglm": e.loglm,
        "mitre": e.mitre,
        "caseId": e.case_id,
        "tags": list(e.tags or []),
        "raw": e.raw or {},
    }
