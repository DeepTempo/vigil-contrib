"""The entity graph for a time window, read from ``log_events`` and a case's findings."""

from __future__ import annotations

import ipaddress
import logging
import os
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import and_, func, select

from core.entity_graph.build import CaseRef, build, entities_of_contexts
from core.entity_graph.features import (
    DEFAULT_INTERNAL,
    RAW_FIELDS,
    Network,
    flows_from_rows,
)
from core.storage.models import Case, Finding, LogEvent, case_findings
from core.storage.unit_of_work import unit_of_work

logger = logging.getLogger(__name__)

# Newest rows win past this. Reported in the response, so the screen can say so.
ROW_CAP = 100_000
MAX_HOURS = 24 * 90
INTERNAL_CIDRS_ENV = "VIGIL_ENTITY_GRAPH_INTERNAL_CIDRS"
RAW_KEYS = tuple(key for keys in RAW_FIELDS.values() for key in keys)
COLUMNS = (
    "time",
    "src_ip",
    "src_host",
    "dst_ip",
    "dst_host",
    "dst_port",
    "event_class",
    "action",
    "loglm",
)


class CaseNotFound(LookupError):
    pass


def internal_ranges() -> list[str]:
    """The operator's ranges, or the default. A bad entry is logged and left out, and the
    response names the ranges in use."""
    ranges = []
    for cidr in os.environ.get(INTERNAL_CIDRS_ENV, "").split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("Ignoring %s entry %r: not a CIDR", INTERNAL_CIDRS_ENV, cidr)
            continue
        ranges.append(cidr)
    return ranges or list(DEFAULT_INTERNAL)


def _both_ends():
    def named(ip_column, host_column):
        return func.coalesce(
            func.nullif(ip_column, ""), func.nullif(host_column, "")
        ).is_not(None)

    return and_(
        named(LogEvent.src_ip, LogEvent.src_host),
        named(LogEvent.dst_ip, LogEvent.dst_host),
    )


def _case_ref(session, case_id: str) -> CaseRef:
    case = session.get(Case, case_id)
    if case is None:
        raise CaseNotFound(case_id)
    contexts = session.scalars(
        select(Finding.entity_context)
        .join(case_findings, case_findings.c.finding_id == Finding.finding_id)
        .where(case_findings.c.case_id == case_id)
    )
    return CaseRef(case_id, case.title or case_id, entities_of_contexts(contexts))


def _flow_rows(session, since, limit: int) -> list[dict[str, Any]]:
    columns = [getattr(LogEvent, name) for name in COLUMNS]
    raw = [LogEvent.raw[key].astext.label(f"raw:{key}") for key in RAW_KEYS]
    result = session.execute(
        select(*columns, *raw)
        .where(LogEvent.time >= since, _both_ends())
        .order_by(LogEvent.time.desc(), LogEvent.event_id)
        .limit(limit)
    )
    rows = []
    for row in result.mappings():
        values = {name: row[name] for name in COLUMNS}
        values["raw"] = {key: row[f"raw:{key}"] for key in RAW_KEYS}
        rows.append(values)
    return rows


def entity_graph_payload(
    hours: int, case_id: Optional[str] = None, row_cap: int = ROW_CAP
) -> dict[str, Any]:
    until = datetime.now(timezone.utc)
    since = until - timedelta(hours=hours)
    with unit_of_work() as session:
        case = _case_ref(session, case_id) if case_id else None
        in_window, with_ends = session.execute(
            select(func.count(), func.count().filter(_both_ends())).where(
                LogEvent.time >= since
            )
        ).one()
        rows = _flow_rows(session, since, row_cap)

    flowset = flows_from_rows(rows)
    ranges = internal_ranges()
    graph = build(flowset, Network.of(ranges), case)
    return {
        **asdict(graph),
        "window": {
            "hours": hours,
            "start": since.isoformat(),
            "end": until.isoformat(),
        },
        "rows": {
            "in_window": in_window,
            "read": len(rows),
            "flows": len(flowset.flows),
            "skipped": in_window - with_ends + flowset.skipped,
            "cap": row_cap,
            "capped": with_ends - len(rows),
        },
        "internal_ranges": ranges,
    }
