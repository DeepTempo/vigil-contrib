"""/api/log-events: send telemetry to Vigil and search what it keeps, every source in one schema."""

from __future__ import annotations

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from psycopg2 import errors
from sqlalchemy import and_, case, func, select, text
from sqlalchemy.exc import OperationalError
from starlette.concurrency import run_in_threadpool

from core.auth.permissions import permission_gate
from core.config import get_settings, load_integrations_config
from core.log_events.ingest import (
    FORMATS,
    SHAPES,
    ingest_file,
    known_cases,
    source_label,
)
from core.log_events.query import parse, to_row, where
from core.log_events.retention import retention_days, sweep
from core.routing import Auth, RouterMeta
from core.storage.models.log_event import LogEvent
from core.storage.unit_of_work import unit_of_work

router = APIRouter()
router.dependencies.append(permission_gate("findings.read"))

ROUTER_META = RouterMeta(prefix="/api/log-events", tags=["logs"], auth=Auth.REQUIRED)

_FINDINGS_WRITE = [permission_gate("findings.write")]

MAX_LIMIT = 500
SEARCH_TIMEOUT_MS = 15_000
FIT_MIN_PAD = timedelta(minutes=1)
EXTENSION_FORMATS = {
    ".json": "json",
    ".jsonl": "jsonl",
    ".ndjson": "jsonl",
    ".log": "jsonl",
    ".csv": "csv",
}


def _iso(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def _when(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=422, detail=f"Not a time: {value}")
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _with_time_limit(session) -> None:
    """A word search reads every row of its window: ``search_text`` has no index, because a
    trigram index over whole raw records would cost more than this bounded store is worth. The
    time limit makes a search too wide for this install answer instead of holding a worker.
    """
    session.execute(text(f"SET LOCAL statement_timeout = {int(SEARCH_TIMEOUT_MS)}"))


def _fitted(session, matched) -> Optional[Tuple[datetime, datetime]]:
    """The window around every event the search matches, wherever they are in the store."""
    query = select(func.min(LogEvent.time), func.max(LogEvent.time))
    first, last = session.execute(
        query.where(matched) if matched is not None else query
    ).one()
    if first is None:
        return None
    pad = max((last - first) * 0.02, FIT_MIN_PAD)
    return first - pad, last + pad


@router.get("/search")
def search_logs(
    q: str = Query(
        "",
        max_length=1000,
        description='Search: free words, "phrases", key:value, -exclude, loglm>0.7',
    ),
    start: Optional[str] = Query(
        None, description="ISO time; default 24 hours before end"
    ),
    end: Optional[str] = Query(None, description="ISO time; default now"),
    fit: bool = Query(
        False, description="Ignore start and end; use the window around every match"
    ),
    hide: Optional[str] = Query(
        None, description="Comma-separated source keys to leave out"
    ),
    limit: int = Query(150, ge=1, le=MAX_LIMIT),
    offset: int = Query(0, ge=0),
    buckets: int = Query(48, ge=6, le=240),
) -> Dict[str, Any]:
    """Newest first. ``by_source`` counts every source the search matched, before ``hide``,
    so the source chips can show what turning one back on adds. ``histogram`` spreads the
    shown events over the window, with those linked to a case counted apart."""
    matched = where(q)
    t1 = _when(end) or datetime.now(timezone.utc)
    t0 = _when(start) or t1 - timedelta(hours=24)
    try:
        return _search(q, t0, t1, fit, matched, hide, limit, offset, buckets)
    except OperationalError as exc:
        if not isinstance(exc.orig, errors.QueryCanceled):
            raise
        limit_passed = (
            f"This search ran past its {SEARCH_TIMEOUT_MS // 1000} second limit"
        )
        raise HTTPException(
            status_code=504,
            detail=(
                f"{limit_passed} while it looked through every stored event for matches. Add "
                "a field such as source: or host: alongside the words."
                if fit
                else f"{limit_passed}. Narrow the time range, or add a field such as source: "
                "or host: alongside the words."
            ),
        ) from exc


def _search(q, t0, t1, fit, matched, hide, limit, offset, buckets) -> Dict[str, Any]:
    with unit_of_work() as session:
        _with_time_limit(session)
        if fit:
            t0, t1 = _fitted(session, matched) or (t0, t1)
        if t0 >= t1:
            raise HTTPException(status_code=422, detail="start must be before end")
        in_window = and_(LogEvent.time >= t0, LogEvent.time <= t1)
        base = and_(in_window, matched) if matched is not None else in_window
        hidden = [s for s in (hide or "").split(",") if s]
        shown = and_(base, LogEvent.source.not_in(hidden)) if hidden else base

        span = (t1 - t0).total_seconds() / buckets
        by_source = dict(
            session.execute(
                select(LogEvent.source, func.count())
                .where(base)
                .group_by(LogEvent.source)
            ).all()
        )
        total = session.execute(
            select(func.count()).select_from(LogEvent).where(shown)
        ).scalar_one()
        rows = (
            session.execute(
                select(LogEvent)
                .where(shown)
                .order_by(LogEvent.time.desc(), LogEvent.event_id.desc())
                .offset(offset)
                .limit(limit)
            )
            .scalars()
            .all()
        )
        index = func.least(
            buckets - 1,
            func.floor((func.extract("epoch", LogEvent.time) - t0.timestamp()) / span),
        ).label("b")
        hist = session.execute(
            select(
                index,
                func.count(),
                func.sum(case((LogEvent.case_id.isnot(None), 1), else_=0)),
            )
            .where(shown)
            .group_by(index)
        ).all()
        newest = session.execute(select(func.max(LogEvent.time))).scalar_one_or_none()
        events = [to_row(e) for e in rows]

    counts = [0] * buckets
    linked = [0] * buckets
    for b, n, in_case in hist:
        if b is not None and 0 <= int(b) < buckets:
            counts[int(b)] = int(n)
            linked[int(b)] = int(in_case or 0)
    return {
        "q": q,
        "terms": [
            {"key": t.key, "value": t.value, "negate": t.negate} for t in parse(q)
        ],
        "start": _iso(t0),
        "end": _iso(t1),
        "total": total,
        "events": events,
        "by_source": by_source,
        "histogram": {"bucket_seconds": span, "counts": counts, "in_case": linked},
        "newest": _iso(newest) if newest else None,
    }


@router.get("/sources")
def log_sources() -> Dict[str, Any]:
    """Each source in the store: how many events Vigil holds, and when the last one happened."""
    with unit_of_work() as session:
        rows = session.execute(
            select(
                LogEvent.source,
                func.count(),
                func.min(LogEvent.time),
                func.max(LogEvent.time),
            ).group_by(LogEvent.source)
        ).all()
    return {
        "sources": [
            {
                "source": s,
                "label": source_label(s),
                "events": int(n),
                "first": _iso(a),
                "last": _iso(b),
            }
            for s, n, a, b in sorted(rows)
        ]
    }


def _loglm_status() -> Dict[str, bool]:
    """What the Settings LogLM card shows: a connector URL and a last test that passed."""
    loaded = load_integrations_config()
    configured = bool((loaded["integrations"].get("loglm") or {}).get("connectorUrl"))
    last_test = (loaded.get("last_test") or {}).get("loglm") or {}
    return {
        "configured": configured,
        "connected": configured and last_test.get("success") is True,
    }


@router.get("/status")
def log_status() -> Dict[str, Any]:
    """What the store holds, how long it keeps it, what it takes, and whether LogLM is scoring."""
    with unit_of_work() as session:
        total, scored = session.execute(
            select(func.count(), func.count(LogEvent.loglm))
        ).one()
    return {
        "total": int(total),
        "scored": int(scored),
        "retention_days": retention_days(),
        "loglm": _loglm_status(),
        "shapes": sorted({s.label for s in SHAPES if s.key != "generic"}),
        "formats": sorted(FORMATS),
        "max_upload_mb": get_settings().max_upload_size_mb,
    }


@router.get("/events/{event_id}")
def get_event(event_id: str) -> Dict[str, Any]:
    with unit_of_work() as session:
        e = session.get(LogEvent, event_id)
        if e is None:
            raise HTTPException(status_code=404, detail=f"No event {event_id}")
        return to_row(e)


def _format_of(filename: str, declared: Optional[str]) -> str:
    fmt = declared or EXTENSION_FORMATS.get(Path(filename).suffix.lower())
    if fmt not in FORMATS:
        raise HTTPException(
            status_code=400,
            detail="Unable to tell the file's format. Use .jsonl, .json or .csv, or set format to jsonl, json or csv.",
        )
    return fmt


async def _spool(file: UploadFile) -> Path:
    """Stream an upload to a temp file, enforcing the size cap as it goes."""
    cap = get_settings().max_upload_size_mb * 1024 * 1024
    with tempfile.NamedTemporaryFile(
        mode="wb", delete=False, suffix=".upload"
    ) as spool:
        path = Path(spool.name)
        size = 0
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > cap:
                spool.close()
                path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large. Maximum upload size is {cap // (1024 * 1024)}MB.",
                )
            spool.write(chunk)
    return path


@router.post("/ingest", dependencies=_FINDINGS_WRITE)
async def ingest_logs(
    file: UploadFile = File(...),
    format: Optional[str] = Form(
        None, description="jsonl, json or csv; default from the file name"
    ),
    case_id: Optional[str] = Form(None, description="Link every row to this case"),
    source: Optional[str] = Form(
        None, description="Source key for rows of no known shape that name none"
    ),
) -> Dict[str, Any]:
    """Store a file of log rows. Sending the same file again stores nothing new. A row
    with a ``loglm`` score or a ``case_id`` column carries it, also on a later send."""
    fmt = _format_of(file.filename or "upload", format)
    if case_id and case_id not in await run_in_threadpool(known_cases, [case_id]):
        raise HTTPException(status_code=404, detail=f"No case {case_id}")
    path = await _spool(file)
    try:
        report = await run_in_threadpool(
            ingest_file, path, fmt, case_id=case_id, source=source
        )
    finally:
        path.unlink(missing_ok=True)
    return {**report.to_dict(), "retention_days": retention_days()}


@router.post("/retention/sweep", dependencies=_FINDINGS_WRITE)
def sweep_logs() -> Dict[str, Any]:
    """Delete events past retention now. Each ingest also does this."""
    return {"deleted": sweep(), "retention_days": retention_days()}
