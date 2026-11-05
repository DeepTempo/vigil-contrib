"""Telemetry events kept by Vigil: one row per event, every source in one schema, with
the source's own record kept beside it. The schema is
core/upgrade/versions/0036_log_events.sql."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from core.storage.models.base import Base

LOG_SEVERITIES = ("critical", "high", "medium", "low", "info")


class LogEvent(Base):
    __tablename__ = "log_events"
    __table_args__ = (
        Index("ix_log_events_time", "time"),
        Index("ix_log_events_source_time", "source", "time"),
        Index("ix_log_events_case_id", "case_id"),
    )

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    event_class: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default=text("''")
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'info'")
    )
    src_ip: Mapped[Optional[str]] = mapped_column(String(64))
    src_host: Mapped[Optional[str]] = mapped_column(String(255))
    dst_ip: Mapped[Optional[str]] = mapped_column(String(64))
    dst_host: Mapped[Optional[str]] = mapped_column(String(255))
    dst_port: Mapped[Optional[int]] = mapped_column(Integer)
    user_name: Mapped[Optional[str]] = mapped_column(String(128))
    action: Mapped[Optional[str]] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("''")
    )
    mitre: Mapped[Optional[str]] = mapped_column(String(32))
    # LogLM's anomaly score, 0..1. Null without LogLM.
    loglm: Mapped[Optional[float]] = mapped_column(Float)
    case_id: Mapped[Optional[str]] = mapped_column(
        String(50), ForeignKey("cases.case_id", ondelete="SET NULL")
    )
    tags: Mapped[List[str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    raw: Mapped[Dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    # Lower-cased summary, hosts, user and raw record, for free-text search.
    search_text: Mapped[str] = mapped_column(
        Text, nullable=False, server_default=text("''")
    )
