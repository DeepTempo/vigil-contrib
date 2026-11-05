"""How long Vigil keeps log events. A bounded evidence store, not a SIEM."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import delete

from core.config import _settings_env_file
from core.storage.models.log_event import LogEvent
from core.storage.unit_of_work import unit_of_work


class _RetentionSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_settings_env_file(),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    log_events_retention_days: int = Field(30, ge=1)


def retention_days() -> int:
    return _RetentionSettings().log_events_retention_days


def cutoff(now: Optional[datetime] = None) -> datetime:
    """Events older than this are past retention."""
    return (now or datetime.now(timezone.utc)) - timedelta(days=retention_days())


def sweep(now: Optional[datetime] = None) -> int:
    """Delete events past retention and return how many went. Safe to run at any time."""
    with unit_of_work() as session:
        gone = session.execute(delete(LogEvent).where(LogEvent.time < cutoff(now)))
        return gone.rowcount or 0
