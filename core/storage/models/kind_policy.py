"""What Vigil may do on its own for one kind of alert: ask, or close as noise.

The schema is core/upgrade/versions/0038_kind_policies.sql. A kind with no row asks.
``mode`` changes only through ``move_to``, which also writes the append-only event, so the
two cannot disagree. The database refuses a close on fewer than 59 clean labels.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, FrozenSet, Mapping

from sqlalchemy import BigInteger, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Index, Integer, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, WriteOnlyMapped, mapped_column, relationship

from core.storage.models.base import Base


class PolicyMode(str, Enum):
    ASK = "ask"
    CLOSE = "close"


# Close to ask is revoking an adoption.
TRANSITIONS: Mapping[PolicyMode, FrozenSet[PolicyMode]] = {
    PolicyMode.ASK: frozenset({PolicyMode.CLOSE}),
    PolicyMode.CLOSE: frozenset({PolicyMode.ASK}),
}


class InvalidPolicyMove(Exception):
    def __init__(self, current: PolicyMode, wanted: PolicyMode):
        super().__init__(f"A policy on {current.value} cannot move to {wanted.value}.")
        self.current = current
        self.wanted = wanted


def _mode_column(**kwargs: Any) -> Any:
    return mapped_column(
        SQLEnum(
            PolicyMode,
            native_enum=False,
            create_constraint=False,
            length=8,
            values_callable=lambda members: [m.value for m in members],
        ),
        **kwargs,
    )


class KindPolicy(Base):
    __tablename__ = "kind_policies"

    signature: Mapped[str] = mapped_column(Text, primary_key=True)
    mode: Mapped[PolicyMode] = _mode_column(nullable=False, default=PolicyMode.ASK)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
        onupdate=text("now()"),
    )
    events: WriteOnlyMapped["KindPolicyEvent"] = relationship(
        order_by="KindPolicyEvent.id"
    )

    def move_to(
        self,
        mode: PolicyMode,
        *,
        actor: str,
        reason: str,
        evidence: Dict[str, Any],
        clean_labels: int,
    ) -> None:
        """Load the row FOR UPDATE first: two people can race the same move."""
        if mode not in TRANSITIONS[self.mode]:
            raise InvalidPolicyMove(self.mode, mode)
        self.events.add(
            KindPolicyEvent(
                from_mode=self.mode,
                to_mode=mode,
                actor=actor,
                reason=reason,
                evidence=evidence,
                clean_labels=clean_labels,
            )
        )
        self.mode = mode


class KindPolicyEvent(Base):
    """One adoption or revocation. Append-only: the app role holds no UPDATE or DELETE."""

    __tablename__ = "kind_policy_events"
    __table_args__ = (Index("idx_kind_policy_events_signature", "signature", "id"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    signature: Mapped[str] = mapped_column(
        Text, ForeignKey("kind_policies.signature"), nullable=False
    )
    from_mode: Mapped[PolicyMode] = _mode_column(nullable=False)
    to_mode: Mapped[PolicyMode] = _mode_column(nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    clean_labels: Mapped[int] = mapped_column(Integer, nullable=False)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
