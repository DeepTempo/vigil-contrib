"""A proposed detection on its way from a missed attack step to a rule in the SIEM.

The schema is core/upgrade/versions/0037_detection_proposals.sql. ``state`` changes only
through ``move_to``, which also writes the append-only event, so the two cannot disagree.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, FrozenSet, Mapping, Optional

from sqlalchemy import BigInteger, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, WriteOnlyMapped, mapped_column, relationship

from core.storage.models.base import Base


class ProposalState(str, Enum):
    DRAFT = "draft"
    LINTED = "linted"
    REPLAYED = "replayed"
    CONVERTED = "converted"
    SHADOW = "shadow"
    LIVE = "live"
    REJECTED = "rejected"


# Back to draft is the way to change a rule's text: the checks it passed judged the old one.
# A live rule leaves through detection_rule_stages, so live has no way out here.
TRANSITIONS: Mapping[ProposalState, FrozenSet[ProposalState]] = {
    ProposalState.DRAFT: frozenset({ProposalState.LINTED, ProposalState.REJECTED}),
    ProposalState.LINTED: frozenset(
        {ProposalState.REPLAYED, ProposalState.DRAFT, ProposalState.REJECTED}
    ),
    ProposalState.REPLAYED: frozenset(
        {ProposalState.CONVERTED, ProposalState.DRAFT, ProposalState.REJECTED}
    ),
    ProposalState.CONVERTED: frozenset(
        {ProposalState.SHADOW, ProposalState.DRAFT, ProposalState.REJECTED}
    ),
    ProposalState.SHADOW: frozenset(
        {ProposalState.LIVE, ProposalState.DRAFT, ProposalState.REJECTED}
    ),
    ProposalState.LIVE: frozenset(),
    ProposalState.REJECTED: frozenset(),
}


class InvalidProposalMove(Exception):
    def __init__(self, current: ProposalState, wanted: ProposalState):
        super().__init__(f"A {current.value} proposal cannot become {wanted.value}.")
        self.current = current
        self.wanted = wanted


def _state_column(**kwargs: Any) -> Any:
    return mapped_column(
        SQLEnum(
            ProposalState,
            native_enum=False,
            create_constraint=False,
            length=16,
            values_callable=lambda members: [m.value for m in members],
        ),
        **kwargs,
    )


class DetectionProposal(Base):
    __tablename__ = "detection_proposals"
    __table_args__ = (
        Index("idx_detection_proposals_state", "state"),
        Index("idx_detection_proposals_case_id", "case_id"),
    )

    proposal_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    technique: Mapped[Optional[str]] = mapped_column(Text)
    case_id: Mapped[Optional[str]] = mapped_column(
        String(50), ForeignKey("cases.case_id", ondelete="SET NULL")
    )
    origin: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    sigma: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[ProposalState] = _state_column(nullable=False)
    rule_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("detection_rules.id")
    )
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
        onupdate=text("now()"),
    )
    events: WriteOnlyMapped["DetectionProposalEvent"] = relationship(
        order_by="DetectionProposalEvent.id"
    )

    @classmethod
    def draft(
        cls,
        *,
        title: str,
        sigma: str,
        actor: str,
        evidence: Dict[str, Any],
        technique: Optional[str] = None,
        case_id: Optional[str] = None,
        origin: Optional[Dict[str, Any]] = None,
    ) -> "DetectionProposal":
        proposal = cls(
            title=title,
            sigma=sigma,
            state=ProposalState.DRAFT,
            created_by=actor,
            technique=technique,
            case_id=case_id,
            origin=origin or {},
        )
        proposal.events.add(
            DetectionProposalEvent(
                from_state=None,
                to_state=ProposalState.DRAFT,
                sigma=sigma,
                actor=actor,
                evidence=evidence,
            )
        )
        return proposal

    def move_to(
        self,
        state: ProposalState,
        *,
        actor: str,
        evidence: Dict[str, Any],
        reason: str = "",
        sigma: Optional[str] = None,
    ) -> None:
        """Load the row FOR UPDATE first: two people can race the same move. New rule
        text is only taken on the way back to draft."""
        if state not in TRANSITIONS[self.state]:
            raise InvalidProposalMove(self.state, state)
        if sigma is not None and state is not ProposalState.DRAFT:
            raise ValueError("A rule's text changes only on the way back to draft.")
        self.events.add(
            DetectionProposalEvent(
                from_state=self.state,
                to_state=state,
                sigma=self.sigma if sigma is None else sigma,
                actor=actor,
                evidence=evidence,
                reason=reason,
            )
        )
        self.state = state
        if sigma is not None:
            self.sigma = sigma


class DetectionProposalEvent(Base):
    """One state a proposal entered. Append-only: the app role holds no UPDATE or DELETE."""

    __tablename__ = "detection_proposal_events"
    __table_args__ = (
        Index("idx_detection_proposal_events_proposal", "proposal_id", "id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    proposal_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("detection_proposals.proposal_id"), nullable=False
    )
    from_state: Mapped[Optional[ProposalState]] = _state_column()
    to_state: Mapped[ProposalState] = _state_column(nullable=False)
    sigma: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default=text("''")
    )
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
