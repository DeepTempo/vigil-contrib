"""The two state machines the detection and autonomy screens are built on."""

import pytest

from core.storage.models import (
    DetectionProposal,
    InvalidPolicyMove,
    InvalidProposalMove,
    KindPolicy,
    PolicyMode,
    ProposalState,
)
from core.storage.models.detection_proposal import TRANSITIONS as PROPOSAL_TRANSITIONS
from core.storage.models.kind_policy import TRANSITIONS as POLICY_TRANSITIONS

EVIDENCE = {"lint": "passed"}


def proposal_in(state: ProposalState) -> DetectionProposal:
    proposal = DetectionProposal.draft(
        title="t", sigma="rule", actor="analyst", evidence=EVIDENCE
    )
    proposal.state = state
    return proposal


def test_every_state_has_an_entry():
    assert set(PROPOSAL_TRANSITIONS) == set(ProposalState)
    assert set(POLICY_TRANSITIONS) == set(PolicyMode)


def test_a_draft_reaches_live_through_every_stage():
    proposal = DetectionProposal.draft(
        title="t", sigma="rule", actor="analyst", evidence=EVIDENCE
    )
    for state in (
        ProposalState.LINTED,
        ProposalState.REPLAYED,
        ProposalState.CONVERTED,
        ProposalState.SHADOW,
        ProposalState.LIVE,
    ):
        proposal.move_to(state, actor="analyst", evidence=EVIDENCE)
        assert proposal.state is state


@pytest.mark.parametrize(
    "current,wanted",
    [
        (ProposalState.DRAFT, ProposalState.REPLAYED),
        (ProposalState.DRAFT, ProposalState.LIVE),
        (ProposalState.CONVERTED, ProposalState.LIVE),
        (ProposalState.LIVE, ProposalState.DRAFT),
        (ProposalState.REJECTED, ProposalState.DRAFT),
    ],
)
def test_a_stage_cannot_be_skipped_or_left_after_the_end(current, wanted):
    proposal = proposal_in(current)
    with pytest.raises(InvalidProposalMove):
        proposal.move_to(wanted, actor="analyst", evidence=EVIDENCE)
    assert proposal.state is current


def test_rule_text_changes_only_on_the_way_back_to_draft():
    proposal = proposal_in(ProposalState.LINTED)
    with pytest.raises(ValueError):
        proposal.move_to(
            ProposalState.REPLAYED, actor="analyst", evidence=EVIDENCE, sigma="new"
        )
    assert proposal.sigma == "rule"
    proposal.move_to(
        ProposalState.DRAFT, actor="analyst", evidence=EVIDENCE, sigma="new"
    )
    assert proposal.sigma == "new"
    assert proposal.state is ProposalState.DRAFT


def test_a_close_can_be_revoked_but_not_adopted_twice():
    policy = KindPolicy(signature="kind", mode=PolicyMode.ASK)
    move = dict(actor="manager", reason="r", evidence=EVIDENCE, clean_labels=59)
    policy.move_to(PolicyMode.CLOSE, **move)
    with pytest.raises(InvalidPolicyMove):
        policy.move_to(PolicyMode.CLOSE, **move)
    policy.move_to(PolicyMode.ASK, **move)
    assert policy.mode is PolicyMode.ASK
