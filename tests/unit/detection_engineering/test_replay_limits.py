"""What a replay may not claim, and how long it may take."""

import time
from unittest.mock import patch

import pytest
from sqlalchemy import select

from core.detections.engineering import proposals, replay
from core.detections.overlay import Refused
from core.storage.models import DetectionRule
from core.storage.unit_of_work import unit_of_work

from .conftest import RULE

SPL = 'ParentImage="*\\\\WINWORD.EXE" CommandLine="*-enc*"'


def _cased(pattern):
    return f"""
title: Cased wildcard
logsource: {{category: process_creation, product: windows}}
detection:
  selection:
    CommandLine|cased: '{pattern}'
  condition: selection
"""


def test_a_catastrophic_wildcard_pattern_finishes_at_once_with_the_right_answer():
    pattern = "*a" * 20 + "b"
    matcher, engine = replay.matcher_for(_cased(pattern))
    assert engine == "sigma-tree"
    started = time.monotonic()
    assert matcher({"CommandLine": "a" * 35}) is False
    assert time.monotonic() - started < 0.5
    assert matcher({"CommandLine": "a" * 35 + "b"}) is True


@pytest.mark.parametrize(
    "pattern, value, expected",
    [
        ("Power*Shell", "PowerXShell", True),
        ("Power*Shell", "powerxshell", False),
        ("Power?Shell", "PowerXShell", True),
        ("Power?Shell", "PowerShell", False),
        ("Power*", "Powershell.exe", True),
        ("*Shell", "PowerShell", True),
        ("*Shell", "PowerShell.exe", False),
        ("a*b*c", "aXbYc", True),
        ("a*b*c", "aXcYb", False),
        ("a*a", "a", False),
        ("a*a", "aa", True),
        ("exact", "exact", True),
        ("exact", "not exact", False),
        ("a?c", "a\nc", True),
    ],
)
def test_a_cased_wildcard_keeps_sigma_semantics(pattern, value, expected):
    matcher, _ = replay.matcher_for(_cased(pattern))
    assert matcher({"CommandLine": value}) is expected


def test_a_pattern_with_too_many_wildcards_is_refused_by_name():
    with pytest.raises(replay.NotReplayable, match="wildcards"):
        replay.matcher_for(_cased("*a" * (replay.MAX_WILDCARDS + 1)))[0](
            {"CommandLine": "a"}
        )


@pytest.mark.database
def test_a_replay_that_runs_past_its_time_says_so_and_proves_nothing(attack_and_benign):
    view = proposals.create(
        sigma=RULE, actor="dana.reviewer", case_id=attack_and_benign
    )
    view = proposals.lint(view["proposal_id"], "dana.reviewer")
    with patch.object(replay, "MAX_MATCH_SECONDS", -1):
        view = proposals.replay(view["proposal_id"], "dana.reviewer")
    evidence = view["latest"]["replay"]["evidence"]
    assert evidence["evaluated"] is False
    assert "took longer" in evidence["reason"]


@pytest.mark.database
def test_a_capped_replay_is_not_proven_and_says_why(attack_and_benign):
    view = proposals.create(
        sigma=RULE, actor="dana.reviewer", case_id=attack_and_benign
    )
    view = proposals.lint(view["proposal_id"], "dana.reviewer")
    with patch.object(replay, "MAX_BENIGN_ROWS", 1):
        view = proposals.replay(view["proposal_id"], "dana.reviewer")
    evidence = view["latest"]["replay"]["evidence"]
    assert evidence["benign_truncated"] is True
    assert evidence["proven"] is False
    assert "newest 1" in evidence["unproven_because"]


@pytest.fixture
def in_shadow(attack_and_benign, person):
    view = proposals.create(
        sigma=RULE, actor="dana.reviewer", case_id=attack_and_benign
    )
    view = proposals.lint(view["proposal_id"], "dana.reviewer")
    view = proposals.replay(view["proposal_id"], "dana.reviewer")
    view = proposals.convert(
        view["proposal_id"],
        "dana.reviewer",
        wanted=["splunk"],
        pasted={"splunk": SPL},
    )
    return proposals.shadow(view["proposal_id"], person)


@pytest.mark.database
def test_the_shadow_report_counts_the_whole_window_and_marks_the_cap(
    in_shadow, add_event, attack_row, plain_row
):
    for _ in range(3):
        add_event(plain_row, age_days=-0.01)
    with patch.object(replay, "MAX_BENIGN_ROWS", 2):
        report = proposals.shadow_report(in_shadow["proposal_id"])
    assert report["rows"] == 3
    assert report["rows_checked"] == 2
    assert report["truncated"] is True

    report = proposals.shadow_report(in_shadow["proposal_id"])
    assert (report["rows"], report["rows_checked"]) == (3, 3)
    assert report["truncated"] is False


@pytest.mark.database
def test_promotion_is_refused_while_shadow_measured_only_part_of_its_window(
    in_shadow, person, add_event, plain_row
):
    for _ in range(3):
        add_event(plain_row, age_days=-0.01)
    with patch.object(replay, "MAX_BENIGN_ROWS", 2):
        with pytest.raises(Refused, match="newest 2 of 3"):
            proposals.promote(in_shadow["proposal_id"], person, "Looks quiet")
    view = proposals.get(in_shadow["proposal_id"])
    assert view["state"] == "shadow"
    with unit_of_work() as session:
        assert session.scalars(select(DetectionRule)).first() is not None
    assert (
        proposals.promote(in_shadow["proposal_id"], person, "Looks quiet")["state"]
        == "live"
    )


def test_a_stored_replay_that_was_capped_never_counts_as_proof():
    assert proposals.replay_proves({"proven": True, "benign_truncated": False}) is True
    assert proposals.replay_proves({"proven": True, "benign_truncated": True}) is False
    assert proposals.replay_proves({"proven": False}) is False
