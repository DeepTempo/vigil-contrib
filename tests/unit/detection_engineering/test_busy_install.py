"""A busy install can finish a replay and a shadow, and is told the truth when it cannot."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from core.detections.engineering import proposals, replay
from core.detections.overlay import Refused
from core.storage.unit_of_work import unit_of_work

from .conftest import RULE

SPL = 'ParentImage="*\\\\WINWORD.EXE" CommandLine="*-enc*"'
OTHER_SHAPE = {"dns_query": "example.org", "answers": ["192.0.2.1"]}

pytestmark = pytest.mark.database


def _rule(detection):
    return f"""
title: One rule
logsource: {{category: test}}
detection:
{detection}
"""


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


def _later(**delta):
    moment = datetime.now(timezone.utc) + timedelta(**delta)
    return patch.object(replay, "_now", lambda: moment)


def test_rows_without_the_rules_fields_cannot_stop_a_shadow(
    in_shadow, person, add_event
):
    for _ in range(3):
        add_event(OTHER_SHAPE, age_days=-0.01)
    with patch.object(replay, "MAX_BENIGN_ROWS", 2):
        report = proposals.shadow_report(in_shadow["proposal_id"])
        assert report["truncated"] is False
        assert (report["rows"], report["rows_stored"]) == (0, 3)
        view = proposals.promote(in_shadow["proposal_id"], person, "Quiet.")
    assert view["state"] == "live"


def test_a_person_can_measure_a_window_a_busy_shadow_fits_in(
    in_shadow, person, add_event, plain_row
):
    for _ in range(3):
        add_event(plain_row, age_days=-0.01)
    add_event(plain_row, age_days=-3)
    pid = in_shadow["proposal_id"]
    with _later(days=3), patch.object(replay, "MAX_BENIGN_ROWS", 2):
        whole = proposals.shadow_report(pid)
        assert whole["truncated"] is True
        assert "shorter window" in whole["advice"]
        with pytest.raises(Refused, match="newest 2 of 4"):
            proposals.promote(pid, person, "Quiet.")

        hour = proposals.shadow_report(pid, window_hours=2)
        assert (hour["rows"], hour["truncated"]) == (1, False)
        assert hour["window_hours"] == 2
        view = proposals.promote(pid, person, "Quiet.", window_hours=2)
    assert view["state"] == "live"
    shadow = view["latest"]["live"]["evidence"]["shadow"]
    assert (shadow["window_hours"], shadow["rows"], shadow["truncated"]) == (
        2,
        1,
        False,
    )


def test_a_shadow_too_busy_for_the_shortest_window_says_what_is_left(
    in_shadow, person, add_event, plain_row
):
    for _ in range(3):
        add_event(plain_row, age_days=-0.001)
    pid = in_shadow["proposal_id"]
    with patch.object(replay, "MAX_BENIGN_ROWS", 2):
        report = proposals.shadow_report(pid, window_hours=1)
        assert report["truncated"] is True
        assert "shorter window" not in report["advice"]
        assert "cannot measure" in report["advice"]
        with pytest.raises(Refused, match="cannot measure"):
            proposals.promote(pid, person, "Quiet.", window_hours=1)


def test_a_replay_reads_only_rows_that_can_prove_the_rule(attack_and_benign, add_event):
    for _ in range(3):
        add_event(OTHER_SHAPE, age_days=0.5)
    view = proposals.create(
        sigma=RULE, actor="dana.reviewer", case_id=attack_and_benign
    )
    view = proposals.lint(view["proposal_id"], "dana.reviewer")
    with patch.object(replay, "MAX_BENIGN_ROWS", 2):
        view = proposals.replay(view["proposal_id"], "dana.reviewer", window_hours=48)
    evidence = view["latest"]["replay"]["evidence"]
    assert evidence["benign_truncated"] is False
    assert evidence["benign_scope"] == "holding_fields"
    assert evidence["window_hours"] == 48
    assert evidence["proven"] is True


def test_a_capped_replay_points_to_hours_then_says_when_no_window_can_prove_it(
    attack_and_benign, add_event, plain_row
):
    for _ in range(4):
        add_event(plain_row, age_days=0.001)
    view = proposals.create(
        sigma=RULE, actor="dana.reviewer", case_id=attack_and_benign
    )
    view = proposals.lint(view["proposal_id"], "dana.reviewer")
    pid = view["proposal_id"]
    with patch.object(replay, "MAX_BENIGN_ROWS", 1):
        day = proposals.replay(pid, "dana.reviewer", window_hours=24)
        hour = proposals.replay(pid, "dana.reviewer", window_hours=1)
    assert "shorter window" in day["latest"]["replay"]["evidence"]["unproven_because"]
    why = hour["latest"]["replay"]["evidence"]["unproven_because"]
    assert "shorter window" not in why
    assert "cannot prove" in why and "written reason" in why


def test_a_window_of_hours_leaves_out_older_rows_and_can_turn_green(
    attack_and_benign, add_event, plain_row
):
    for _ in range(3):
        add_event(plain_row, age_days=0.5)
    view = proposals.create(
        sigma=RULE, actor="dana.reviewer", case_id=attack_and_benign
    )
    view = proposals.lint(view["proposal_id"], "dana.reviewer")
    add_event(plain_row, age_days=0.01)
    with patch.object(replay, "MAX_BENIGN_ROWS", 1):
        view = proposals.replay(view["proposal_id"], "dana.reviewer", window_hours=1)
    evidence = view["latest"]["replay"]["evidence"]
    assert evidence["benign_truncated"] is False
    assert evidence["proven"] is True


@pytest.mark.parametrize(
    "detection",
    [
        "  selection: {CommandLine|contains: x}\n  condition: not selection",
        "  selection: {CommandLine: null}\n  condition: selection",
        "  selection: [just-a-keyword]\n  other: {CommandLine: x}\n"
        "  condition: selection or other",
    ],
    ids=["negated", "null value", "keywords"],
)
def test_a_rule_that_can_match_without_its_fields_is_measured_on_every_row(
    db, add_event, detection
):
    add_event({"unrelated": "just-a-keyword"}, age_days=0.01)
    with unit_of_work() as session:
        report = replay.since(
            session,
            _rule(detection),
            entered=datetime.now(timezone.utc) - timedelta(days=1),
            case_id=None,
        )
    assert report["scoped"] is False
    assert (report["rows"], report["matches"]) == (1, 1)


@pytest.mark.parametrize(
    "field, raw",
    [
        ("Plain", {"Plain": "needle"}),
        ("Has Space", {"Has Space": "needle"}),
        ("a.b", {"a": {"b": "needle"}}),
        ("a.b", {"a.b": "needle"}),
        ("a.b.c", {"a.b": {"c": "needle"}}),
    ],
)
def test_a_field_is_found_however_the_source_nested_it(db, add_event, field, raw):
    add_event(raw, age_days=0.01)
    add_event(OTHER_SHAPE, age_days=0.01)
    detection = f"  selection: {{'{field}': needle}}\n  condition: selection"
    with unit_of_work() as session:
        report = replay.since(
            session,
            _rule(detection),
            entered=datetime.now(timezone.utc) - timedelta(days=1),
            case_id=None,
        )
    assert report["scoped"] is True
    assert (report["rows"], report["rows_stored"], report["matches"]) == (1, 2, 1)


def test_a_field_in_a_column_is_found_too(db, add_event):
    add_event({"other": "x"}, age_days=0.01)
    detection = "  selection: {source: sysmon}\n  condition: selection"
    with unit_of_work() as session:
        report = replay.since(
            session,
            _rule(detection),
            entered=datetime.now(timezone.utc) - timedelta(days=1),
            case_id=None,
        )
    assert (report["scoped"], report["rows"], report["matches"]) == (True, 1, 1)
