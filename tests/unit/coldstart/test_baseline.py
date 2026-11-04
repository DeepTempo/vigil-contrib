"""The stored baseline, what it can see, and how alerts read into it."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from core.coldstart.baseline import (
    Alert,
    Baseline,
    Outcome,
    Stage1,
    alert_from_finding,
    assess,
    build_baseline,
    signature_for,
    signature_of,
)
from core.coldstart.collect import alert_row
from core.coldstart.judge import evidence_lines
from core.coldstart.runner import build_run
from core.coldstart.sample_history import FIXTURE, load_sample
from core.coldstart.tickets import Label, Ticket, filter_tickets, outcomes_from

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)


def _alert(
    alert_id, when, title="Port scan", entities=("ip:10.0.0.1",), severity="low"
):
    return Alert(alert_id, "ids", title, severity, when, frozenset(entities))


def _sample():
    findings, tickets = load_sample(NOW)
    rows = [alert_row(f) for f in findings]
    alerts = [
        Alert(
            r["alert_id"],
            r["source"],
            r["title"],
            r["severity"],
            r["observed_at"],
            frozenset(r["entities"]),
        )
        for r in rows
    ]
    return alerts, filter_tickets(tickets).kept


@pytest.mark.skipif(
    not FIXTURE.exists(), reason="needs scripts/coldstart/build_sample.py's fixture"
)
def test_a_baseline_survives_json_and_decides_the_same():
    alerts, tickets = _sample()
    build = build_run(alerts, tickets, history_days=30, review_days=7, now=NOW)
    restored = Baseline.from_dict(json.loads(json.dumps(build.baseline.to_dict())))

    assert restored == build.baseline
    row = next(r for r in restored.signatures.values() if r.count and r.benign)
    assert sum(row.entity_counts.values()) > 0
    assert row.entity_counts["user:nobody-here"] == 0, "still a Counter"
    assert row.first_seen.tzinfo is not None and row.first_seen < row.last_seen
    for alert in alerts[:200]:
        assert assess(alert, restored) == assess(alert, build.baseline)
        assert evidence_lines(alert, restored) == evidence_lines(alert, build.baseline)


def test_later_alerts_and_tickets_do_not_leak_into_the_baseline():
    as_of = NOW - timedelta(days=7)
    before = [_alert(f"a{i}", as_of - timedelta(days=i + 1)) for i in range(6)]
    signature = signature_for(before[0])
    benign = [
        Outcome(
            signature, "false_positive", as_of - timedelta(days=1), before[0].entities
        )
    ]
    clean = build_baseline(before, benign, as_of)

    at_boundary = _alert("b", as_of)
    later_alert = _alert("c", as_of + timedelta(days=1), entities=("ip:9.9.9.9",))
    later_real = Outcome(signature, "true_positive", as_of, before[0].entities)
    leaked = build_baseline(
        [*before, at_boundary, later_alert], [*benign, later_real], as_of
    )

    assert leaked.to_dict() == clean.to_dict()
    assert leaked.alerts_seen == 6
    row = leaked.signatures[signature]
    assert row.true_positive == 0 and row.entity_counts["ip:9.9.9.9"] == 0


def test_a_ticket_closed_after_the_window_opens_cannot_decide_an_alert_in_it():
    alerts = [
        _alert(f"a{i}", NOW - timedelta(days=d))
        for i, d in enumerate((20, 19, 18, 17, 16, 15, 0.5))
    ]
    closed_later = Ticket(
        "t1",
        Label.TRUE_POSITIVE,
        NOW - timedelta(hours=1),
        alert_ids=("a0",),
    )
    build = build_run(alerts, [closed_later], history_days=30, review_days=1, now=NOW)
    row = build.baseline.signatures[signature_for(alerts[0])]
    assert row.true_positive == 0
    assert [a["alert_id"] for a in build.assessed] == ["a6"]
    assert build.assessed[0]["stage1"] == "dismiss_candidate"


def test_the_window_ends_at_the_newest_alert_so_an_old_export_still_has_a_review():
    last_week = NOW - timedelta(days=7)
    alerts = [_alert("old", last_week - timedelta(days=3)), _alert("new", last_week)]
    build = build_run(alerts, [], history_days=30, review_days=1, now=NOW)
    assert build.as_of == last_week - timedelta(days=1)
    assert [a["alert_id"] for a in build.assessed] == ["new"]


def test_a_future_stamped_alert_cannot_push_the_window_past_now():
    alerts = [_alert("future", NOW + timedelta(days=30)), _alert("now", NOW)]
    build = build_run(alerts, [], history_days=30, review_days=1, now=NOW)
    assert build.as_of == NOW - timedelta(days=1)


def test_history_days_bounds_what_the_baseline_reads():
    alerts = [
        _alert("too-old", NOW - timedelta(days=40)),
        _alert("kept", NOW - timedelta(days=20)),
        _alert("window", NOW),
    ]
    build = build_run(alerts, [], history_days=30, review_days=1, now=NOW)
    assert build.baseline.alerts_seen == 1


@pytest.mark.parametrize(
    "context, expected",
    [
        ({"dest_ips": ["10.0.0.2"]}, {"ip:10.0.0.2"}),
        ({"dst_ips": ["10.0.0.2"]}, {"ip:10.0.0.2"}),
        ({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}, {"ip:10.0.0.1", "ip:10.0.0.2"}),
        ({"hostname": "h1", "user": "alice"}, {"host:h1", "user:alice"}),
        ({"usernames": ["alice"], "hostnames": ["h1"]}, {"host:h1", "user:alice"}),
        ({"sequence_id": "x", "src_ip": None}, set()),
    ],
)
def test_every_shape_an_adapter_or_row_writes_reads_as_entities(context, expected):
    alert = alert_from_finding(
        {"timestamp": NOW.isoformat(), "title": "t", "entity_context": context}
    )
    assert alert.entities == frozenset(expected)


def test_one_kind_of_alert_on_different_entities_shares_a_signature():
    a = _alert("a", NOW, "Failed login for alice", ("user:alice",))
    b = _alert("b", NOW, "Failed login for bob", ("user:bob",))
    assert signature_for(a) == signature_for(b)


def test_a_ticket_with_no_alert_it_can_name_links_by_source_and_title():
    alert = _alert("a", NOW, "Failed login for alice", ("user:alice",))
    by_title = filter_tickets(
        [
            {
                "ticket_id": "t",
                "title": "Failed login for bob",
                "source": "ids",
                "entities": "user:bob",
                "disposition": "FP",
                "closed_at": NOW.isoformat(),
            }
        ]
    ).kept
    outcomes, unlinked = outcomes_from(by_title, {alert.alert_id: alert})
    assert unlinked == 0
    assert outcomes[0].signature == signature_for(alert)
    assert outcomes[0].entities == frozenset({"user:bob"})


def _ticket(closed_at, alert_ids, signature=None):
    return Ticket(
        external_id="t-1",
        disposition=Label("benign_positive"),
        closed_at=closed_at,
        alert_ids=tuple(alert_ids),
        signature=signature,
        entities=frozenset(),
        source_system="jira",
    )


def test_one_ticket_repeating_an_alert_id_is_one_label():
    seen = datetime(2026, 1, 1, tzinfo=timezone.utc)
    alert = Alert("a-1", "edr", "Port sweep", "low", seen, frozenset({"host:h1"}))
    closed = seen + timedelta(hours=1)
    outcomes, unlinked = outcomes_from([_ticket(closed, ["a-1"] * 20)], {"a-1": alert})
    assert len(outcomes) == 1 and unlinked == 0


def test_a_ticket_cannot_label_an_alert_seen_after_it_closed():
    seen = datetime(2026, 1, 10, tzinfo=timezone.utc)
    alert = Alert("a-1", "edr", "Port sweep", "low", seen, frozenset({"host:new"}))
    earlier = seen - timedelta(days=5)
    outcomes, unlinked = outcomes_from(
        [_ticket(earlier, ["a-1"], signature="edr|Port sweep")], {"a-1": alert}
    )
    assert outcomes == [] and unlinked == 1


def test_a_number_in_a_title_keeps_detections_apart():
    assert signature_of("elastic", "Windows Event 4624") != signature_of(
        "elastic", "Windows Event 1102"
    )
    assert signature_of(
        "edr", "Failed login for alice", ["user:alice"]
    ) == signature_of("edr", "Failed login for bob", ["user:bob"])


def test_a_long_decimal_detection_code_keeps_detections_apart():
    assert signature_of("edr", "Detection 12345678") != signature_of(
        "edr", "Detection 87654321"
    )
    assert signature_of("edr", f"Hash {'a1' * 16} seen") == signature_of(
        "edr", f"Hash {'b2' * 16} seen"
    )


def _kind_with_clean_tickets(tickets, *, real=0, days=40):
    """A kind fired on one known host, with this many benign tickets and real ones."""
    known = frozenset({"host:known"})
    alerts = [
        Alert(f"a{i}", "edr", "Port sweep", "low", NOW - timedelta(days=i + 2), known)
        for i in range(days)
    ]
    key = signature_for(alerts[0])
    closed = NOW - timedelta(days=2)
    outcomes = [Outcome(key, "benign_positive", closed)] * tickets
    outcomes += [Outcome(key, "true_positive", closed)] * real
    return build_baseline(alerts, outcomes, NOW)


def _on_new_host(severity):
    return Alert(
        "new", "edr", "Port sweep", severity, NOW, frozenset({"host:never-seen"})
    )


def test_a_new_host_needs_59_clean_tickets_before_a_kind_can_close_on_it():
    assert assess(_on_new_host("low"), _kind_with_clean_tickets(58)).stage1 is (
        Stage1.ABSTAIN
    )
    assert assess(_on_new_host("low"), _kind_with_clean_tickets(59)).stage1 is (
        Stage1.DISMISS_CANDIDATE
    )


def test_a_high_severity_alert_on_a_new_host_never_closes_on_the_kinds_record():
    result = assess(_on_new_host("high"), _kind_with_clean_tickets(500))
    assert result.stage1 is Stage1.ABSTAIN


def test_without_tickets_frequency_clears_only_low_severity():
    history = _kind_with_clean_tickets(0)
    known = frozenset({"host:known"})
    low = Alert("n1", "edr", "Port sweep", "low", NOW, known)
    medium = Alert("n2", "edr", "Port sweep", "medium", NOW, known)
    assert assess(low, history).stage1 is Stage1.DISMISS_CANDIDATE
    assert assess(medium, history).stage1 is Stage1.ABSTAIN


def test_a_real_ticket_older_than_the_alert_window_still_blocks_closing():
    alerts = [
        Alert(
            f"a{i}",
            "edr",
            "Port sweep",
            "low",
            NOW - timedelta(days=i + 2),
            frozenset(),
        )
        for i in range(10)
    ]
    old_alert = Alert(
        "old", "edr", "Port sweep", "low", NOW - timedelta(days=80), frozenset()
    )
    benign = [
        Ticket(
            f"t{i}",
            Label.BENIGN_POSITIVE,
            NOW - timedelta(days=3),
            alert_ids=(f"a{i}",),
        )
        for i in range(10)
    ]
    real = Ticket(
        "old", Label.TRUE_POSITIVE, NOW - timedelta(days=79), alert_ids=("old",)
    )
    build = build_run(
        [*alerts, old_alert], [*benign, real], history_days=14, review_days=1, now=NOW
    )
    assert build.baseline.signatures[signature_for(old_alert)].true_positive == 1


def test_one_ticket_naming_59_alerts_is_one_decision_not_59():
    alerts = {
        f"a{i}": Alert(
            f"a{i}", "edr", "Port sweep", "low", NOW - timedelta(days=100), frozenset()
        )
        for i in range(59)
    }
    ticket = Ticket(
        "t-1",
        Label.BENIGN_POSITIVE,
        NOW - timedelta(days=99),
        alert_ids=tuple(alerts),
    )
    outcomes, _ = outcomes_from([ticket], alerts)
    baseline = build_baseline(alerts.values(), outcomes, NOW)
    assert baseline.signatures[signature_for(alerts["a0"])].benign == 1
    assert assess(_on_new_host("medium"), baseline).stage1 is Stage1.ABSTAIN


def test_separate_tickets_each_count_once():
    alerts = {
        f"a{i}": Alert(
            f"a{i}",
            "edr",
            "Port sweep",
            "low",
            NOW - timedelta(days=9),
            frozenset({"host:h"}),
        )
        for i in range(3)
    }
    tickets = [
        Ticket(
            f"t-{i}",
            Label.BENIGN_POSITIVE,
            NOW - timedelta(days=8),
            alert_ids=(f"a{i}",),
        )
        for i in range(3)
    ]
    outcomes, _ = outcomes_from(tickets, alerts)
    row = build_baseline(alerts.values(), outcomes, NOW).signatures[
        signature_for(alerts["a0"])
    ]
    assert row.benign == 3 and row.entity_benign["host:h"] == 3
