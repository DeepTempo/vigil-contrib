"""Which closed tickets count as labels, and why the rest do not."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from core.coldstart.baseline import Alert, signature_for
from core.coldstart.sample_history import FIXTURE, load_fixture
from core.coldstart.tickets import (
    Label,
    filter_tickets,
    outcomes_from,
    parse_ticket_file,
)

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def _ticket(ticket_id="t", disposition="False Positive", closed_at=T0, **over):
    return {
        "ticket_id": ticket_id,
        "disposition": disposition,
        "closed_at": closed_at.isoformat() if closed_at else None,
        **over,
    }


@pytest.mark.skipif(
    not FIXTURE.exists(), reason="needs scripts/coldstart/build_sample.py's fixture"
)
def test_the_normalized_export_filters_to_exactly_its_usable_labels():
    tickets = load_fixture()["tickets"]
    result = filter_tickets(tickets)
    assert len(result.kept) == 1852
    assert dict(result.dropped) == {
        "bulk_close": 86,
        "duplicate": 76,
        "undetermined": 147,
    }
    usable = {t["ticket_id"] for t in tickets if t["usable_label"]}
    assert {t.external_id for t in result.kept} == usable


@pytest.mark.skipif(
    not FIXTURE.exists(), reason="needs scripts/coldstart/build_sample.py's fixture"
)
def test_the_bulk_rule_alone_finds_the_bulk_closes():
    """The filter's own rule, with the export's usable_label flag taken away."""
    tickets = [
        {k: v for k, v in t.items() if k not in ("usable_label", "label_quality")}
        for t in load_fixture()["tickets"]
        if t["label_quality"] in ("good", "lazy_bulk")
    ]
    assert filter_tickets(tickets).dropped["bulk_close"] == 86


@pytest.mark.parametrize(
    "raw, label",
    [
        ("True Positive", Label.TRUE_POSITIVE),
        ("TP", Label.TRUE_POSITIVE),
        ("TruePositive", Label.TRUE_POSITIVE),
        ("Confirmed Malicious", Label.TRUE_POSITIVE),
        ("BenignPositive", Label.BENIGN_POSITIVE),
        ("Benign - Expected Activity", Label.BENIGN_POSITIVE),
        ("Authorized Activity", Label.BENIGN_POSITIVE),
        ("false_positive", Label.FALSE_POSITIVE),
        ("FP", Label.FALSE_POSITIVE),
        ("Noise - Tuning Needed", Label.FALSE_POSITIVE),
    ],
)
def test_raw_values_map_to_one_label(raw, label):
    result = filter_tickets([_ticket(disposition=raw)])
    assert [t.disposition for t in result.kept] == [label]


@pytest.mark.parametrize(
    "ticket, reason",
    [
        (_ticket(disposition="Closed - Won't Fix"), "unmapped_disposition"),
        (_ticket(disposition=None), "unmapped_disposition"),
        (_ticket(closed_at=None), "no_closed_at"),
        (_ticket(disposition="Duplicate"), "duplicate"),
        (_ticket(duplicate_of="t0"), "duplicate"),
        (_ticket(disposition="Undetermined"), "undetermined"),
        (_ticket(disposition="Unable to Determine"), "undetermined"),
        (_ticket(usable_label=False, label_quality="lazy_bulk"), "bulk_close"),
        (_ticket(usable_label=False, label_quality="auto_closed"), "undetermined"),
    ],
)
def test_each_reason_is_counted_and_nothing_is_kept(ticket, reason):
    result = filter_tickets([ticket])
    assert result.kept == []
    assert dict(result.dropped) == {reason: 1}


def _burst(count, spacing_seconds=20, closer="alice"):
    return [
        _ticket(
            f"t{i}",
            closed_at=T0 + timedelta(seconds=i * spacing_seconds),
            closed_by=closer,
        )
        for i in range(count)
    ]


def test_ten_closes_in_five_minutes_by_one_person_are_a_bulk_close():
    result = filter_tickets(_burst(10))
    assert result.kept == []
    assert result.dropped["bulk_close"] == 10


def test_nine_closes_are_not():
    assert len(filter_tickets(_burst(9)).kept) == 9


def test_ten_closes_over_more_than_five_minutes_are_not():
    assert len(filter_tickets(_burst(10, spacing_seconds=40)).kept) == 10


def test_ten_closes_by_different_people_are_not():
    tickets = [
        _ticket(f"t{i}", closed_at=T0 + timedelta(seconds=i), closed_by=f"p{i}")
        for i in range(10)
    ]
    assert len(filter_tickets(tickets).kept) == 10


def test_a_repeated_external_id_is_counted_as_a_duplicate_and_kept_once():
    result = filter_tickets([_ticket("t1"), _ticket("t1")])
    assert [t.external_id for t in result.kept] == ["t1"]
    assert dict(result.dropped) == {"duplicate": 1}


def test_a_ticket_links_to_each_alert_it_names():
    alert = Alert("a1", "edr", "Malware on h1", "low", T0, frozenset({"host:h1"}))
    kept = filter_tickets(
        [_ticket(alert_refs=[{"external_id": "a1"}, {"external_id": "gone"}])]
    ).kept
    outcomes, unlinked = outcomes_from(kept, {"a1": alert})
    assert unlinked == 0
    assert [(o.signature, o.entities) for o in outcomes] == [
        (signature_for(alert), alert.entities)
    ]


def test_a_ticket_with_no_alert_and_no_title_is_kept_and_counted_as_unlinked():
    outcomes, unlinked = outcomes_from(filter_tickets([_ticket()]).kept, {})
    assert (outcomes, unlinked) == ([], 1)


def test_simple_csv(tmp_path):
    path = tmp_path / "tickets.csv"
    path.write_text(
        "title,alert_id,source,entities,disposition,closed_at,closed_by\n"
        "Failed login for bob,,okta,user:bob;ip:1.2.3.4,FP,2026-10-01T12:00:00Z,al\n"
        ",a1,,,TP,2026-10-01T13:00:00Z,al\n"
        "No close,,okta,,FP,,al\n"
        "Odd,,okta,,Won't Fix,2026-10-01T14:00:00Z,al\n"
    )
    result = parse_ticket_file(path, "csv")
    assert dict(result.dropped) == {"no_closed_at": 1, "unmapped_disposition": 1}
    by_title, by_id = result.kept
    assert by_title.signature == "okta|Failed login for <entity>"
    assert by_title.entities == frozenset({"user:bob", "ip:1.2.3.4"})
    assert by_id.alert_ids == ("a1",) and by_id.signature is None
    assert by_id.disposition is Label.TRUE_POSITIVE


def test_csv_with_no_id_column_gets_the_same_id_on_a_second_read(tmp_path):
    path = tmp_path / "tickets.csv"
    path.write_text("alert_id,disposition,closed_at\na1,FP,2026-10-01T12:00:00Z\n")
    first = parse_ticket_file(path, "csv").kept[0]
    assert parse_ticket_file(path, "csv").kept[0].external_id == first.external_id


def test_json_and_jsonl_read_alike_and_a_bad_line_is_counted(tmp_path):
    rows = [_ticket("t1"), _ticket("t2", "TP")]
    as_json = tmp_path / "t.json"
    as_json.write_text(json.dumps({"tickets": rows}))
    as_jsonl = tmp_path / "t.jsonl"
    as_jsonl.write_text("\n".join(json.dumps(r) for r in rows) + "\nnot json\n")

    from_json = parse_ticket_file(as_json, "json")
    from_jsonl = parse_ticket_file(as_jsonl, "jsonl")
    assert from_json.kept == from_jsonl.kept and len(from_json.kept) == 2
    assert dict(from_jsonl.dropped) == {"unreadable": 1}


def test_a_file_that_cannot_be_read_at_all_is_a_value_error(tmp_path):
    path = tmp_path / "t.json"
    path.write_text("{not json")
    with pytest.raises(ValueError):
        parse_ticket_file(path, "json")


def test_two_ticket_systems_sharing_a_number_are_two_tickets():
    benign = _ticket(ticket_id="0", source_system="jira")
    real = _ticket(ticket_id="0", source_system="sentinel", disposition="true_positive")
    result = filter_tickets([benign, real])
    assert not result.dropped
    assert {t.external_id for t in result.kept} == {"jira:0", "sentinel:0"}


def test_an_id_already_named_for_its_system_is_not_prefixed_twice():
    result = filter_tickets([_ticket(ticket_id="jira:SOC-1", source_system="jira")])
    assert result.kept[0].external_id == "jira:SOC-1"
