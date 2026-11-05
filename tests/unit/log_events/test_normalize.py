"""What one source's row becomes in the one schema. No database."""

from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest

from core.log_events.ingest import (
    DROP_FUTURE_TIME,
    DROP_NO_TIME,
    DROP_NOT_OBJECT,
    DROP_PAST_RETENTION,
    DROP_TOO_LARGE,
    NOTE_BAD_SCORE,
    NOTE_REDACTED,
    Dropped,
    normalize,
    parse_time,
    source_label,
)
from tests.unit.log_events import samples

pytestmark = pytest.mark.unit

AT = samples.now()


def event(record, source=None, case_id=None, notes=None):
    return normalize(
        record,
        source=source,
        case_id=case_id,
        now=AT + timedelta(minutes=1),
        oldest=AT - timedelta(days=30),
        notes=Counter() if notes is None else notes,
    )


@pytest.mark.parametrize(
    "record, shape, expected",
    [
        (
            samples.zeek_conn(AT),
            "zeek_conn",
            {
                "source": "zeek",
                "event_class": "Network",
                "src_ip": "192.0.2.5",
                "dst_ip": "192.0.2.9",
                "dst_port": 445,
                "action": "completed",
                "summary": "tcp smb 192.0.2.5 to 192.0.2.9 port 445 completed 1200 bytes out",
            },
        ),
        (
            samples.zeek_dns(AT),
            "zeek_dns",
            {
                "source": "dns",
                "event_class": "DNS",
                "src_ip": "192.0.2.5",
                "dst_host": "quokka-update.example.net",
                "action": "NOERROR",
                "summary": "A query quokka-update.example.net answered 198.51.100.7",
            },
        ),
        (
            samples.dns_log(AT),
            "dns",
            {
                "source": "dns",
                "src_ip": "192.0.2.6",
                "dst_host": "wombat-cdn.example.org",
                "action": "NXDOMAIN",
            },
        ),
        (
            samples.windows_logon(AT),
            "windows_security",
            {
                "source": "winsec",
                "event_class": "Authentication",
                "action": "logon_failed",
                "user_name": "pat.quill",
                "src_ip": "192.0.2.7",
                "src_host": "wks-rig-7",
                "dst_host": "dc-rig-1.corp.example",
            },
        ),
        (
            samples.winlogbeat_process(AT),
            "windows_security",
            {
                "source": "winsec",
                "event_class": "Process",
                "action": "process_start",
                "src_host": "wks-rig-7",
                "dst_host": None,
                "user_name": "pat.quill",
            },
        ),
        (
            samples.sysmon_process(AT),
            "sysmon",
            {
                "source": "sysmon",
                "event_class": "Process",
                "action": "process_start",
                "src_host": "wks-rig-8",
                "user_name": "CORP\\sam.ridge",
                "summary": "Process started C:\\Windows\\System32\\quokkahost.exe quokkahost.exe -enc AAAA",
            },
        ),
        (
            samples.paloalto_csv_row(AT),
            "paloalto",
            {
                "source": "paloalto",
                "event_class": "Firewall",
                "action": "deny",
                "dst_ip": "203.0.113.40",
                "dst_port": 8443,
                "user_name": "CORP\\sam.ridge",
            },
        ),
        (
            samples.crowdstrike_process(AT),
            "crowdstrike",
            {
                "source": "crowdstrike",
                "event_class": "Process",
                "action": "process_start",
                "severity": "high",
                "src_host": "wks-rig-9",
                "mitre": "T1059.001",
            },
        ),
        (
            samples.entra_failed(AT),
            "entra",
            {
                "source": "entra",
                "event_class": "Sign-in",
                "action": "signin_failed",
                "user_name": "lee.marsh@corp.example",
                "src_ip": "198.51.100.23",
                "summary": "Sign-in failed for lee.marsh@corp.example to Rig Portal from 198.51.100.23 Testville Invalid password",
            },
        ),
        (
            samples.generic(AT),
            "generic",
            {
                "source": "rigapp-audit",
                "severity": "medium",
                "action": "export",
                "src_host": "app-rig-1",
                "user_name": "kit.vale",
                "dst_ip": None,
                "dst_host": "not-an-address",
                "summary": "Exported the quokka report",
            },
        ),
    ],
)
def test_each_shape_fills_the_one_schema_and_keeps_the_record(record, shape, expected):
    found, row = event(record)
    assert found.key == shape
    assert {k: row[k] for k in expected} == expected
    assert row["raw"] == record
    assert abs((row["time"] - AT).total_seconds()) < 1
    assert len(row["event_id"]) == 64


def test_free_words_reach_the_summary_and_the_raw_record():
    _, row = event(samples.generic(AT, ticket="ZZ-991"))
    assert "exported the quokka report" in row["search_text"]
    assert "zz-991" in row["search_text"]
    assert row["search_text"] == row["search_text"].lower()


def test_event_id_ignores_key_order_and_the_score_and_case_columns():
    record = samples.zeek_conn(AT)
    _, first = event(record)
    _, reordered = event(dict(reversed(list(record.items()))))
    _, scored = event({**record, "loglm": 0.9, "case_id": "logs-case-1"})
    _, other = event({**record, "uid": "Cfake0002"})
    assert first["event_id"] == reordered["event_id"] == scored["event_id"]
    assert first["event_id"] != other["event_id"]


@pytest.mark.parametrize(
    "score, stored, noted",
    [
        (0.87, 0.87, 0),
        ("0.5", 0.5, 0),
        (0, 0.0, 0),
        (1.5, None, 1),
        (-0.1, None, 1),
        ("high", None, 1),
        ("", None, 0),
    ],
)
def test_a_score_outside_zero_to_one_is_left_out_and_noted(score, stored, noted):
    notes = Counter()
    _, row = event(samples.zeek_conn(AT, loglm=score), notes=notes)
    assert row["loglm"] == stored
    assert notes[NOTE_BAD_SCORE] == noted


def test_a_row_without_a_score_has_none():
    _, row = event(samples.zeek_conn(AT))
    assert row["loglm"] is None


@pytest.mark.parametrize(
    "record, reason",
    [
        ({"message": "no clock here"}, DROP_NO_TIME),
        (samples.generic(AT, time="yesterday-ish"), DROP_NO_TIME),
        (samples.generic(AT, time="-"), DROP_NO_TIME),
        (samples.zeek_conn(AT - timedelta(days=31)), DROP_PAST_RETENTION),
        (samples.zeek_conn(AT + timedelta(days=3)), DROP_FUTURE_TIME),
        (["not", "an", "object"], DROP_NOT_OBJECT),
        ("just text", DROP_NOT_OBJECT),
        (samples.generic(AT, blob="x" * 1_000_001), DROP_TOO_LARGE),
    ],
)
def test_a_row_is_dropped_with_its_reason(record, reason):
    with pytest.raises(Dropped) as dropped:
        event(record)
    assert dropped.value.reason == reason


@pytest.mark.parametrize(
    "text, expected",
    [
        ("1794000000.25", datetime(2026, 11, 6, 21, 20, 0, 250000, timezone.utc)),
        ("1794000000000", datetime(2026, 11, 6, 21, 20, tzinfo=timezone.utc)),
        (
            "2026-11-03T10:22:33Z",
            datetime(2026, 11, 3, 10, 22, 33, tzinfo=timezone.utc),
        ),
        (
            "2026-11-03T10:22:33.123456700Z",
            datetime(2026, 11, 3, 10, 22, 33, 123456, timezone.utc),
        ),
        (
            "2026-11-03T10:22:33+02:00",
            datetime(2026, 11, 3, 8, 22, 33, tzinfo=timezone.utc),
        ),
        (
            "2026-11-03 10:22:33.123",
            datetime(2026, 11, 3, 10, 22, 33, 123000, timezone.utc),
        ),
        ("2026/11/03 10:22:33", datetime(2026, 11, 3, 10, 22, 33, tzinfo=timezone.utc)),
        (
            "11/3/2026 2:22:33 PM",
            datetime(2026, 11, 3, 14, 22, 33, tzinfo=timezone.utc),
        ),
    ],
)
def test_times_from_each_exporter(text, expected):
    assert parse_time(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "",
        None,
        "nan",
        "inf",
        "0",
        "-5",
        "1e400",
        "not a time",
        "0001-01-01T00:00:00+23:59",
    ],
)
def test_what_is_not_a_time(text):
    assert parse_time(text) is None


def test_text_postgres_cannot_hold_is_cleaned_not_fatal():
    _, row = event(
        samples.generic(AT, message="bad\x00byte", extra="\ud800", huge=float("inf"))
    )
    assert row["summary"] == "badbyte"
    assert "\x00" not in row["search_text"]
    assert row["raw"]["huge"] is None
    assert row["raw"]["extra"] == "?"


def test_values_too_long_for_a_column_are_cut_and_the_record_keeps_them():
    long_host = "h" * 400
    _, row = event(samples.generic(AT, host=long_host, source="s" * 80))
    assert row["src_host"] == "h" * 255
    assert len(row["source"]) == 32
    assert row["raw"]["host"] == long_host


def test_a_form_source_names_rows_that_name_none():
    record = {"time": AT.isoformat(), "message": "hello"}
    assert event(record, source="Edge Proxy")[1]["source"] == "edge-proxy"
    assert event(record)[1]["source"] == "generic"


def test_a_row_of_no_known_words_still_shows_something():
    _, row = event({"time": AT.isoformat(), "weird": "value"})
    assert "weird" in row["summary"]


def test_source_labels_come_from_the_table_and_other_sources_keep_their_key():
    assert source_label("winsec") == "Windows Security"
    assert source_label("rigapp-audit") == "rigapp-audit"


def _stored(record, notes=None):
    return event({"time": AT.isoformat(), "msg": "hello", **record}, notes=notes)[1]


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Passwd",
        "client_secret",
        "accessToken",
        "api_key",
        "X-Api-Key",
        "Authorization",
        "Cookie",
        "set-cookie",
        "secretAccessKey",
        "private_key",
    ],
)
def test_a_credential_field_is_gone_before_the_row_is_stored(key):
    notes = Counter()
    stored = _stored({key: "hunter2val"}, notes)
    assert stored["raw"][key] == "[redacted]"
    assert "hunter2val" not in stored["search_text"]
    assert "hunter2val" not in stored["summary"]
    assert "redacted" in stored["tags"]
    assert notes[NOTE_REDACTED] == 1


def test_credentials_are_found_at_any_depth_and_inside_text():
    stored = _stored(
        {
            "request": {"headers": [{"cookie": "abc-cookie"}, {"x": 1}]},
            "nested": {"deep": {"password": {"value": "deep-pass"}}},
            "line": "curl -H 'Authorization: Bearer abc.def-123' http://x",
            "command": "tool --password=sw0rdfish --user bob",
            "url": "https://x.test/?token=abc123&page=2",
        }
    )
    text = stored["search_text"]
    for secret in ("abc-cookie", "deep-pass", "abc.def-123", "sw0rdfish", "abc123"):
        assert secret not in text, secret
        assert secret not in str(stored["raw"]), secret
    assert stored["raw"]["nested"]["deep"]["password"] == "[redacted]"
    assert "page=2" in stored["raw"]["url"]
    assert "--user bob" in stored["raw"]["command"]


@pytest.mark.parametrize(
    "record",
    [
        {"token_type": "bearer"},
        {"password_changed": "2026-01-01"},
        {"TokenElevationType": "%%1936"},
        {"password": True},
        {"secret": None},
    ],
)
def test_fields_that_only_mention_a_credential_stay(record):
    stored = _stored(record)
    key = next(iter(record))
    assert stored["raw"][key] == record[key]
    assert "redacted" not in stored["tags"]


def test_a_whole_header_is_gone_when_it_is_written_in_text():
    stored = _stored(
        {
            "basic": "Authorization: Basic dXNlcjpwYXNz from 192.0.2.1",
            "cookies": "Cookie: session=abc123; theme=dark",
            "quoted": "curl -H 'Authorization: Digest user=bob' http://x.test",
        }
    )
    for secret in ("dXNlcjpwYXNz", "abc123", "dark", "user=bob"):
        assert secret not in str(stored["raw"]), secret
    assert "http://x.test" in stored["raw"]["quoted"]


def test_redacting_a_credential_does_not_change_which_event_a_row_is():
    first = _stored({"password": "one"})
    second = _stored({"password": "two"})
    assert first["event_id"] == second["event_id"]


def test_the_uploaded_case_wins_over_a_rows_own_column():
    record = {"time": AT.isoformat(), "msg": "x", "case_id": "case-from-row"}
    assert event(record, case_id="case-from-form")[1]["case_id"] == "case-from-form"
    assert event(record)[1]["case_id"] == "case-from-row"


def test_a_connector_detection_row_takes_its_created_timestamp_as_its_time():
    row = {"detection_id": "ldt:1", "created_timestamp": AT.isoformat()}
    assert event(row)[1]["time"] == AT


def test_a_created_timestamp_alone_does_not_make_a_row_an_event():
    with pytest.raises(Dropped):
        event({"created_timestamp": AT.isoformat(), "msg": "a record, not an event"})
