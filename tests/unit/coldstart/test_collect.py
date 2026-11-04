"""Paging a source by its cursor, and reading alert files."""

import json
from datetime import datetime, timedelta, timezone

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from core.coldstart.collect import alert_row, collect_history, parse_alert_file
from core.federation.contract import FetchResult

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)


def _finding(alert_id, minute=0):
    return {
        "external_id": alert_id,
        "finding_id": f"elastic-{alert_id}",
        "data_source": "elastic",
        "title": f"Alert on {alert_id}",
        "severity": "low",
        "timestamp": (T0 + timedelta(minutes=minute)).isoformat(),
        "entity_context": {"hostnames": [alert_id]},
    }


class ScriptedAdapter:
    name = "scripted"

    def __init__(self, *pages):
        self.pages = list(pages)
        self.cursors = []

    async def fetch(self, *, cursor, max_items):
        self.cursors.append(cursor)
        if not self.pages:
            return FetchResult(findings=[], cursor=cursor)
        return self.pages.pop(0)


async def _collect(adapter, **over):
    stored = []

    async def store_batch(rows):
        stored.extend(rows)

    result = await collect_history(
        adapter, start=T0 - timedelta(days=3), store_batch=store_batch, **over
    )
    return result, stored


async def test_the_seed_is_never_empty_and_is_naive_utc():
    adapter = ScriptedAdapter()
    await _collect(adapter)
    assert adapter.cursors == [{"last_poll_at": "2026-09-28T12:00:00"}]


async def test_a_boundary_alert_read_twice_is_stored_once():
    adapter = ScriptedAdapter(
        FetchResult([_finding("a"), _finding("b", 1)], {"last_poll_at": "p2"}),
        FetchResult([_finding("b", 1), _finding("c", 2)], {"last_poll_at": "p3"}),
        FetchResult([_finding("c", 2)], {"last_poll_at": "p4"}),
    )
    result, stored = await _collect(adapter)
    assert [r["alert_id"] for r in stored] == ["a", "b", "c"]
    assert result.read == 3 and not result.capped
    assert adapter.cursors[1:] == [
        {"last_poll_at": "p2"},
        {"last_poll_at": "p3"},
        {"last_poll_at": "p4"},
    ]


async def test_a_full_page_with_nothing_new_keeps_going_past_a_stuck_instant(
    monkeypatch,
):
    monkeypatch.setattr("core.coldstart.collect.BATCH_SIZE", 2)
    same_instant = [_finding("a"), _finding("b")]
    adapter = ScriptedAdapter(
        FetchResult(same_instant, {"last_poll_at": "p2"}),
        FetchResult(same_instant, {"last_poll_at": "p3"}),
        FetchResult([_finding("c", 5)], {"last_poll_at": "p4"}),
        FetchResult([], {"last_poll_at": "p5"}),
    )
    _, stored = await _collect(adapter)
    assert [r["alert_id"] for r in stored] == ["a", "b", "c"]


async def test_a_full_page_that_does_not_move_the_cursor_stops(monkeypatch):
    monkeypatch.setattr("core.coldstart.collect.BATCH_SIZE", 1)
    stuck = {"last_poll_at": "stuck"}
    adapter = ScriptedAdapter(
        FetchResult([_finding("a")], stuck),
        FetchResult([_finding("a")], stuck),
        FetchResult([_finding("never")], stuck),
    )
    _, stored = await _collect(adapter)
    assert [r["alert_id"] for r in stored] == ["a"]


async def test_the_row_cap_is_hard_and_reported():
    adapter = ScriptedAdapter(
        FetchResult([_finding(f"a{i}", i) for i in range(5)], {"last_poll_at": "p2"}),
        FetchResult([_finding("never", 9)], {"last_poll_at": "p3"}),
    )
    result, stored = await _collect(adapter, max_rows=3)
    assert len(stored) == 3 and result.read == 3
    assert result.capped
    assert len(adapter.cursors) == 1


async def test_drops_are_counted():
    no_time = {**_finding("x"), "timestamp": None}
    adapter = ScriptedAdapter(
        FetchResult([_finding("a"), no_time], {"last_poll_at": "p2"}, dropped=2),
    )
    result, stored = await _collect(adapter)
    assert len(stored) == 1
    assert dict(result.dropped) == {"unreadable": 2, "no_time": 1}


def test_an_alert_keeps_the_id_tickets_refer_to_and_loses_nul_bytes():
    row = alert_row({**_finding("wks-1"), "title": "bad\x00title on wks-1"})
    assert row["alert_id"] == "wks-1"
    assert row["title"] == "badtitle on wks-1"
    assert row["signature"] == "elastic|badtitle on <entity>"
    assert row["entities"] == ["host:wks-1"]


def _loglm_table(**over):
    columns = {
        "sequence_id": ["s1", "s2", "s3", "s4"],
        "event_start_time": [
            int((T0 + timedelta(minutes=i)).timestamp() * 1000) for i in range(3)
        ]
        + [None],
        "focal_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        "engaged_ip": ["10.9.0.1", "10.9.0.2", "10.9.0.3", "10.9.0.4"],
        "incident_pred": [1, 0, 1, 1],
        "mitre_pred": [0, 0, 1, 0],
        "confidence_score": [0.9, 0.1, 0.8, 0.7],
        "embedding": [[0.1, 0.2]] * 4,
    }
    return pa.table({**columns, **over})


def test_loglm_rows_not_predicted_incidents_are_dropped_and_counted(tmp_path):
    path = tmp_path / "flows.parquet"
    pq.write_table(_loglm_table(), path)

    parsed = parse_alert_file(path, "parquet")

    assert dict(parsed.dropped) == {"loglm_not_incident": 1, "no_time": 1}
    assert [r["source"] for r in parsed.rows] == ["loglm", "loglm"]
    first = parsed.rows[0]
    assert first["entities"] == ["ip:10.0.0.1", "ip:10.9.0.1"]
    assert first["title"].startswith("LogLM flow")
    assert first["signature"].startswith("loglm|LogLM flow")
    assert first["observed_at"] == T0
    assert parse_alert_file(path, "parquet").rows == parsed.rows, "same file, same ids"


def test_a_parquet_with_another_schema_reads_generically(tmp_path):
    path = tmp_path / "other.parquet"
    pq.write_table(
        pa.table(
            {
                "timestamp": [T0.isoformat()],
                "src_ip": ["10.0.0.1"],
                "title": ["Odd flow"],
                "severity": ["low"],
                "incident_pred": [0],
            }
        ),
        path,
    )
    parsed = parse_alert_file(path, "parquet")
    assert [r["source"] for r in parsed.rows] == ["upload"]
    assert parsed.rows[0]["title"] == "Odd flow"
    assert parsed.rows[0]["entities"] == ["ip:10.0.0.1"]


def test_json_jsonl_and_the_common_keys(tmp_path):
    finding = {
        "id": "f-1",
        "external_id": "ext-1",
        "source": "edr",
        "title": "Malware on h1",
        "severity": "HIGH",
        "timestamp": "2026-10-01T12:00:00Z",
        "description": "seen",
        "iocs": {"hostnames": ["h1"]},
    }
    as_json = tmp_path / "a.json"
    as_json.write_text(json.dumps({"findings": [finding]}))
    as_array = tmp_path / "b.json"
    as_array.write_text(json.dumps([finding]))
    as_jsonl = tmp_path / "a.jsonl"
    as_jsonl.write_text(json.dumps(finding) + "\nnot json\n" + json.dumps(5) + "\n")

    expected = {
        "alert_id": "ext-1",
        "source": "edr",
        "signature": "edr|Malware on <entity>",
        "observed_at": T0,
        "title": "Malware on h1",
        "severity": "high",
        "entities": ["host:h1"],
        "payload": {"description": "seen"},
    }
    assert parse_alert_file(as_json, "json").rows == [expected]
    assert parse_alert_file(as_array, "json").rows == [expected]
    from_jsonl = parse_alert_file(as_jsonl, "jsonl")
    assert from_jsonl.rows == [expected]
    assert dict(from_jsonl.dropped) == {"unreadable": 2}


def test_csv_keeps_the_title_and_a_row_with_no_id_is_stable_across_reads(tmp_path):
    path = tmp_path / "a.csv"
    path.write_text(
        "title,source,severity,timestamp,entity_context\n"
        'Failed login for bob,okta,low,2026-10-01T12:00:00Z,"{""usernames"": [""bob""]}"\n'
        "No time,okta,low,,\n"
    )
    parsed = parse_alert_file(path, "csv")
    assert dict(parsed.dropped) == {"no_time": 1}
    row = parsed.rows[0]
    assert row["signature"] == "okta|Failed login for <entity>"
    assert row["alert_id"] == parse_alert_file(path, "csv").rows[0]["alert_id"]


def test_a_file_that_cannot_be_read_at_all_is_a_value_error(tmp_path):
    bad_json = tmp_path / "a.json"
    bad_json.write_text("{not json")
    bad_parquet = tmp_path / "a.parquet"
    bad_parquet.write_text("not parquet")
    with pytest.raises(ValueError):
        parse_alert_file(bad_json, "json")
    with pytest.raises(ValueError):
        parse_alert_file(bad_parquet, "parquet")


async def test_a_short_repeating_batch_does_not_end_the_walk_and_lose_later_alerts():
    from datetime import datetime, timezone

    from core.coldstart.collect import collect_history
    from core.federation.contract import FetchResult

    def finding(alert_id):
        return {
            "finding_id": alert_id,
            "title": "Port sweep",
            "severity": "low",
            "data_source": "elastic",
            "timestamp": "2026-01-01T00:00:00+00:00",
        }

    class Adapter:
        name = "fake"
        pages = [
            (["a-1"], "t1"),
            (["a-1"], "t2"),
            (["a-2"], "t3"),
            ([], "t4"),
        ]

        async def fetch(self, *, cursor, max_items):
            ids, next_cursor = self.pages.pop(0)
            return FetchResult(
                findings=[finding(i) for i in ids],
                cursor={"last_poll_at": next_cursor},
            )

    stored = []

    async def store_batch(rows):
        stored.extend(row["alert_id"] for row in rows)

    await collect_history(
        Adapter(),
        start=datetime(2026, 1, 1, tzinfo=timezone.utc),
        store_batch=store_batch,
    )
    assert stored == ["a-1", "a-2"]


async def test_full_pages_of_dropped_records_do_not_end_the_walk(monkeypatch):
    monkeypatch.setattr("core.coldstart.collect.BATCH_SIZE", 2)
    pages = [FetchResult([], {"last_poll_at": f"p{i}"}, dropped=2) for i in range(5)]
    adapter = ScriptedAdapter(
        *pages,
        FetchResult([_finding("after-the-drops")], {"last_poll_at": "p9"}),
        FetchResult([], {"last_poll_at": "p10"}),
    )
    result, stored = await _collect(adapter)
    assert [r["alert_id"] for r in stored] == ["after-the-drops"]
    assert not result.capped


async def test_a_walk_that_hits_the_read_budget_says_it_is_incomplete(monkeypatch):
    monkeypatch.setattr("core.coldstart.collect.BATCH_SIZE", 2)
    monkeypatch.setattr("core.coldstart.collect.MAX_READS", 3)
    adapter = ScriptedAdapter(
        *[FetchResult([], {"last_poll_at": f"p{i}"}, dropped=2) for i in range(9)]
    )
    result, _ = await _collect(adapter)
    assert result.capped


def test_a_file_using_one_id_for_two_sources_is_refused_and_a_repeat_is_not(tmp_path):
    path = tmp_path / "alerts.jsonl"
    row = {
        "external_id": "17",
        "title": "Port scan",
        "severity": "low",
        "timestamp": "2026-01-01T00:00:00Z",
    }
    path.write_text("\n".join(json.dumps({**row, "source": "ids"}) for _ in range(2)))
    assert [r["source"] for r in parse_alert_file(path, "jsonl").rows] == ["ids"]

    path.write_text(
        "\n".join(json.dumps({**row, "source": src}) for src in ("ids", "edr"))
    )
    with pytest.raises(ValueError, match="17"):
        parse_alert_file(path, "jsonl")
