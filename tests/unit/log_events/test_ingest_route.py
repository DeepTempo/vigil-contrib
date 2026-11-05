"""POST /api/log-events/ingest on real Postgres, read back through search."""

import json

import pytest
from sqlalchemy import text

from core.storage.unit_of_work import unit_of_work
from tests.unit.log_events import samples
from tests.unit.log_events.samples import make_case

pytestmark = [pytest.mark.unit, pytest.mark.database]

SEARCH = "/api/log-events/search"


def found(client, q=""):
    answer = client.get(SEARCH, params={"q": q, "fit": True, "limit": 500})
    assert answer.status_code == 200, answer.text
    return answer.json()["events"]


def test_jsonl_of_every_shape_is_stored_and_searchable(client, analyst):
    at = samples.ago(hours=1)
    rows = [
        samples.zeek_conn(at),
        samples.zeek_dns(at),
        samples.dns_log(at),
        samples.windows_logon(at),
        samples.winlogbeat_process(at),
        samples.sysmon_process(at),
        samples.crowdstrike_process(at),
        samples.entra_failed(at),
        samples.generic(at),
    ]
    answer = samples.send(client, samples.jsonl(rows))
    assert answer.status_code == 200, answer.text
    report = answer.json()
    assert report["rows"] == report["stored"] == len(rows)
    assert report["dropped"] == {}
    assert report["retention_days"] == 30
    assert report["shapes"]["windows_security"] == 2

    assert {e["source"] for e in found(client)} == {
        "zeek",
        "dns",
        "winsec",
        "sysmon",
        "crowdstrike",
        "entra",
        "rigapp-audit",
    }
    original = found(client, "source:entra")[0]["raw"]
    assert original == samples.entra_failed(at)


def test_a_json_array_a_wrapped_array_and_a_csv_are_read(client, analyst):
    at = samples.ago(hours=2)
    assert (
        samples.send(
            client, json.dumps([samples.dns_log(at)]).encode(), "a.json"
        ).json()["stored"]
        == 1
    )
    assert (
        samples.send(
            client,
            json.dumps({"value": [samples.entra_failed(at)]}).encode(),
            "signins.json",
        ).json()["stored"]
        == 1
    )
    assert (
        samples.send(
            client, samples.csv_bytes([samples.paloalto_csv_row(at)]), "traffic.csv"
        ).json()["stored"]
        == 1
    )
    assert {e["source"] for e in found(client)} == {"dns", "entra", "paloalto"}


def test_a_json_file_holding_one_object_a_line_is_read(client, analyst):
    at = samples.ago(hours=2)
    answer = samples.send(
        client, samples.jsonl([samples.dns_log(at), samples.zeek_dns(at)]), "lines.json"
    )
    assert answer.json()["stored"] == 2


def test_sending_a_file_twice_stores_nothing_new(client, analyst):
    at = samples.ago(hours=1)
    content = samples.jsonl([samples.zeek_conn(at), samples.dns_log(at)])
    assert samples.send(client, content).json()["stored"] == 2
    again = samples.send(client, content).json()
    assert (again["stored"], again["updated"], again["unchanged"]) == (0, 0, 2)
    assert len(found(client)) == 2


def test_the_same_row_twice_in_one_file_is_one_event(client, analyst):
    row = samples.zeek_conn(samples.ago(hours=1))
    report = samples.send(client, samples.jsonl([row, row, row])).json()
    assert (report["rows"], report["stored"], report["unchanged"]) == (3, 1, 2)
    assert len(found(client)) == 1


def test_sending_rows_again_with_scores_fills_them_in(client, analyst):
    at = samples.ago(hours=1)
    plain = samples.zeek_conn(at)
    samples.send(client, samples.jsonl([plain]))
    assert found(client)[0]["loglm"] is None

    report = samples.send(client, samples.jsonl([{**plain, "loglm": 0.91}])).json()
    assert (report["stored"], report["updated"]) == (0, 1)
    assert found(client, "loglm>0.9")[0]["loglm"] == pytest.approx(0.91)

    samples.send(client, samples.jsonl([plain]))
    assert found(client)[0]["loglm"] == pytest.approx(0.91)


def test_a_case_id_column_links_rows_and_an_unknown_case_is_noted(client, analyst):
    make_case("logs-case-1")
    at = samples.ago(hours=1)
    rows = [
        samples.zeek_conn(at, case_id="logs-case-1"),
        samples.zeek_conn(at, uid="Cfake0009", case_id="logs-case-ghost"),
    ]
    report = samples.send(client, samples.jsonl(rows)).json()
    assert report["stored"] == 2
    assert report["notes"] == {"unknown_case": 1}
    linked = found(client, "case:logs-case-1")
    assert [e["caseId"] for e in linked] == ["logs-case-1"]


def test_a_form_case_links_every_row_and_must_exist(client, analyst):
    make_case("logs-case-2")
    row = samples.dns_log(samples.ago(hours=1))
    assert (
        samples.send(
            client, samples.jsonl([row]), case_id="logs-case-ghost"
        ).status_code
        == 404
    )
    assert found(client) == []
    assert (
        samples.send(client, samples.jsonl([row]), case_id="logs-case-2").json()[
            "stored"
        ]
        == 1
    )
    assert found(client, "case:LOGS-CASE-2")[0]["caseId"] == "logs-case-2"


def test_dropped_rows_are_counted_by_reason_and_the_rest_are_stored(client, analyst):
    at = samples.ago(hours=1)
    lines = [
        json.dumps(samples.zeek_conn(at)),
        json.dumps({"message": "no clock"}),
        json.dumps({"message": "no clock either"}),
        "{broken json",
        json.dumps("a bare string"),
        json.dumps(samples.zeek_conn(samples.ago(days=45))),
        json.dumps(samples.zeek_conn(samples.ago(days=-5))),
    ]
    report = samples.send(client, "\n".join(lines).encode()).json()
    assert report["rows"] == 7
    assert report["stored"] == 1
    assert report["dropped"] == {
        "no_time": 2,
        "not_parseable": 1,
        "not_object": 1,
        "past_retention": 1,
        "future_time": 1,
    }


def test_a_broken_file_is_a_report_and_not_a_failure(client, analyst):
    report = samples.send(client, b"[1, 2,", "broken.json").json()
    assert report["stored"] == 0
    assert report["dropped"] == {"not_parseable": 1}
    assert samples.send(client, b"", "empty.csv").json()["rows"] == 0


def test_text_postgres_cannot_hold_does_not_lose_the_batch(client, analyst):
    at = samples.ago(hours=1)
    rows = [
        samples.dns_log(at),
        samples.generic(at, message="bad\x00byte", extra="\ud800", huge=float("inf")),
    ]
    report = samples.send(client, samples.jsonl(rows)).json()
    assert report["stored"] == 2


def test_a_file_of_more_than_one_batch_is_stored_whole(client, analyst):
    at = samples.ago(hours=1)
    rows = [samples.zeek_conn(at, uid=f"C{i}") for i in range(2345)]
    report = samples.send(client, samples.jsonl(rows)).json()
    assert report["stored"] == 2345
    assert client.get("/api/log-events/status").json()["total"] == 2345


def test_a_file_of_an_unknown_format_is_refused(client, analyst):
    assert samples.send(client, b"x", "events.parquet").status_code == 400
    assert samples.send(client, b"x", "events.txt", format="yaml").status_code == 400


def test_a_file_named_oddly_can_declare_its_format(client, analyst):
    row = samples.dns_log(samples.ago(hours=1))
    assert (
        samples.send(client, samples.jsonl([row]), "export.txt", format="jsonl").json()[
            "stored"
        ]
        == 1
    )


def test_a_file_over_the_cap_is_refused(client, analyst, monkeypatch):
    from core.config import get_settings

    monkeypatch.setenv("MAX_UPLOAD_SIZE_MB", "1")
    get_settings.cache_clear()
    row = json.dumps(samples.dns_log(samples.ago(hours=1)))
    content = "\n".join([row] * 12000).encode()
    assert len(content) > 1024 * 1024
    answer = samples.send(client, content)
    assert answer.status_code == 413
    assert "1MB" in answer.json()["detail"]
    assert found(client) == []


def test_reading_needs_read_and_sending_needs_write(client, reader):
    row = samples.dns_log(samples.ago(hours=1))
    assert client.get(SEARCH).status_code == 200
    assert samples.send(client, samples.jsonl([row])).status_code == 403
    assert client.post("/api/log-events/retention/sweep").status_code == 403
    assert found(client) == []


def _stored_rows():
    with unit_of_work() as session:
        return session.execute(
            text("SELECT case_id, raw::text, search_text FROM log_events")
        ).all()


def test_a_form_case_wins_over_each_rows_own_case(client, analyst):
    make_case("logs-case-form")
    make_case("logs-case-row")
    row = samples.generic(samples.ago(minutes=5), case_id="logs-case-row")
    sent = samples.send(client, samples.jsonl([row]), case_id="logs-case-form")
    assert sent.status_code == 200, sent.text
    assert _stored_rows()[0][0] == "logs-case-form"


def test_a_credential_in_an_upload_is_reported_and_not_stored(client, analyst):
    row = samples.generic(samples.ago(minutes=5), password="hunter2-value")
    sent = samples.send(client, samples.jsonl([row]))
    assert sent.json()["notes"]["credentials_redacted"] == 1
    _, raw, search = _stored_rows()[0]
    assert "hunter2-value" not in raw and "hunter2-value" not in search
    assert "[redacted]" in raw
