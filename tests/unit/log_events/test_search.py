"""The search language, the histogram, sources and LogLM's state, on rows sent through the route."""

import json

import pytest
from sqlalchemy import text

from core.storage.unit_of_work import unit_of_work
from tests.unit.log_events import samples

pytestmark = [pytest.mark.unit, pytest.mark.database]

SEARCH = "/api/log-events/search"


@pytest.fixture
def store(client, analyst):
    samples.make_case("logs-case-9")
    rows = [
        samples.zeek_conn(samples.ago(minutes=10), loglm=0.95, case_id="logs-case-9"),
        samples.zeek_conn(
            samples.ago(minutes=20),
            uid="Cfake0002",
            loglm=0.2,
            **{"id.resp_h": "203.0.113.9"},
        ),
        samples.windows_logon(samples.ago(hours=2)),
        samples.sysmon_process(samples.ago(hours=3)),
        samples.entra_failed(samples.ago(hours=4)),
        samples.generic(samples.ago(hours=5)),
        samples.generic(
            samples.ago(days=3), message="an older svc_backup_1 note", host="app-rig-2"
        ),
    ]
    report = samples.send(client, samples.jsonl(rows)).json()
    assert report["stored"] == len(rows)
    return client


def summaries(client, q, **params):
    answer = client.get(
        SEARCH, params={"q": q, "start": samples.iso(samples.ago(days=7)), **params}
    )
    assert answer.status_code == 200, answer.text
    return answer.json()


@pytest.mark.parametrize(
    "q, sources",
    [
        ("quokkahost", {"sysmon"}),
        ('"exported the quokka"', {"rigapp-audit"}),
        ("host:wks-rig-8", {"sysmon"}),
        ("user:lee.marsh", {"entra"}),
        ("ip:192.0.2.9", {"zeek"}),
        ("port:445", {"zeek"}),
        ("port:not-a-port", set()),
        ("sev:medium", {"rigapp-audit"}),
        ("class:auth", {"winsec"}),
        ("action:logon_failed,signin_failed", {"winsec", "entra"}),
        ("source:windows", {"winsec"}),
        ("source:rigapp-audit", {"rigapp-audit"}),
        ("source:entra,sysmon", {"entra", "sysmon"}),
        ("loglm>0.9", {"zeek"}),
        ("case:logs-case-9", {"zeek"}),
        ("CORP\\sam.ridge", {"sysmon"}),
        ("svc_backup_1", {"rigapp-audit"}),
        ("mystery:word", set()),
    ],
)
def test_search_terms_find_their_sources(store, q, sources):
    assert {e["source"] for e in summaries(store, q)["events"]} == sources


def test_a_prefix_stops_on_a_dot(store):
    prefix = summaries(store, "ip:192.0.2")["events"]
    assert all(
        e["srcIp"].startswith("192.0.2.") or (e["dstIp"] or "").startswith("192.0.2.")
        for e in prefix
    )
    just_the_other = summaries(store, "ip:203.0.113")["events"]
    assert [e["dstIp"] for e in just_the_other] == ["203.0.113.9"]


def test_underscore_and_percent_are_letters(store):
    assert summaries(store, "user:%")["events"] == []
    assert summaries(store, "svc%backup")["events"] == []


def test_excluding_keeps_events_without_the_field(store):
    kept = {e["source"] for e in summaries(store, "-user:pat.quill")["events"]}
    assert "zeek" in kept and "winsec" not in kept
    assert "zeek" not in {
        e["source"] for e in summaries(store, "-source:zeek")["events"]
    }
    assert "zeek" in {
        e["source"] for e in summaries(store, "-loglm>0.9 source:zeek")["events"]
    }


def test_an_unclosed_quote_reads_as_words(store):
    assert {e["source"] for e in summaries(store, '"quokkahost')["events"]} == {
        "sysmon"
    }


def test_the_default_window_is_a_day_and_a_range_narrows_it(store):
    day = store.get(SEARCH).json()
    assert day["total"] == 6
    narrow = store.get(
        SEARCH,
        params={
            "start": samples.iso(samples.ago(hours=3, minutes=30)),
            "end": samples.iso(samples.ago(hours=2, minutes=30)),
        },
    ).json()
    assert [e["source"] for e in narrow["events"]] == ["sysmon"]


def test_bad_times_are_refused(store):
    assert store.get(SEARCH, params={"start": "whenever"}).status_code == 422
    now = samples.now()
    backwards = store.get(
        SEARCH,
        params={"start": samples.iso(now), "end": samples.iso(samples.ago(hours=1))},
    )
    assert backwards.status_code == 422


def test_results_are_newest_first_and_page(store):
    first = summaries(store, "", limit=2)
    second = summaries(store, "", limit=2, offset=2)
    assert first["total"] == 7
    times = [e["ts"] for e in first["events"] + second["events"]]
    assert times == sorted(times, reverse=True)
    assert not {e["id"] for e in first["events"]} & {e["id"] for e in second["events"]}


def test_hiding_a_source_keeps_its_count_on_the_chip(store):
    body = summaries(store, "", hide="zeek,winsec")
    assert body["by_source"]["zeek"] == 2
    assert body["by_source"]["winsec"] == 1
    assert {e["source"] for e in body["events"]} == {"sysmon", "entra", "rigapp-audit"}
    assert body["total"] == 4


def test_the_histogram_counts_shown_events_and_those_in_a_case(store):
    body = summaries(store, "", buckets=24)
    assert sum(body["histogram"]["counts"]) == body["total"] == 7
    assert sum(body["histogram"]["in_case"]) == 1
    assert len(body["histogram"]["counts"]) == 24
    hidden = summaries(store, "", buckets=24, hide="zeek")
    assert sum(hidden["histogram"]["counts"]) == 5
    assert sum(hidden["histogram"]["in_case"]) == 0


def test_fit_finds_events_outside_the_default_window(store):
    assert store.get(SEARCH, params={"q": "app-rig-2"}).json()["total"] == 0
    body = store.get(SEARCH, params={"q": "app-rig-2", "fit": True}).json()
    assert body["total"] == 1
    assert sum(body["histogram"]["counts"]) == 1
    assert body["start"] < body["events"][0]["time"] < body["end"]


def test_fit_with_no_match_is_an_empty_day(store):
    body = store.get(SEARCH, params={"q": "nothing-matches-this", "fit": True}).json()
    assert body["total"] == 0
    assert sum(body["histogram"]["counts"]) == 0


def test_terms_are_read_back(store):
    terms = store.get(SEARCH, params={"q": "host:wks -source:zeek word"}).json()[
        "terms"
    ]
    assert terms == [
        {"key": "host", "value": "wks", "negate": False},
        {"key": "source", "value": "zeek", "negate": True},
        {"key": None, "value": "word", "negate": False},
    ]


def test_an_empty_store_answers_empty(client, analyst):
    body = client.get(SEARCH).json()
    assert body["total"] == 0
    assert body["events"] == []
    assert body["by_source"] == {}
    assert body["newest"] is None
    assert client.get("/api/log-events/sources").json() == {"sources": []}


def test_sources_come_from_the_data(store):
    listed = store.get("/api/log-events/sources").json()["sources"]
    by_key = {s["source"]: s for s in listed}
    assert set(by_key) == {"zeek", "winsec", "sysmon", "entra", "rigapp-audit"}
    assert by_key["winsec"]["label"] == "Windows Security"
    assert by_key["rigapp-audit"]["label"] == "rigapp-audit"
    assert by_key["zeek"]["events"] == 2
    assert by_key["zeek"]["first"] <= by_key["zeek"]["last"]


def test_one_event_by_id(store):
    event = summaries(store, "quokkahost")["events"][0]
    assert store.get(f"/api/log-events/events/{event['id']}").json() == event
    assert store.get("/api/log-events/events/no-such-event").status_code == 404


def test_status_says_how_much_is_scored_and_that_loglm_is_not_connected(store):
    status = store.get("/api/log-events/status").json()
    assert status["total"] == 7
    assert status["scored"] == 2
    assert status["retention_days"] == 30
    assert status["loglm"] == {"configured": False, "connected": False}
    assert "Zeek" in status["shapes"]
    assert "Other" not in status["shapes"]


def test_status_follows_the_real_loglm_settings(client, analyst):
    from core.storage.config_service import get_config_service

    service = get_config_service()
    service.set_integration_config(
        "loglm", {"connectorUrl": "http://loglm.invalid"}, enabled=True
    )
    status = client.get("/api/log-events/status").json()
    assert status["loglm"] == {"configured": True, "connected": False}

    with unit_of_work() as session:
        session.execute(
            text(
                "UPDATE integration_configs SET last_test_at = now(), last_test_success = true "
                "WHERE integration_id = 'loglm'"
            )
        )
    assert client.get("/api/log-events/status").json()["loglm"]["connected"] is True


def test_the_raw_record_is_what_was_sent(store):
    event = summaries(store, "quokkahost")["events"][0]
    assert json.dumps(event["raw"], sort_keys=True).count("quokkahost.exe") == 2


@pytest.mark.parametrize(
    "value, keys",
    [
        ("a", {"a"}),
        ("win", {"win"}),
        ("wind", {"wind", "winsec"}),
        ("fire", {"fire", "paloalto"}),
        ("ad", {"ad", "winsec"}),
        ("admin", {"admin"}),
        ("firewalls", {"firewalls", "paloalto"}),
        ("winsec", {"winsec"}),
        ("someapp", {"someapp"}),
    ],
)
def test_a_source_alias_needs_four_letters_to_be_a_prefix_and_keeps_the_literal_key(
    value, keys
):
    from core.log_events.query import _source_keys

    assert set(_source_keys(value)) == keys


def test_a_short_source_search_finds_its_own_source_and_not_an_aliased_one(
    client, analyst
):
    at = samples.ago(minutes=5)
    rows = [
        samples.generic(at, source="ab", message="a"),
        samples.generic(at, source="sysmon", message="b"),
    ]
    assert samples.send(client, samples.jsonl(rows)).status_code == 200
    found = client.get(SEARCH, params={"q": "source:ab", "fit": True}).json()
    assert {e["source"] for e in found["events"]} == {"ab"}


def test_a_search_past_its_time_says_so_and_how_to_narrow_it(client, analyst):
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO log_events (event_id, time, source, summary, search_text) "
                "SELECT 'slow-' || g, now(), 'sysmon', 'x', repeat('word ', 200) "
                "FROM generate_series(1, 5000) g"
            )
        )
    from unittest.mock import patch

    with patch("core.log_events.log_events_router.SEARCH_TIMEOUT_MS", 1):
        answer = client.get(SEARCH, params={"q": "nothingmatchesthis"})
    assert answer.status_code == 504
    assert "Narrow the time range" in answer.json()["detail"]


def test_a_search_with_no_times_reads_only_the_default_window(client, analyst):
    answer = client.get(SEARCH, params={"q": "word"}).json()
    from datetime import datetime

    start = datetime.fromisoformat(answer["start"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(answer["end"].replace("Z", "+00:00"))
    assert (end - start).total_seconds() == 24 * 3600
