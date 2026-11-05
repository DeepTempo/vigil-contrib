"""Retention keeps this a bounded evidence store."""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from core.log_events.retention import cutoff, retention_days, sweep
from core.storage.unit_of_work import unit_of_work
from tests.unit.log_events import samples


def backdate(event_q: str, client, days: int) -> None:
    with unit_of_work() as session:
        session.execute(
            text(
                "UPDATE log_events SET time = time - make_interval(days => :days) "
                "WHERE search_text LIKE :word"
            ),
            {"days": days, "word": f"%{event_q}%"},
        )


@pytest.mark.unit
def test_the_default_is_thirty_days_and_the_setting_moves_it(monkeypatch):
    assert retention_days() == 30
    monkeypatch.setenv("LOG_EVENTS_RETENTION_DAYS", "7")
    assert retention_days() == 7
    now = datetime(2026, 11, 4, tzinfo=timezone.utc)
    assert cutoff(now) == now - timedelta(days=7)


@pytest.mark.unit
@pytest.mark.parametrize("value", ["0", "-1", "soon"])
def test_a_retention_that_would_not_bound_the_store_is_refused(monkeypatch, value):
    monkeypatch.setenv("LOG_EVENTS_RETENTION_DAYS", value)
    with pytest.raises(ValidationError):
        retention_days()


@pytest.mark.unit
@pytest.mark.database
def test_the_sweep_deletes_what_is_past_retention_and_keeps_the_rest(
    client, analyst, monkeypatch
):
    at = samples.ago(hours=1)
    samples.send(client, samples.jsonl([samples.zeek_conn(at), samples.dns_log(at)]))
    backdate("wombat-cdn", client, 40)

    assert sweep() == 1
    assert sweep() == 0
    assert client.get("/api/log-events/status").json()["total"] == 1

    monkeypatch.setenv("LOG_EVENTS_RETENTION_DAYS", "90")
    samples.send(client, samples.jsonl([samples.dns_log(samples.ago(days=40))]))
    assert sweep() == 0


@pytest.mark.unit
@pytest.mark.database
def test_the_route_sweeps_and_says_how_many_went(client, analyst):
    at = samples.ago(hours=1)
    samples.send(client, samples.jsonl([samples.zeek_conn(at)]))
    backdate("192.0.2.5", client, 31)
    answer = client.post("/api/log-events/retention/sweep")
    assert answer.status_code == 200
    assert answer.json() == {"deleted": 1, "retention_days": 30}


@pytest.mark.unit
@pytest.mark.database
def test_each_ingest_sweeps_too(client, analyst):
    at = samples.ago(hours=1)
    samples.send(client, samples.jsonl([samples.zeek_conn(at)]))
    backdate("192.0.2.5", client, 31)
    report = samples.send(client, samples.jsonl([samples.dns_log(at)])).json()
    assert report["swept"] == 1
    assert client.get("/api/log-events/status").json()["total"] == 1


@pytest.mark.unit
@pytest.mark.database
def test_a_shorter_retention_drops_rows_that_are_past_it(client, analyst, monkeypatch):
    monkeypatch.setenv("LOG_EVENTS_RETENTION_DAYS", "2")
    report = samples.send(
        client, samples.jsonl([samples.zeek_conn(samples.ago(days=3))])
    ).json()
    assert report["dropped"] == {"past_retention": 1}
    assert report["retention_days"] == 2
