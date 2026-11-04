"""A run through its API, the real adapter and Postgres. Only the model is scripted."""

import csv
import io
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import text

from core.coldstart import active, store
from core.coldstart.baseline import parse_time
from core.coldstart.collect import alert_row, collect_history
from core.coldstart.sample_history import FIXTURE, load_fixture
from core.federation import store as federation_store
from core.federation.registry import get_adapter
from core.integrations.credential_check import check_credentials
from core.llm.router.router import ProviderSpec
from core.storage.config_service import get_config_service
from core.storage.unit_of_work import unit_of_work
from scripts.coldstart.fake_elastic import make_server
from services.daemon.config import ProcessingConfig
from services.daemon.processor import FindingProcessor

pytestmark = [
    pytest.mark.unit,
    pytest.mark.database,
    pytest.mark.skipif(
        not FIXTURE.exists(), reason="needs scripts/coldstart/build_sample.py's fixture"
    ),
]

BASE = "/api/cold-start"
GOOD_REPLY = (
    "SEVERITY: low\nCONFIDENCE: 0.6\nCATEGORY: other\n"
    "RECOMMENDED_ACTION: monitor\nREASONING: Fits the history."
)
NOW = datetime.now(timezone.utc)


def _sql(statement, **params):
    with unit_of_work() as session:
        result = session.execute(text(statement), params)
        return result.all() if result.returns_rows else None


def _wait(client, run_id, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"{BASE}/runs/{run_id}").json()
        if not run["running"]:
            return run
        time.sleep(0.05)
    raise AssertionError(f"run still working: {run}")


def _go_live(client, run_id):
    """Sample history may not go live, so the run holds it as a customer upload."""
    _sql("UPDATE cold_start_runs SET source = 'upload' WHERE run_id = :r", r=run_id)
    return client.post(f"{BASE}/runs/{run_id}/go-live")


def _start(client, **body):
    response = client.post(f"{BASE}/runs", json=body)
    assert response.status_code == 202, response.text
    return response.json()["id"]


def _sample_run(client, reply=GOOD_REPLY, **body):
    complete = AsyncMock(return_value=reply)
    with patch("core.coldstart.runner.oneshot.complete", complete):
        run_id = _start(client, source="sample", **{"history_days": 90, **body})
        run = _wait(client, run_id)
    assert run["status"] == "ready", run
    return run, complete


def _upload(client, run_id, kind, name, content):
    return client.post(f"{BASE}/runs/{run_id}/{kind}", files={"file": (name, content)})


def _jsonl(rows):
    return "\n".join(json.dumps(r) for r in rows).encode()


@pytest.fixture
def fake_elastic(db):
    server = make_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    get_config_service().set_integration_config(
        "elastic-siem",
        {"elasticsearch_url": url, "kibana_url": url, "verify_ssl": False},
        enabled=True,
    )
    yield url
    server.shutdown()
    server.server_close()


def _fixture_ids_since(cutoff):
    alerts = load_fixture()["alerts"]
    newest = max(parse_time(a["timestamp"]) for a in alerts)
    return {
        a["external_id"]
        for a in alerts
        if parse_time(a["timestamp"]) >= newest - cutoff
    }


async def test_the_real_elastic_adapter_reads_the_double_and_passes_its_credential_check(
    fake_elastic,
):
    ok, message = await check_credentials("elastic-siem")
    assert ok, message
    assert "fake-elastic-test-double" in message

    adapter = get_adapter("elastic")
    assert adapter.is_configured()
    days = timedelta(days=40)
    stored = []

    async def store_batch(rows):
        stored.extend(rows)

    server_newest = datetime.now(timezone.utc) - timedelta(minutes=2)
    result = await collect_history(
        adapter,
        start=server_newest - days + timedelta(minutes=1),
        store_batch=store_batch,
    )
    ids = [row["alert_id"] for row in stored]
    assert len(ids) == len(set(ids)) == result.read
    assert set(ids) == _fixture_ids_since(days), "every alert in the window, none twice"
    assert len(ids) > 500, "more than one page"
    assert {row["source"] for row in stored} == {"elastic"}
    assert not result.capped


def test_an_elastic_run_through_the_api_reads_the_double_and_writes_no_findings(
    client, analyst, fake_elastic
):
    complete = AsyncMock(return_value=GOOD_REPLY)
    with patch("core.coldstart.runner.oneshot.complete", complete):
        run_id = _start(client, source="elastic", history_days=30, review_days=7)
        run = _wait(client, run_id)
    assert run["status"] == "ready", run
    assert run["counts"]["alerts_read"] == len(_fixture_ids_since(timedelta(days=37)))
    assert run["counts"]["review_alerts"] > 0
    assert _sql("SELECT count(*) FROM findings")[0][0] == 0


def test_a_source_that_fails_fails_the_run_and_records_why(client, analyst, db):
    get_config_service().set_integration_config(
        "elastic-siem",
        {"elasticsearch_url": "http://127.0.0.1:1", "kibana_url": "http://127.0.0.1:1"},
        enabled=True,
    )
    run = _wait(client, _start(client, source="elastic"))
    assert run["status"] == "failed"
    assert "Elastic" in run["error"]
    assert client.post(f"{BASE}/runs", json={"source": "sample"}).status_code == 202


def test_an_unconfigured_or_unknown_source_is_refused(client, analyst):
    assert client.post(f"{BASE}/runs", json={"source": "nope"}).status_code == 400
    assert client.post(f"{BASE}/runs", json={"source": "elastic"}).status_code == 400


def test_no_model_skips_judging_and_goes_to_ready(client, analyst):
    with patch("core.coldstart.runner.resolve_dispatch", return_value=None):
        run_id = _start(client, source="sample", history_days=90)
        run = _wait(client, run_id)

    assert run["status"] == "ready"
    assert run["judging_skipped"] == "no model"
    counts = run["counts"]
    assert counts["judged"] == 0 and counts["abstained"] > 0
    assert counts["tickets_kept"] == 1852
    assert counts["tickets_dropped"] == {
        "bulk_close": 86,
        "duplicate": 76,
        "undetermined": 147,
    }
    assert counts["alerts_read"] == 2293
    assert counts["days_covered"] > 80
    assert counts["kinds"] > 10
    assert counts["average_model_seconds"] is None
    assert counts["review_alerts"] == (
        counts["dismiss_candidates"] + counts["escalations"] + counts["abstained"]
    )
    assert counts["review_alerts"] == len(_fixture_ids_since(timedelta(days=7)))
    assert run["as_of"] is not None and run["review_days"] == 7
    assert _sql("SELECT count(*) FROM findings")[0][0] == 0
    assert _sql("SELECT count(*) FROM case_closure_info")[0][0] == 0


def test_judging_takes_at_most_three_of_a_kind_up_to_the_limit(client, analyst):
    run, complete = _sample_run(client, judge_limit=40)
    judged = _sql(
        "SELECT signature, count(*) FROM cold_start_alerts "
        "WHERE run_id = :r AND llm IS NOT NULL GROUP BY 1",
        r=run["id"],
    )
    assert sum(n for _, n in judged) == complete.await_count == run["counts"]["judged"]
    assert run["counts"]["judged"] <= 40
    assert all(n <= 3 for _, n in judged)
    assert len(judged) == min(
        40,
        _sql(
            "SELECT count(DISTINCT signature) FROM cold_start_alerts "
            "WHERE run_id = :r AND in_review_window AND stage1 = 'abstain'",
            r=run["id"],
        )[0][0],
    ), "every kind before any kind's second"
    outside = _sql(
        "SELECT count(*) FROM cold_start_alerts WHERE run_id = :r AND llm IS NOT NULL "
        "AND (NOT in_review_window OR stage1 <> 'abstain')",
        r=run["id"],
    )[0][0]
    assert outside == 0

    llm = _sql(
        "SELECT llm FROM cold_start_alerts WHERE run_id = :r AND llm IS NOT NULL LIMIT 1",
        r=run["id"],
    )[0][0]
    assert llm["verdict"] == "monitor" and llm["parsed"] is True
    assert llm["confidence"] == 0.6 and llm["reasoning"] == "Fits the history."
    assert isinstance(llm["latency_ms"], int) and "model" in llm
    assert run["counts"]["average_model_seconds"] is not None
    assert complete.await_args.kwargs["component"] == "triage"
    prompt = complete.await_args.kwargs["message"]
    assert "<history>" not in prompt and "<alert_data>" in prompt


def test_the_prompt_gets_the_alert_description(client, analyst):
    _, complete = _sample_run(client, judge_limit=5)
    assert "Description: \n" not in complete.await_args.kwargs["message"]


def test_judging_reaches_the_assigned_provider_through_the_real_oneshot(
    client, analyst
):
    provider = ProviderSpec(
        provider_id="ollama-local",
        provider_type="ollama",
        base_url="http://127.0.0.1:11434",
        api_key_ref=None,
        default_model="nemotron",
        config={},
    )
    dispatch = AsyncMock(return_value={"content": GOOD_REPLY})
    with (
        patch("core.llm.target.resolve_dispatch", return_value=(provider, "nemotron")),
        patch(
            "core.coldstart.runner.resolve_dispatch",
            return_value=(provider, "nemotron"),
        ),
        patch("core.llm.target.resolve_effort", return_value=None),
        patch("core.llm.router.router.LLMRouter.dispatch", dispatch),
    ):
        run_id = _start(client, source="sample", judge_limit=2)
        run = _wait(client, run_id)
    assert run["status"] == "ready" and run["judging_skipped"] is None
    assert dispatch.await_count == run["counts"]["judged"] == 2
    kwargs = dispatch.await_args.kwargs
    assert kwargs["provider"] is provider and kwargs["model"] == "nemotron"
    assert "<history>" not in kwargs["messages"][-1]["content"]
    llm = _sql(
        "SELECT llm FROM cold_start_alerts WHERE run_id = :r AND llm IS NOT NULL LIMIT 1",
        r=run_id,
    )[0][0]
    assert llm["model"] == "ollama-local/nemotron" and llm["verdict"] == "monitor"


def test_an_unparsed_reply_is_recorded_and_is_never_a_verdict(client, analyst):
    run, _ = _sample_run(client, reply="I would rather not say.", judge_limit=5)
    assert run["counts"]["judged"] == 5 and run["counts"]["unparsed"] == 5
    rows = _sql(
        "SELECT llm FROM cold_start_alerts WHERE run_id = :r AND llm IS NOT NULL",
        r=run["id"],
    )
    assert all(r[0]["parsed"] is False and r[0]["verdict"] is None for r in rows)
    groups = client.get(f"{BASE}/runs/{run['id']}/groups").json()["groups"]
    assert all(g["llm"]["verdicts"] == {} for g in groups)
    assert sum(g["llm"]["unparsed"] for g in groups) == 5
    assert all(g["llm"]["example_reasoning"] is None for g in groups)


def test_a_failing_model_stops_and_a_resume_skips_what_is_judged(client, analyst):
    calls = {"n": 0}

    async def dies_after_two(**_):
        calls["n"] += 1
        if calls["n"] > 2:
            raise RuntimeError("provider down")
        return GOOD_REPLY

    with patch("core.coldstart.runner.oneshot.complete", dies_after_two):
        run_id = _start(client, source="sample", judge_limit=10)
        run = _wait(client, run_id)
    assert run["status"] == "ready"
    assert run["judging_skipped"] == "model failing: RuntimeError"
    assert run["counts"]["judged"] == 2
    judged = {
        r[0]
        for r in _sql(
            "SELECT alert_id FROM cold_start_alerts WHERE run_id = :r AND llm IS NOT NULL",
            r=run_id,
        )
    }

    asked = []

    async def records(*, message, **_):
        asked.append(message)
        return GOOD_REPLY

    with patch("core.coldstart.runner.oneshot.complete", records):
        assert client.post(f"{BASE}/runs/{run_id}/judge").status_code == 200
        run = _wait(client, run_id)
    assert run["status"] == "ready" and run["judging_skipped"] is None
    assert run["counts"]["judged"] == 10
    assert len(asked) == 8, "only the eight not yet judged"
    still = {
        r[0]
        for r in _sql(
            "SELECT alert_id FROM cold_start_alerts WHERE run_id = :r "
            "AND llm->>'verdict' = 'monitor'",
            r=run_id,
        )
    }
    assert judged <= still


def test_a_run_whose_process_died_judging_resumes(client, analyst):
    run, complete = _sample_run(client, judge_limit=6)
    # What a killed process leaves: still judging, three results lost, no lease held.
    _sql("UPDATE cold_start_runs SET status = 'judging' WHERE run_id = :r", r=run["id"])
    victims = _sql(
        "SELECT alert_id FROM cold_start_alerts WHERE run_id = :r AND llm IS NOT NULL LIMIT 3",
        r=run["id"],
    )
    for (alert_id,) in victims:
        _sql(
            "UPDATE cold_start_alerts SET llm = NULL WHERE run_id = :r AND alert_id = :a",
            r=run["id"],
            a=alert_id,
        )
    stalled = client.get(f"{BASE}/runs/{run['id']}").json()
    assert stalled["resumable"] is True and stalled["running"] is False

    again = AsyncMock(return_value=GOOD_REPLY)
    with patch("core.coldstart.runner.oneshot.complete", again):
        assert client.post(f"{BASE}/runs/{run['id']}/judge").status_code == 200
        resumed = _wait(client, run["id"])
    assert again.await_count == 3
    assert resumed["status"] == "ready" and resumed["counts"]["judged"] == 6


def test_a_run_whose_process_died_collecting_resumes(client, analyst):
    run_id = store.create_run(
        source="sample",
        history_days=90,
        review_days=7,
        judge_limit=0,
        created_by="someone",
    )
    assert client.post(f"{BASE}/runs", json={"source": "sample"}).status_code == 409
    assert client.post(f"{BASE}/runs/{run_id}/judge").status_code == 200
    run = _wait(client, run_id)
    assert run["status"] == "ready" and run["counts"]["alerts_read"] == 2293


def test_judge_is_refused_while_another_worker_holds_the_lease(client, analyst):
    run, _ = _sample_run(client, judge_limit=0)
    _sql("UPDATE cold_start_runs SET status = 'judging' WHERE run_id = :r", r=run["id"])
    lease = store.WorkerLease.acquire()
    try:
        assert client.post(f"{BASE}/runs/{run['id']}/judge").status_code == 409
        held = client.get(f"{BASE}/runs/{run['id']}").json()
        assert held["running"] is True and held["resumable"] is False
    finally:
        lease.release()
    assert client.get(f"{BASE}/runs/{run['id']}").json()["running"] is False


def test_only_one_active_run_with_409(client, analyst):
    run_id = _start(client, source="upload")
    assert (
        _upload(
            client,
            run_id,
            "alerts",
            "a.jsonl",
            _jsonl(load_fixture()["alerts"][:20]),
        ).status_code
        == 200
    )
    response = client.post(f"{BASE}/runs", json={"source": "sample"})
    assert response.status_code == 409
    assert _sql("SELECT count(*) FROM cold_start_runs")[0][0] == 1


def test_an_upload_run_that_received_nothing_gives_way(client, analyst):
    abandoned = _start(client, source="upload")
    assert client.post(f"{BASE}/runs/{abandoned}/rebuild").status_code == 409
    assert client.post(f"{BASE}/runs/{abandoned}/judge").status_code == 409
    replacement = _start(client, source="upload")
    assert client.get(f"{BASE}/runs/{abandoned}").json()["status"] == "failed"
    assert client.get(f"{BASE}/runs/{replacement}").json()["status"] == "collecting"


def _tickets_for(alerts, disposition):
    return [
        {
            "ticket_id": f"t-{a['external_id']}",
            "alert_refs": [{"external_id": a["external_id"]}],
            "disposition": disposition,
            "closed_at": a["timestamp"],
        }
        for a in alerts
    ]


def _recent_alerts(count):
    """A kind of alert with clean history before the window and two inside it."""
    newest = NOW
    return [
        {
            "external_id": f"a{i}",
            "source": "edr",
            "title": "Malware quarantined on wks-1",
            "severity": "low",
            "timestamp": (newest - timedelta(days=i)).isoformat(),
            "description": "seen",
            "iocs": {"hostnames": ["wks-1"]},
        }
        for i in range(count)
    ]


def test_upload_flow_rebuild_starts_it_and_reuploads_change_no_counts(client, analyst):
    alerts = _recent_alerts(10)
    run_id = _start(client, source="upload", judge_limit=2)
    assert client.get(f"{BASE}/runs/{run_id}").json()["review_days"] == 1

    assert _upload(client, run_id, "alerts", "x.txt", b"").status_code == 400
    bad = _upload(client, run_id, "alerts", "a.json", b"{not json")
    assert bad.status_code == 400

    first = _upload(
        client,
        run_id,
        "alerts",
        "a.jsonl",
        _jsonl(alerts) + b"\n" + json.dumps({"title": "no time"}).encode(),
    )
    assert first.status_code == 200
    assert first.json() == {"kept": 10, "dropped": {"no_time": 1}}

    rows = _tickets_for(alerts[2:], "FP")
    body = io.StringIO()
    writer = csv.DictWriter(body, ["alert_id", "disposition", "closed_at", "closed_by"])
    writer.writeheader()
    for row in rows:
        writer.writerow(
            {
                "alert_id": row["alert_refs"][0]["external_id"],
                "disposition": row["disposition"],
                "closed_at": row["closed_at"],
                "closed_by": "pat",
            }
        )
    writer.writerow(
        {"alert_id": "a9", "disposition": "Won't Fix", "closed_at": row["closed_at"]}
    )
    content = body.getvalue().encode()
    kept = _upload(client, run_id, "tickets", "t.csv", content).json()
    assert kept == {"kept": 8, "dropped": {"unmapped_disposition": 1}}
    assert _upload(client, run_id, "tickets", "t.csv", content).json() == kept

    with patch(
        "core.coldstart.runner.oneshot.complete",
        AsyncMock(return_value=GOOD_REPLY),
    ):
        assert client.post(f"{BASE}/runs/{run_id}/rebuild").status_code == 200
        run = _wait(client, run_id)
    assert run["status"] == "ready"
    counts = run["counts"]
    assert counts["alerts_read"] == 10 and counts["alerts_dropped"] == {"no_time": 1}
    assert counts["tickets_kept"] == 8
    assert counts["tickets_dropped"] == {"unmapped_disposition": 1}
    assert counts["review_alerts"] == 2


def test_groups_shape_review_and_rebuild_keep_what_people_and_the_model_said(
    client, analyst
):
    run, _ = _sample_run(client, judge_limit=30)
    run_id = run["id"]
    groups = client.get(f"{BASE}/runs/{run_id}/groups").json()["groups"]
    assert sum(g["count"] for g in groups) == run["counts"]["review_alerts"]
    assert [g["count"] for g in groups] == sorted(
        (g["count"] for g in groups), reverse=True
    )
    target = next(g for g in groups if g["llm"]["judged"])
    assert len(target["key"]) == 16
    assert set(target) == {
        "key",
        "label",
        "source",
        "count",
        "stage1",
        "top_rule",
        "reasons",
        "sample",
        "llm",
        "review",
        "tickets",
        "miss_bound",
    }
    assert target["label"] and not target["label"].startswith(target["source"])
    assert sum(target["stage1"].values()) == target["count"]
    assert target["reasons"] and target["top_rule"]
    assert target["sample"]["description"]
    assert target["llm"]["verdicts"]["monitor"] == target["llm"]["judged"]
    assert target["llm"]["example_reasoning"] == "Fits the history."
    assert target["review"] == {
        "agree": 0,
        "not_benign": 0,
        "pending": target["count"],
    }
    clean = next(
        g for g in groups if g["tickets"]["benign"] and not g["tickets"]["real"]
    )
    assert 0 < clean["miss_bound"] < 1
    dirty = next(g for g in groups if g["tickets"]["real"])
    assert dirty["miss_bound"] is None

    url = f"{BASE}/runs/{run_id}/groups/{target['key']}/review"
    assert client.post(url, json={"verdict": "maybe"}).status_code == 422
    first = client.post(url, json={"verdict": "agree"})
    assert first.status_code == 200
    reviewed = next(g for g in first.json()["groups"] if g["key"] == target["key"])
    assert reviewed["review"]["agree"] == target["count"]
    stamp = _sql(
        "SELECT DISTINCT reviewed_by, reviewed_at FROM cold_start_alerts "
        "WHERE run_id = :r AND review = 'agree'",
        r=run_id,
    )
    assert len(stamp) == 1 and stamp[0][0] == "cs-admin"

    assert client.post(url, json={"verdict": "agree"}).json() == first.json()
    assert (
        _sql(
            "SELECT DISTINCT reviewed_by, reviewed_at FROM cold_start_alerts "
            "WHERE run_id = :r AND review = 'agree'",
            r=run_id,
        )
        == stamp
    ), "a repeat changes nothing"

    missing = f"{BASE}/runs/{run_id}/groups/nosuchkey/review"
    assert client.post(missing, json={"verdict": "agree"}).status_code == 404

    llm_before = _sql(
        "SELECT alert_id, llm FROM cold_start_alerts WHERE run_id = :r AND llm IS NOT NULL "
        "ORDER BY alert_id",
        r=run_id,
    )
    stage_before = _sql(
        "SELECT signature, count(*) FROM cold_start_alerts "
        "WHERE run_id = :r AND in_review_window AND stage1 = 'dismiss_candidate' GROUP BY 1",
        r=run_id,
    )
    assert client.post(f"{BASE}/runs/{run_id}/rebuild").status_code == 200

    after = client.get(f"{BASE}/runs/{run_id}/groups").json()["groups"]
    assert next(g for g in after if g["key"] == target["key"])["review"]["agree"] == (
        target["count"]
    )
    assert llm_before == _sql(
        "SELECT alert_id, llm FROM cold_start_alerts WHERE run_id = :r AND llm IS NOT NULL "
        "ORDER BY alert_id",
        r=run_id,
    )
    assert stage_before == _sql(
        "SELECT signature, count(*) FROM cold_start_alerts "
        "WHERE run_id = :r AND in_review_window AND stage1 = 'dismiss_candidate' GROUP BY 1",
        r=run_id,
    ), "the same inputs build the same assessments"


def test_a_ticket_uploaded_after_the_run_changes_the_baseline_on_rebuild(
    client, analyst
):
    run, _ = _sample_run(client, judge_limit=0)
    run_id = run["id"]
    target = client.get(f"{BASE}/runs/{run_id}/groups").json()["groups"][0]
    alert_id = target["sample"]["alert_id"]
    as_of = parse_time(run["as_of"])
    history = _sql(
        "SELECT alert_id FROM cold_start_alerts WHERE run_id = :r AND signature = "
        "(SELECT signature FROM cold_start_alerts WHERE run_id = :r AND alert_id = :a) "
        "AND NOT in_review_window LIMIT 1",
        r=run_id,
        a=alert_id,
    )
    assert history, "the kind has history"
    real_before = target["tickets"]["real"]
    closed = (as_of - timedelta(hours=1)).isoformat()
    response = _upload(
        client,
        run_id,
        "tickets",
        "t.jsonl",
        _jsonl(
            [
                {
                    "ticket_id": "new-real",
                    "alert_refs": [{"external_id": history[0][0]}],
                    "disposition": "True Positive",
                    "closed_at": closed,
                }
            ]
        ),
    )
    assert response.json() == {"kept": 1, "dropped": {}}
    assert client.post(f"{BASE}/runs/{run_id}/rebuild").status_code == 200
    after = client.get(f"{BASE}/runs/{run_id}/groups").json()["groups"]
    assert next(g for g in after if g["key"] == target["key"])["tickets"]["real"] == (
        real_before + 1
    )


def test_go_live_keeps_one_live_run_and_the_seam_reads_it(client, analyst):
    first, _ = _sample_run(client, judge_limit=0)
    assert _go_live(client, first["id"]).status_code == 200
    assert client.get(f"{BASE}/runs/{first['id']}").json()["status"] == "live"
    assert client.get(f"{BASE}/runs/{first['id']}").json()["live_at"]

    second, _ = _sample_run(client, judge_limit=0)
    assert _go_live(client, second["id"]).status_code == 200
    assert client.post(f"{BASE}/runs/{second['id']}/go-live").status_code == 200

    statuses = {r[0]: r[1] for r in _sql("SELECT run_id, status FROM cold_start_runs")}
    assert statuses == {first["id"]: "ready", second["id"]: "live"}
    assert _sql(
        "SELECT live_at IS NULL FROM cold_start_runs WHERE run_id = :r", r=first["id"]
    )[0][0]

    active.forget()
    live = active.live_baseline()
    assert live is not None and live.signatures
    assert live.as_of == parse_time(
        client.get(f"{BASE}/runs/{second['id']}").json()["as_of"]
    )


async def test_a_new_alert_gets_the_live_baseline_in_triage(client, analyst):
    run, _ = _sample_run(client, judge_limit=0)
    source, title, severity, entities = _sql(
        "SELECT source, title, severity, entities FROM cold_start_alerts "
        "WHERE run_id = :r AND rule = 'clean_on_these_entities' LIMIT 1",
        r=run["id"],
    )[0]
    assert _go_live(client, run["id"]).status_code == 200

    active.forget()
    keys = {"user": "usernames", "ip": "src_ips", "host": "hostnames"}
    context = {}
    for entity in entities:
        kind, value = entity.split(":", 1)
        context.setdefault(keys[kind], []).append(value)
    finding = {
        "finding_id": "f-new",
        "data_source": source,
        "title": title,
        "severity": severity,
        "description": "new",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "entity_context": context,
    }
    processor = FindingProcessor(ProcessingConfig())
    get_triage = AsyncMock(return_value=(GOOD_REPLY, None))
    with patch.object(FindingProcessor, "_get_ai_triage", get_triage):
        result = await processor._triage_finding(finding)
    prompt = get_triage.await_args.args[0]
    assert "<history>" not in prompt and "This kind of alert fired" not in prompt
    assert result["ai_triage"]["baseline"]["rule"] == "clean_on_these_entities"
    assert result["ai_triage"]["baseline"]["stage1"] == "dismiss_candidate"
    assert (
        result["recommended_action"] == "monitor"
    ), "the model's answer, not the rule's"


def test_a_run_not_yet_ready_cannot_go_live(client, analyst):
    run_id = _start(client, source="upload")
    assert client.post(f"{BASE}/runs/{run_id}/go-live").status_code == 409
    assert client.get(f"{BASE}/runs/{run_id}").json()["status"] == "collecting"
    active.forget()
    assert active.live_baseline() is None


def test_going_live_enables_the_source_from_now_and_a_repeat_keeps_its_cursor(
    client, analyst, fake_elastic
):
    with patch(
        "core.coldstart.runner.oneshot.complete", AsyncMock(return_value=GOOD_REPLY)
    ):
        run_id = _start(client, source="elastic", judge_limit=0)
        run = _wait(client, run_id)
    assert run["status"] == "ready"
    assert not (federation_store.read_source("elastic") or {}).get("enabled")

    before = datetime.now(timezone.utc).replace(tzinfo=None)
    assert client.post(f"{BASE}/runs/{run_id}/go-live").status_code == 200
    row = federation_store.read_source("elastic")
    assert row["enabled"] is True
    cursor = datetime.fromisoformat(row["cursor"]["last_poll_at"])
    assert before <= cursor <= datetime.now(timezone.utc).replace(tzinfo=None)
    assert federation_store.is_globally_enabled()

    assert client.post(f"{BASE}/runs/{run_id}/go-live").status_code == 200
    assert federation_store.read_source("elastic")["cursor"] == row["cursor"]


def test_a_source_already_polling_keeps_its_cursor_when_a_run_goes_live(
    client, analyst, fake_elastic
):
    federation_store.upsert_source("elastic", {"interval_seconds": 300})
    behind = {"last_poll_at": "2026-01-01T00:00:00"}
    federation_store.update_source("elastic", {"enabled": True, "cursor": behind})
    with patch(
        "core.coldstart.runner.oneshot.complete", AsyncMock(return_value=GOOD_REPLY)
    ):
        run_id = _start(client, source="elastic", judge_limit=0)
        _wait(client, run_id)
    assert client.post(f"{BASE}/runs/{run_id}/go-live").status_code == 200
    assert federation_store.read_source("elastic")["cursor"] == behind


def test_sources_lists_what_can_run(client, analyst, fake_elastic):
    with patch("services.api.routers.cold_start.resolve_dispatch", return_value=None):
        body = client.get(f"{BASE}/sources").json()
    by_id = {s["id"]: s for s in body["sources"]}
    assert by_id["elastic"] == {
        "id": "elastic",
        "label": "Elastic, or a Wazuh indexer",
        "kind": "federation",
        "configured": True,
    }
    assert by_id["splunk"]["configured"] is False
    assert by_id["sample"]["configured"] and by_id["upload"]["kind"] == "upload"
    assert body["model"] is None
    assert body["loglm"] == {"configured": False, "connected": False}


def test_two_uploads_racing_with_one_id_cannot_both_be_kept(client, analyst):
    run_id = _start(client, source="upload")
    for round_number in range(20):
        ids = [f"{round_number}-{i}" for i in range(5)]
        files = [
            [alert_row(_upload_alert(i, "Port scan", source=src)) for i in ids]
            for src in ("ids", "edr")
        ]
        barrier = threading.Barrier(2)
        accepted = []

        def upload(rows):
            barrier.wait()
            try:
                store.insert_uploaded_alerts(run_id, rows)
                accepted.append(rows[0]["source"])
            except ValueError:
                pass

        threads = [threading.Thread(target=upload, args=(f,)) for f in files]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(accepted) == 1, f"round {round_number} accepted {accepted}"


def _upload_alert(alert_id, title, source="ids"):
    return {
        "external_id": alert_id,
        "title": title,
        "severity": "low",
        "source": source,
        "timestamp": (NOW - timedelta(hours=1)).isoformat(),
    }


def test_judge_on_a_ready_run_takes_in_what_was_uploaded_since(client, analyst):
    run_id = _start(client, source="upload")
    first = _jsonl([_upload_alert("first", "First kind of alert")])
    assert _upload(client, run_id, "alerts", "a.jsonl", first).status_code == 200
    asked = []

    async def records(*, message, **_):
        asked.append(message)
        return GOOD_REPLY

    with patch("core.coldstart.runner.oneshot.complete", records):
        assert client.post(f"{BASE}/runs/{run_id}/judge").status_code == 200
        assert _wait(client, run_id)["status"] == "ready"
        later = _jsonl([_upload_alert("later", "Later kind of alert")])
        assert _upload(client, run_id, "alerts", "b.jsonl", later).status_code == 200
        assert client.post(f"{BASE}/runs/{run_id}/judge").status_code == 200
        assert _wait(client, run_id)["status"] == "ready"

    assert len(asked) == 2 and "Later kind of alert" in asked[1]
    window = _sql(
        "SELECT in_review_window FROM cold_start_alerts WHERE alert_id = 'later'"
    )
    assert window[0][0] is True


def test_an_upload_reusing_an_id_from_another_source_is_refused(client, analyst):
    run_id = _start(client, source="upload")
    ids = _jsonl([_upload_alert("17", "Port scan", source="ids")])
    edr = _jsonl([_upload_alert("17", "Port scan", source="edr")])
    assert _upload(client, run_id, "alerts", "a.jsonl", ids).status_code == 200
    assert _upload(client, run_id, "alerts", "a.jsonl", ids).status_code == 200

    refused = _upload(client, run_id, "alerts", "b.jsonl", edr)

    assert refused.status_code == 400 and "17" in refused.json()["detail"]
    held = _sql("SELECT source FROM cold_start_alerts WHERE run_id = :r", r=run_id)
    assert [row[0] for row in held] == ["ids"]


def test_sample_without_its_fixture_is_not_offered_and_cannot_start(client, analyst):
    with patch(
        "services.api.routers.cold_start.FIXTURE", Path("/nonexistent/sample.json.gz")
    ):
        sources = client.get(f"{BASE}/sources").json()["sources"]
        response = client.post(f"{BASE}/runs", json={"source": "sample"})
    assert {s["id"]: s for s in sources}["sample"]["configured"] is False
    assert response.status_code == 400
    assert client.get(f"{BASE}/runs/latest").status_code == 404


def test_sources_reads_loglm_as_the_settings_card_does(client, analyst):
    service = get_config_service()
    service.set_integration_config(
        "loglm", {"connectorUrl": "http://127.0.0.1:1"}, enabled=True
    )
    body = client.get(f"{BASE}/sources").json()
    assert body["loglm"] == {"configured": True, "connected": False}

    service.record_integration_test(
        "loglm", success=True, error=None, tested_at=NOW.replace(tzinfo=None)
    )
    body = client.get(f"{BASE}/sources").json()
    assert body["loglm"] == {"configured": True, "connected": True}


def test_sources_reports_the_assigned_model(client, analyst):
    class Provider:
        provider_type = "ollama"

    with patch(
        "services.api.routers.cold_start.resolve_dispatch",
        return_value=(Provider(), "nemotron"),
    ):
        body = client.get(f"{BASE}/sources").json()
    assert body["model"] == {"provider": "ollama", "model": "nemotron"}


def test_latest_and_missing_runs(client, analyst):
    assert client.get(f"{BASE}/runs/latest").status_code == 404
    assert client.get(f"{BASE}/runs/nope").status_code == 404
    assert client.post(f"{BASE}/runs/nope/judge").status_code == 404
    run_id = _start(client, source="upload")
    assert client.get(f"{BASE}/runs/latest").json()["id"] == run_id


def test_a_viewer_can_read_but_not_write(client, analyst):
    from core.storage.models import User
    from services.api.middleware.auth import get_current_active_user, get_current_user

    _sql(
        "INSERT INTO principals (principal_id, kind, label) "
        "VALUES ('person:cs-viewer', 'person', 'cs-viewer') ON CONFLICT DO NOTHING"
    )
    _sql(
        "INSERT INTO users (user_id, username, email, password_hash, full_name, role_id, "
        "is_active, mfa_enabled, principal_id) VALUES ('cs-viewer', 'cs-viewer', "
        "'v@test.local', '', 'V', 'role-viewer', true, false, 'person:cs-viewer') "
        "ON CONFLICT (user_id) DO NOTHING"
    )
    viewer = User(
        user_id="cs-viewer",
        username="cs-viewer",
        email="v@test.local",
        password_hash="",
        full_name="V",
        role_id="role-viewer",
        is_active=True,
        mfa_enabled=False,
        principal_id="person:cs-viewer",
    )
    client.app.dependency_overrides[get_current_user] = lambda: viewer
    client.app.dependency_overrides[get_current_active_user] = lambda: viewer
    assert client.get(f"{BASE}/sources").status_code == 200
    assert client.post(f"{BASE}/runs", json={"source": "sample"}).status_code == 403


def test_sample_history_cannot_become_the_baseline_for_real_alerts(client, analyst):
    run, _ = _sample_run(client, judge_limit=0)
    response = client.post(f"{BASE}/runs/{run['id']}/go-live")
    assert response.status_code >= 400
    assert "synthetic" in response.json()["detail"]
    assert client.get(f"{BASE}/runs/{run['id']}").json()["status"] == "ready"


def test_a_sample_run_reads_only_the_history_it_was_asked_for(client, analyst):
    run, _ = _sample_run(client, judge_limit=0, history_days=7, review_days=1)
    counts = client.get(f"{BASE}/runs/{run['id']}").json()["counts"]
    assert 0 < counts["days_covered"] <= 9
    assert counts["alerts_read"] < 2293


def test_a_not_benign_review_takes_the_kind_off_would_close(client, analyst):
    run, _ = _sample_run(client, judge_limit=0)
    groups = client.get(f"{BASE}/runs/{run['id']}/groups").json()["groups"]
    target = next(
        g
        for g in groups
        if g["stage1"]["dismiss_candidate"] == g["count"] and g["tickets"]["real"] == 0
    )

    response = client.post(
        f"{BASE}/runs/{run['id']}/groups/{target['key']}/review",
        json={"verdict": "not_benign"},
    )
    assert response.status_code == 200

    after = next(g for g in response.json()["groups"] if g["key"] == target["key"])
    assert after["stage1"]["dismiss_candidate"] == 0
    assert after["stage1"]["escalate"] == after["count"]
    assert after["tickets"] == target["tickets"]
    assert after["review"]["not_benign"] == after["count"]


def test_agreeing_records_the_review_and_invents_no_label(client, analyst):
    run, _ = _sample_run(client, judge_limit=0)
    groups = client.get(f"{BASE}/runs/{run['id']}/groups").json()["groups"]
    target = next(g for g in groups if g["stage1"]["abstain"] > 0)

    after = next(
        g
        for g in client.post(
            f"{BASE}/runs/{run['id']}/groups/{target['key']}/review",
            json={"verdict": "agree"},
        ).json()["groups"]
        if g["key"] == target["key"]
    )
    assert after["tickets"] == target["tickets"]
    assert after["stage1"] == target["stage1"]
    assert after["review"]["agree"] == after["count"]


def test_a_review_saved_while_judging_reaches_the_baseline_that_goes_live(
    client, analyst
):
    run, _ = _sample_run(client, judge_limit=0)
    run_id = run["id"]
    groups = client.get(f"{BASE}/runs/{run_id}/groups").json()["groups"]
    target = next(g for g in groups if g["stage1"]["dismiss_candidate"] == g["count"])

    lease = store.WorkerLease.acquire()
    assert lease is not None
    try:
        response = client.post(
            f"{BASE}/runs/{run_id}/groups/{target['key']}/review",
            json={"verdict": "not_benign"},
        )
        assert response.status_code == 200
        still = next(g for g in response.json()["groups"] if g["key"] == target["key"])
        assert still["stage1"]["dismiss_candidate"] == still["count"]
        assert _go_live(client, run_id).status_code == 409
    finally:
        lease.release()

    assert _go_live(client, run_id).status_code == 200
    after = next(
        g
        for g in client.get(f"{BASE}/runs/{run_id}/groups").json()["groups"]
        if g["key"] == target["key"]
    )
    assert after["stage1"]["escalate"] == after["count"]


def test_a_review_saved_during_a_short_build_is_applied_when_it_ends(client, analyst):
    run, _ = _sample_run(client, judge_limit=0)
    run_id = run["id"]
    groups = client.get(f"{BASE}/runs/{run_id}/groups").json()["groups"]
    target = next(g for g in groups if g["stage1"]["dismiss_candidate"] == g["count"])

    lease = store.WorkerLease.acquire()
    assert lease is not None
    release = threading.Timer(1.0, lease.release)
    release.start()
    try:
        response = client.post(
            f"{BASE}/runs/{run_id}/groups/{target['key']}/review",
            json={"verdict": "not_benign"},
        )
    finally:
        release.join()
    assert response.status_code == 200
    after = next(g for g in response.json()["groups"] if g["key"] == target["key"])
    assert after["stage1"]["escalate"] == after["count"]


def test_a_rebuild_error_after_judging_keeps_the_good_run(client, analyst):
    run, _ = _sample_run(client, judge_limit=0)
    run_id = run["id"]
    groups = client.get(f"{BASE}/runs/{run_id}/groups").json()["groups"]
    client.post(
        f"{BASE}/runs/{run_id}/groups/{groups[0]['key']}/review",
        json={"verdict": "agree"},
    )
    with (
        patch(
            "core.coldstart.runner.rebuild", side_effect=RuntimeError("database hiccup")
        ),
        patch(
            "core.coldstart.runner.oneshot.complete", AsyncMock(return_value=GOOD_REPLY)
        ),
    ):
        assert client.post(f"{BASE}/runs/{run_id}/judge").status_code == 200
        resumed = _wait(client, run_id)
    assert resumed["status"] == "ready"
