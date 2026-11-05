"""The routes and the daemon's seam on real Postgres. Only the model's reply is scripted."""

from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import text

from core.autonomy import policy
from core.autonomy.track_record import POLICY_LIFETIME, POLICY_REASON_PREFIX
from core.coldstart import store as coldstart_store
from core.coldstart.tickets import filter_tickets
from core.storage.database_data_service import DatabaseDataService
from core.storage.models import Finding
from core.storage.models.cold_start import RunStatus
from core.storage.unit_of_work import unit_of_work
from services.daemon.config import ProcessingConfig
from services.daemon.processor import FindingProcessor
from tests.unit.autonomy_kinds.conftest import (
    ENTITIES,
    NOW,
    PERSON,
    RULE,
    SOURCE,
    TITLE,
    add_finding,
    closed_case,
    earn,
    kind_key,
    row_of,
)

pytestmark = [pytest.mark.unit, pytest.mark.database]

BASE = "/api/kind-autonomy"
BENIGN_REPLY = (
    "SEVERITY: low\nCONFIDENCE: 0.4\nRECOMMENDED_ACTION: dismiss\nREASONING: fine"
)


def _adopt(client, key=None):
    return client.post(
        f"{BASE}/{key or kind_key()}/adopt", json={"reason": "Reviewed."}
    )


def _events(client, key=None):
    return client.get(f"{BASE}/{key or kind_key()}/events").json()["events"]


def _turn_on(client):
    assert (
        client.put(f"{BASE}/settings", json={"close_enabled": True}).status_code == 200
    )


def _sql(statement, **params):
    with unit_of_work() as session:
        return session.execute(text(statement), params).all()


def _stored(finding_id):
    with unit_of_work() as session:
        row = session.get(Finding, finding_id)
        return (row.noise_marked_at, row.noise_marked_by_kind, row.noise_reason)


def _adopted(client):
    earn()
    assert _adopt(client).status_code == 200


def _incoming(finding_id="new", *, severity="low", rule=RULE, title=TITLE, **over):
    add_finding(finding_id, severity=severity, at=NOW, rule=rule, title=title)
    return {
        "finding_id": finding_id,
        "data_source": SOURCE,
        "title": title,
        "severity": severity,
        "description": "d",
        "timestamp": NOW.isoformat(),
        "entity_context": ENTITIES,
        **over,
    }


async def _through_daemon(finding, reply=BENIGN_REPLY, data_service=True):
    """The real background path, with only the model and the offer to intake scripted."""
    processor = FindingProcessor(ProcessingConfig(auto_enrich_enabled=False))
    processor._data_service = DatabaseDataService() if data_service else None
    offer = AsyncMock()
    with (
        patch.object(
            FindingProcessor, "_get_ai_triage", AsyncMock(return_value=(reply, None))
        ),
        patch.object(FindingProcessor, "_evaluate_for_response", offer),
        patch("core.coldstart.active.live_baseline", return_value=None),
    ):
        await processor._enrich_in_background(finding)
    return offer


def test_a_clean_install_has_no_kinds_and_closing_is_off(client, admin):
    body = client.get(BASE).json()
    assert body["kinds"] == []
    assert body["close_enabled"] is False
    assert body["bar"] == 59
    assert body["summary"] == {
        "kinds": 0,
        "closing": 0,
        "closed_by_vigil": 0,
        "overturned": 0,
    }
    assert sum(d["asked"] + d["closed"] for d in body["daily"]) == 0


def test_a_kind_shows_its_record_and_why_it_is_not_eligible(client, admin):
    earn(5)
    add_finding("waiting")
    row = row_of(client)
    assert row["mode"] == "ask"
    assert row["source"] == SOURCE
    assert row["track_record"]["alerts_seen"] == 6
    assert row["track_record"]["agreed"] == 5
    assert row["eligible"] is False
    assert row["why_not"][0]["why"].startswith("5 of 59 clean labels")


def test_adoption_below_59_is_refused_with_the_reason(client, admin):
    earn(58)
    refused = _adopt(client)
    assert refused.status_code == 409
    assert "58 of 59 clean labels" in refused.json()["detail"]
    assert _events(client) == []
    assert row_of(client)["mode"] == "ask"


def test_one_case_of_59_alerts_is_one_label_through_the_route(client, admin):
    ids = [add_finding(f"f{i}") for i in range(59)]
    closed_case("case-59", ids)
    assert row_of(client)["track_record"]["agreed"] == 1
    assert _adopt(client).status_code == 409


def test_a_reopened_case_retracts_its_label(client, admin):
    closed_case("case-open", [add_finding("f")], status="in_progress")
    assert row_of(client)["track_record"]["agreed"] == 0


def test_adoption_at_59_names_the_person_and_the_evidence(client, admin):
    earn()
    adopted = _adopt(client)
    assert adopted.status_code == 200
    row = row_of(client)
    assert row["mode"] == "close"
    assert row["adoption"]["by"] == "person:ka-admin"
    assert row["adoption"]["by_label"] == "ka-admin"
    assert row["adoption"]["policy_id"] == adopted.json()["policy_id"]
    event = _events(client)[0]
    assert event["event"] == "adopt"
    assert event["clean_labels"] == 59
    assert event["evidence"]["closed_here_benign"] == 59
    assert event["evidence"]["miss_bound"] == pytest.approx(0.0495, abs=0.001)


def test_the_database_itself_refuses_a_close_below_the_bar(client, admin):
    with pytest.raises(Exception, match="kind_policy_events_adopt_bar_check"):
        with unit_of_work() as session:
            session.execute(
                text("INSERT INTO kind_policies (signature, mode) VALUES ('k', 'ask')")
            )
            session.execute(
                text(
                    "INSERT INTO kind_policy_events (signature, from_mode, to_mode, "
                    "actor, reason, evidence, clean_labels) VALUES ('k', 'ask', 'close', "
                    "'a', 'r', '{\"e\": 1}'::jsonb, 58)"
                )
            )


@pytest.mark.parametrize(
    "role, route, status",
    [
        ("role-viewer", "adopt", 403),
        ("role-analyst", "adopt", 403),
        ("role-viewer", "revoke", 403),
        ("role-analyst", "revoke", 403),
    ],
)
def test_changing_a_policy_needs_its_permission(client, act_as, role, route, status):
    earn()
    act_as("ka-limited", role)
    answer = client.post(f"{BASE}/{kind_key()}/{route}")
    assert answer.status_code == status


def test_a_service_account_cannot_adopt_or_revoke(client, act_as):
    earn()
    act_as("ka-service", service=True)
    assert _adopt(client).status_code == 403
    assert client.post(f"{BASE}/{kind_key()}/revoke").status_code == 403
    assert (
        client.put(f"{BASE}/settings", json={"close_enabled": True}).status_code == 403
    )


def test_adoption_is_refused_while_autonomy_is_stopped(client, admin):
    earn()
    assert client.post("/api/orchestrator/kill").status_code == 200
    assert _adopt(client).status_code == 409
    assert (
        client.put(f"{BASE}/settings", json={"close_enabled": True}).status_code == 409
    )


def test_a_person_revokes_and_a_later_adoption_works(client, admin):
    _adopted(client)
    assert client.post(f"{BASE}/{kind_key()}/revoke").json()["mode"] == "ask"
    assert row_of(client)["mode"] == "ask"
    assert client.post(f"{BASE}/{kind_key()}/revoke").status_code == 409
    assert _adopt(client).status_code == 200
    assert [e["event"] for e in _events(client)] == ["adopt", "revoke", "adopt"]


def test_readopting_a_live_policy_renews_its_lifetime(client, admin):
    _adopted(client)
    first = row_of(client)["adoption"]
    assert _adopt(client).status_code == 200
    second = row_of(client)["adoption"]
    assert second["policy_id"] > first["policy_id"]
    assert second["expires_at"] > first["expires_at"]
    assert [e["event"] for e in _events(client)] == ["adopt", "renew", "adopt"]


async def test_off_by_default_an_adopted_kind_stays_in_the_queue(client, admin):
    _adopted(client)
    offer = await _through_daemon(_incoming())
    assert _stored("new") == (None, None, None)
    offer.assert_awaited_once()


async def test_on_a_live_policy_closes_and_records_vigil_as_the_closer(client, admin):
    _adopted(client)
    _turn_on(client)
    policy_id = row_of(client)["adoption"]["policy_id"]
    offer = await _through_daemon(_incoming())
    marked_at, kind, reason = _stored("new")
    assert marked_at is not None
    assert kind == "agent"
    assert reason == f"{POLICY_REASON_PREFIX}{policy_id}"
    offer.assert_not_awaited()
    assert (
        _sql("SELECT count(*) FROM intake_triggers WHERE finding_id = 'new'")[0][0] == 0
    )
    trail = _sql(
        "SELECT payload->>'action' FROM audit_trail "
        "WHERE payload->>'finding_id' = 'new' ORDER BY seq DESC LIMIT 1"
    )
    assert trail[0][0] == "finding.noise.mark"


async def test_vigils_own_closures_do_not_raise_its_record(client, admin):
    _adopted(client)
    _turn_on(client)
    before = row_of(client)["track_record"]["agreed"]
    for i in range(3):
        await _through_daemon(_incoming(f"auto-{i}"))
    row = row_of(client)
    assert row["track_record"]["closed_by_vigil"] == 3
    assert row["track_record"]["agreed"] == before


@pytest.mark.parametrize("severity", ["high", "critical"])
async def test_a_real_attack_above_scope_on_an_adopted_kind_stays(
    client, admin, severity
):
    _adopted(client)
    _turn_on(client)
    reply = (
        f"SEVERITY: {severity}\nCONFIDENCE: 0.9\nRECOMMENDED_ACTION: isolate\n"
        "REASONING: lateral movement"
    )
    offer = await _through_daemon(_incoming(severity=severity), reply)
    assert _stored("new") == (None, None, None)
    offer.assert_awaited_once()


async def test_a_high_alert_a_model_calls_low_still_stays(client, admin):
    _adopted(client)
    _turn_on(client)
    offer = await _through_daemon(_incoming(severity="high"))
    assert _stored("new") == (None, None, None)
    offer.assert_awaited_once()


async def test_a_low_alert_triage_raises_to_high_stays(client, admin):
    _adopted(client)
    _turn_on(client)
    reply = "SEVERITY: high\nRECOMMENDED_ACTION: dismiss"
    await _through_daemon(_incoming(), reply)
    assert _stored("new") == (None, None, None)


async def test_a_failed_triage_stays(client, admin):
    _adopted(client)
    _turn_on(client)
    offer = await _through_daemon(_incoming(), "I cannot help with that.")
    assert _stored("new") == (None, None, None)
    offer.assert_awaited_once()


async def test_another_kind_stays(client, admin):
    _adopted(client)
    _turn_on(client)
    add_finding("other", title="Some other alert", at=NOW)
    await _through_daemon(
        {
            "finding_id": "other",
            "data_source": SOURCE,
            "title": "Some other alert",
            "severity": "low",
            "timestamp": NOW.isoformat(),
            "entity_context": ENTITIES,
        }
    )
    assert _stored("other") == (None, None, None)


async def test_an_alert_on_a_case_stays(client, admin):
    _adopted(client)
    _turn_on(client)
    finding = _incoming()
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO cases (case_id, title, status, priority, timeline) "
                "VALUES ('open', 'c', 'new', 'low', '[]'::jsonb)"
            )
        )
        session.execute(
            text(
                "INSERT INTO case_findings (case_id, finding_id, added_at) "
                "VALUES ('open', 'new', now())"
            )
        )
    await _through_daemon(finding)
    assert _stored("new") == (None, None, None)


async def test_while_stopped_nothing_closes(client, admin):
    _adopted(client)
    _turn_on(client)
    assert client.post("/api/orchestrator/kill").status_code == 200
    await _through_daemon(_incoming())
    assert _stored("new") == (None, None, None)


async def test_no_database_means_nothing_closes(client, admin):
    _adopted(client)
    _turn_on(client)
    offer = await _through_daemon(_incoming(), data_service=False)
    assert _stored("new") == (None, None, None)
    offer.assert_awaited_once()


@pytest.mark.parametrize(
    "target",
    [
        "core.autonomy.policy.close_enabled",
        "core.autonomy.policy.unit_of_work",
        "core.autonomy.policy.execution_held",
        "core.autonomy.policy._settle",
    ],
)
async def test_any_failure_leaves_the_alert_in_the_queue(client, admin, target):
    _adopted(client)
    _turn_on(client)
    finding = _incoming()
    with patch(target, side_effect=RuntimeError("no database")):
        offer = await _through_daemon(finding)
    assert _stored("new") == (None, None, None)
    offer.assert_awaited_once()


async def test_a_failed_audit_write_undoes_the_close(client, admin):
    _adopted(client)
    _turn_on(client)
    finding = _incoming()
    with patch(
        "core.autonomy.policy.case_trail.append_or_legacy",
        side_effect=RuntimeError("no trail"),
    ):
        offer = await _through_daemon(finding)
    assert _stored("new") == (None, None, None)
    offer.assert_awaited_once()


def test_a_real_closure_after_adoption_suspends_with_an_event(client, admin):
    _adopted(client)
    closed_case(
        "real-1",
        [add_finding("attack", at=NOW)],
        category="resolved",
        at=NOW + timedelta(minutes=5),
    )
    row = row_of(client)
    assert row["mode"] == "suspended"
    assert row["adoption"] is None
    assert row["mode_reason"].startswith(
        "A person closed an alert of this kind as real"
    )
    event = _events(client)[0]
    assert event["event"] == "suspend"
    assert event["actor_label"] == "Vigil"
    assert event["evidence"]["ref"] == "real-1"
    assert "none_real" in {r["rule"] for r in row["why_not"]}
    assert _adopt(client).status_code == 409


async def test_the_daemon_notices_a_real_closure_before_it_closes(client, admin):
    _adopted(client)
    _turn_on(client)
    closed_case(
        "real-2",
        [add_finding("attack", at=NOW)],
        category="resolved",
        at=NOW + timedelta(minutes=5),
    )
    finding = _incoming()
    with patch("core.autonomy.policy._now", return_value=NOW + timedelta(minutes=10)):
        offer = await _through_daemon(finding)
    assert _stored("new") == (None, None, None)
    offer.assert_awaited_once()
    with unit_of_work() as session:
        assert (
            session.execute(
                text("SELECT mode FROM kind_policies WHERE signature LIKE :s"),
                {"s": f"{SOURCE}|%"},
            ).scalar_one()
            == "ask"
        )
    assert _events(client)[0]["event"] == "suspend"


def test_an_agents_real_closure_does_not_suspend(client, admin):
    _adopted(client)
    closed_case(
        "agent-real",
        [add_finding("attack", at=NOW)],
        category="resolved",
        channel="agent",
        at=NOW + timedelta(minutes=5),
    )
    assert row_of(client)["mode"] == "close"


async def test_a_policy_expires_after_90_days_and_stops_closing(client, admin):
    _adopted(client)
    _turn_on(client)
    later = NOW + POLICY_LIFETIME + timedelta(hours=1)
    finding = _incoming()
    with patch("core.autonomy.policy._now", return_value=later):
        offer = await _through_daemon(finding)
    assert _stored("new") == (None, None, None)
    offer.assert_awaited_once()
    assert row_of(client)["mode"] == "expired"
    assert _events(client)[0]["event"] == "expire"
    assert _events(client)[0]["actor"] == "vigil"


def test_expiry_shows_on_the_screens_read_with_no_alert_to_trigger_it(client, admin):
    _adopted(client)
    later = NOW + POLICY_LIFETIME + timedelta(hours=1)
    with patch("core.autonomy.policy._now", return_value=later):
        row = row_of(client)
    assert row["mode"] == "expired"


async def test_a_person_samples_and_overturns_and_that_suspends(client, admin):
    _adopted(client)
    _turn_on(client)
    await _through_daemon(_incoming("auto-1"))
    await _through_daemon(_incoming("auto-2"))
    closed = client.get(f"{BASE}/{kind_key()}/closed").json()
    assert closed["total"] == 2
    assert {a["finding_id"] for a in closed["alerts"]} == {"auto-1", "auto-2"}
    sampled = client.get(f"{BASE}/{kind_key()}/closed?sample=true&limit=1").json()
    assert sampled["total"] == 2 and len(sampled["alerts"]) == 1

    done = client.post(
        f"{BASE}/{kind_key()}/closed/auto-1/overturn", json={"reason": "This was real."}
    )
    assert done.status_code == 200
    assert _stored("auto-1") == (None, None, None)
    row = row_of(client)
    assert row["mode"] == "suspended"
    assert row["track_record"]["overturned"] == 1
    assert row["track_record"]["real"] == 1
    assert _adopt(client).status_code == 409
    event = _events(client)[0]
    assert event["event"] == "overturn"
    assert event["reason"] == "This was real."
    assert event["actor"] == PERSON

    # After the suspension the other closure can still be overturned, and counts too.
    assert client.post(f"{BASE}/{kind_key()}/closed/auto-2/overturn").status_code == 200
    assert row_of(client)["track_record"]["overturned"] == 2
    assert client.get(f"{BASE}/{kind_key()}/closed").json()["total"] == 0


async def test_a_suspended_policy_stops_closing(client, admin):
    _adopted(client)
    _turn_on(client)
    await _through_daemon(_incoming("auto-1"))
    client.post(f"{BASE}/{kind_key()}/closed/auto-1/overturn")
    await _through_daemon(_incoming("auto-2"))
    assert _stored("auto-2") == (None, None, None)


def test_only_what_the_policy_closed_can_be_overturned(client, admin):
    _adopted(client)
    add_finding(
        "by-hand",
        noise_at=NOW,
        noise_by="ka-closer",
        noise_kind="person",
    )
    add_finding(
        "other-policy",
        noise_at=NOW,
        noise_by="vigil",
        noise_kind="agent",
        noise_reason=f"{POLICY_REASON_PREFIX}999999",
    )
    for finding_id in ("by-hand", "other-policy", "missing"):
        answer = client.post(f"{BASE}/{kind_key()}/closed/{finding_id}/overturn")
        assert answer.status_code == 404
    assert row_of(client)["mode"] == "close"


async def test_an_analyst_can_overturn_but_not_adopt(client, act_as):
    act_as("ka-admin")
    _adopted(client)
    _turn_on(client)
    await _through_daemon(_incoming("auto-1"))
    act_as("ka-analyst", "role-analyst")
    assert _adopt(client).status_code == 403
    done = client.post(f"{BASE}/{kind_key()}/closed/auto-1/overturn")
    assert done.status_code == 200
    assert _events(client)[0]["actor"] == "person:ka-analyst"


def _live_run(tickets, *, go_live=True):
    run_id = coldstart_store.create_run(
        source="upload",
        history_days=45,
        review_days=7,
        judge_limit=0,
        created_by="ka-admin",
    )
    coldstart_store.insert_tickets(run_id, filter_tickets(tickets).kept)
    if go_live:
        with unit_of_work() as session:
            session.execute(
                text("UPDATE cold_start_runs SET status = :s WHERE run_id = :r"),
                {"s": RunStatus.LIVE.value, "r": run_id},
            )
    return run_id


def _ticket(i, disposition="false_positive"):
    return {
        "external_id": f"t-{i}",
        "source": SOURCE,
        "title": TITLE,
        "disposition": disposition,
        "closed_at": (NOW - timedelta(hours=2 * (i + 1))).isoformat(),
        "closed_by": "a person",
        "entities": ["wks-sample-1"],
    }


def test_tickets_count_only_from_a_live_run_and_read_as_imported(client, admin):
    _live_run([_ticket(i) for i in range(59)], go_live=False)
    add_finding("one")
    assert row_of(client)["track_record"]["imported_benign"] == 0

    with unit_of_work() as session:
        session.execute(text("DELETE FROM cold_start_runs"))
    _live_run([_ticket(i) for i in range(59)])
    row = row_of(client)
    assert row["track_record"]["imported_benign"] == 59
    assert row["track_record"]["closed_here_benign"] == 0
    assert row["eligible"] is True
    assert _sql("SELECT count(*) FROM case_closure_info")[0][0] == 0
    assert _adopt(client).status_code == 200
    assert _events(client)[0]["evidence"]["imported_benign"] == 59


def test_a_real_ticket_in_the_live_run_blocks_adoption(client, admin):
    earn()
    _live_run([_ticket(0, "true_positive")])
    refused = _adopt(client)
    assert refused.status_code == 409
    assert "closed real" in refused.json()["detail"]


def test_a_real_ticket_closed_after_adoption_suspends(client, admin):
    _adopted(client)
    ticket = _ticket(0, "true_positive")
    ticket["closed_at"] = (NOW + timedelta(minutes=5)).isoformat()
    _live_run([ticket])
    with patch("core.autonomy.policy._now", return_value=NOW + timedelta(minutes=10)):
        assert row_of(client)["mode"] == "suspended"


def test_turning_closing_off_needs_only_the_stop_permission(client, act_as):
    act_as("ka-admin")
    _turn_on(client)
    assert policy.close_enabled() is True
    act_as("ka-senior", "role-senior-analyst")
    assert (
        client.put(f"{BASE}/settings", json={"close_enabled": True}).status_code == 403
    )
    assert (
        client.put(f"{BASE}/settings", json={"close_enabled": False}).status_code == 200
    )
    assert policy.close_enabled() is False


def test_events_and_closed_for_an_unknown_kind_are_empty(client, admin):
    assert client.get(f"{BASE}/nope/events").json() == {"events": []}
    assert client.get(f"{BASE}/nope/closed").json() == {"total": 0, "alerts": []}
    assert client.post(f"{BASE}/nope/adopt").status_code == 404
    assert client.post(f"{BASE}/nope/revoke").status_code == 404


@pytest.mark.parametrize(
    "reply",
    [
        "SEVERITY: low\nCONFIDENCE: 0.4\nRECOMMENDED_ACTION: monitor\nREASONING: fine",
        "SEVERITY: low\nCONFIDENCE: 0.4\nREASONING: no action named",
        "SEVERITY: low",
    ],
)
async def test_only_an_explicit_dismiss_closes_and_the_rest_are_evaluated(
    client, admin, reply
):
    _adopted(client)
    _turn_on(client)
    offer = await _through_daemon(_incoming("stays"), reply)
    assert _stored("stays") == (None, None, None)
    offer.assert_awaited_once()


async def test_a_dismiss_closes_and_skips_response_evaluation(client, admin):
    _adopted(client)
    _turn_on(client)
    offer = await _through_daemon(_incoming("goes"))
    assert _stored("goes")[1] == "agent"
    offer.assert_not_awaited()


def _mark_through_the_route(client):
    add_finding("marked")
    response = client.post("/api/findings/marked/noise", json={"reason": "seen it"})
    assert response.status_code == 200, response.text
    return response.json()["noise_marked_by_kind"]


def test_an_agent_token_noise_mark_is_stored_as_an_agent_and_earns_nothing(
    client, admin
):
    assert _mark_through_the_route(client) == "agent"
    assert _stored("marked")[1] == "agent"
    assert row_of(client)["track_record"]["agreed"] == 0


def test_a_console_person_noise_mark_is_stored_as_a_person_and_counts(client, admin):
    from core.cases.agent_closure import note_http_actor
    from services.api.middleware.auth import get_current_user

    async def signed_in():
        note_http_actor(
            username=admin.username,
            principal_id=admin.principal_id,
            via="cookie",
            person=True,
        )
        return admin

    client.app.dependency_overrides[get_current_user] = signed_in
    assert _mark_through_the_route(client) == "person"
    assert row_of(client)["track_record"]["agreed"] == 1


def test_a_legacy_analyst_mark_cannot_show_a_person_made_it_so_it_earns_nothing(
    client, admin
):
    earn(5, kind="analyst")
    assert row_of(client)["track_record"]["agreed"] == 0


def test_a_title_only_kind_shows_its_record_and_says_why_it_cannot_be_adopted(
    client, admin
):
    earn(rule=None)
    row = row_of(client)
    assert row["rule_id"] is None
    assert row["track_record"]["agreed"] == 59
    assert row["eligible"] is False
    assert [r["rule"] for r in row["why_not"]] == ["one_source_rule"]
    assert "Known only by its title" in row["why_not"][0]["why"]
    refused = _adopt(client)
    assert refused.status_code == 409
    assert "Known only by its title" in refused.json()["detail"]


def test_a_kind_two_rules_share_cannot_be_adopted(client, admin):
    earn()
    add_finding("other-rule", rule="another-rule")
    assert _adopt(client).status_code == 409
    assert "2 different source rules" in row_of(client)["why_not"][0]["why"]


async def test_an_alert_that_only_matches_the_title_is_never_closed(client, admin):
    _adopted(client)
    _turn_on(client)
    assert row_of(client)["rule_id"] == RULE
    await _through_daemon(_incoming("no-rule", rule=None))
    await _through_daemon(_incoming("another-rule", rule="another-rule"))
    await _through_daemon(_incoming("same-rule"))
    assert _stored("no-rule")[0] is None
    assert _stored("another-rule")[0] is None
    assert _stored("same-rule")[1] == "agent"


async def test_masking_cannot_hand_one_detection_anothers_policy(client, admin):
    masked = "<entity> connection to <entity>"
    earn(
        title="Allowed connection to allowed",
        rule="allow-rule",
        entities={"hostnames": ["allowed"]},
    )
    row = next(k for k in client.get(BASE).json()["kinds"] if k["title"] == masked)
    assert _adopt(client, row["key"]).status_code == 200
    _turn_on(client)

    add_finding(
        "blocked-one",
        title="Blocked connection to blocked",
        rule="deny-rule",
        entities={"hostnames": ["blocked"]},
        at=NOW,
    )
    finding = {
        "finding_id": "blocked-one",
        "data_source": SOURCE,
        "title": "Blocked connection to blocked",
        "severity": "low",
        "description": "d",
        "timestamp": NOW.isoformat(),
        "entity_context": {"hostnames": ["blocked"]},
    }
    await _through_daemon(finding)
    assert _stored("blocked-one")[0] is None


def test_a_request_cannot_claim_a_source_rule():
    plain = Finding(
        finding_id="x",
        data_source="s",
        entity_context={"source_rule": "claimed", "hostnames": ["a"]},
    )
    assert plain.entity_context == {"hostnames": ["a"]}
    assert plain.source_rule is None
    plain.source_rule = "claimed"
    assert plain.source_rule is None


def test_a_later_plain_write_keeps_the_rule_an_adapter_gave():
    from core.storage.source_rule import with_source_rule

    row = Finding(
        finding_id="x",
        data_source="s",
        entity_context=with_source_rule({"hostnames": ["a"]}, "real"),
    )
    assert row.entity_context == {"hostnames": ["a"]}
    assert row.source_rule == "real"
    row.source_rule = "claimed"
    row.entity_context = {"source_rule": "claimed", "hostnames": ["b"]}
    assert row.source_rule == "real"
    assert row.entity_context == {"hostnames": ["b"]}


def test_a_webhook_row_loses_its_claimed_rule_and_an_adapter_row_keeps_its_own(db):
    from core.ingestion.ingestion_service import IngestionService
    from core.integrations.splunk.adapter import _splunk_event_to_finding

    service = IngestionService()
    claimed = {
        "finding_id": "webhook-1",
        "data_source": "splunk",
        "title": "Failed logins",
        "severity": "low",
        "timestamp": NOW.isoformat(),
        "entity_context": {"source_rule": "Failed logins"},
        "mitre_predictions": {},
    }
    assert service.ingest_finding(claimed)
    adapter = _splunk_event_to_finding(
        {"_cd": "cd-1", "search_name": "Failed logins", "_time": NOW.isoformat()}
    )
    assert service.ingest_finding(adapter)
    with unit_of_work() as session:
        assert session.get(Finding, "webhook-1").source_rule is None
        stored = session.get(Finding, adapter["finding_id"])
        assert stored.source_rule == "Failed logins"
        assert "source_rule" not in (stored.entity_context or {})


def _forge_stored_rule(rule=RULE):
    """What a row holds when something wrote the key without passing through the model."""
    _sql(
        "UPDATE findings SET entity_context = coalesce(entity_context, '{}') || "
        "jsonb_build_object('source_rule', cast(:rule as text)) RETURNING finding_id",
        rule=rule,
    )


def test_a_rule_key_already_stored_on_a_row_earns_no_adoption(client, admin):
    earn(rule=None)
    _forge_stored_rule()
    row = row_of(client)
    assert row["rule_id"] is None
    assert row["eligible"] is False
    assert [r["rule"] for r in row["why_not"]] == ["one_source_rule"]
    refused = _adopt(client)
    assert refused.status_code == 409
    assert "Known only by its title" in refused.json()["detail"]


async def test_a_rule_key_already_stored_on_a_row_earns_no_close(client, admin):
    _adopted(client)
    _turn_on(client)
    finding = _incoming("forged", rule=None)
    _forge_stored_rule()
    await _through_daemon(finding)
    assert _stored("forged")[0] is None


async def test_a_true_positive_ticket_stops_the_next_close_at_once(client, admin):
    _adopted(client)
    _turn_on(client)
    ticket = _ticket(0, "true_positive")
    ticket["closed_at"] = (NOW + timedelta(minutes=5)).isoformat()
    _live_run([ticket])
    with patch("core.autonomy.policy._now", return_value=NOW + timedelta(minutes=10)):
        await _through_daemon(_incoming("after-ticket"))
    assert _stored("after-ticket")[0] is None
    assert _events(client)[0]["event"] == "suspend"
    assert _events(client)[0]["evidence"]["origin"] == "imported"


async def test_a_run_that_goes_live_after_adoption_is_weighed_whatever_its_dates(
    client, admin
):
    _adopted(client)
    _turn_on(client)
    run_id = _live_run([_ticket(0, "true_positive")])
    with unit_of_work() as session:
        session.execute(
            text("UPDATE cold_start_runs SET live_at = now() WHERE run_id = :r"),
            {"r": run_id},
        )
    await _through_daemon(_incoming("after-go-live"))
    assert _stored("after-go-live")[0] is None
    assert _events(client)[0]["event"] == "suspend"


async def test_closing_fails_closed_when_cold_start_history_cannot_be_read(
    client, admin
):
    _adopted(client)
    _turn_on(client)
    _live_run([])
    with patch(
        "core.autonomy.policy.coldstart_store.first_true_positive",
        side_effect=RuntimeError("no read"),
    ):
        offer = await _through_daemon(_incoming("unread"))
    assert _stored("unread")[0] is None
    offer.assert_awaited_once()


def _rows_fetched(work):
    """Every row the database handed back while ``work`` ran."""
    from sqlalchemy import event

    from core.storage.connection import get_db_manager

    fetched = []

    def count(_conn, cursor, _statement, _params, _context, _many):
        fetched.append(max(cursor.rowcount, 0))

    engine = get_db_manager().engine
    event.listen(engine, "after_cursor_execute", count)
    try:
        work()
    finally:
        event.remove(engine, "after_cursor_execute", count)
    return sum(fetched)


def _many_findings(count, title=TITLE):
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO findings (finding_id, title, data_source, severity, timestamp, "
                "source_rule, entity_context) SELECT 'bulk-' || g, :title, :source, 'low', "
                "now() - interval '1 hour', :rule, "
                "jsonb_build_object('src_ips', jsonb_build_array('10.0.' || (g / 250) || '.' "
                "|| (g % 250))) "
                "FROM generate_series(1, :count) g"
            ),
            {"title": title, "source": SOURCE, "rule": RULE, "count": count},
        )


def test_a_page_view_counts_in_the_database_rather_than_loading_every_alert(
    client, admin
):
    _many_findings(3000)
    fetched = _rows_fetched(lambda: client.get(BASE))
    assert fetched < 100
    assert row_of(client)["track_record"]["alerts_seen"] == 3000


async def test_a_close_does_not_read_every_alert_or_case(client, admin):
    _adopted(client)
    _turn_on(client)
    _many_findings(3000)
    finding = _incoming("one-more")
    assert _rows_fetched(lambda: policy.close_if_adopted(finding, "low")) < 50


def test_a_title_naming_its_entity_still_groups_by_the_masked_title(client, admin):
    for name in ("alice", "bob"):
        add_finding(
            f"login-{name}",
            title=f"Failed login for {name}",
            entities={"usernames": [name]},
        )
    rows = {k["title"]: k for k in client.get(BASE).json()["kinds"]}
    assert rows["Failed login for <entity>"]["track_record"]["alerts_seen"] == 2


def test_a_read_that_hits_its_limit_says_so_and_nothing_can_be_adopted(client, admin):
    earn()
    add_finding("second-kind", title="Another title")
    with patch("core.autonomy.policy.MAX_ALERT_GROUPS", 1):
        body = client.get(BASE).json()
        refused = _adopt(client)
    assert body["incomplete"] is True
    assert all(not k["eligible"] for k in body["kinds"])
    assert refused.status_code == 409
    assert "incomplete" in refused.json()["detail"]


def test_one_ticket_naming_two_alerts_of_a_kind_is_one_label(client, admin):
    add_finding("seen")
    run_id = _live_run([])
    with unit_of_work() as session:
        for i in range(2):
            session.execute(
                text(
                    "INSERT INTO cold_start_alerts (run_id, alert_id, source, signature, "
                    "observed_at, title, severity, entities, payload) VALUES (:r, :a, :s, "
                    ":k, :at, :t, 'low', '[]'::jsonb, '{}'::jsonb)"
                ),
                {
                    "r": run_id,
                    "a": f"h{i}",
                    "s": SOURCE,
                    "k": f"{SOURCE}|{TITLE}",
                    "at": NOW - timedelta(days=3),
                    "t": TITLE,
                },
            )
        session.execute(
            text(
                "INSERT INTO cold_start_outcomes (run_id, external_id, alert_ids, "
                "disposition, closed_at, entities) VALUES (:r, 'one', "
                "'[\"h0\", \"h1\"]'::jsonb, 'false_positive', :at, '[]'::jsonb)"
            ),
            {"r": run_id, "at": NOW - timedelta(days=1)},
        )
    assert row_of(client)["track_record"]["imported_benign"] == 1


@pytest.fixture
def policy_only(client, act_as):
    """A person who may read autonomy and not one finding."""
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO roles (role_id, name, description, permissions, is_system_role) "
                "VALUES ('role-ka-policy', 'Policy only', 'Autonomy, no findings', "
                """'{"ai_autonomy.read": true}', false) ON CONFLICT DO NOTHING"""
            )
        )
    act_as("ka-admin")
    _adopted(client)
    act_as("ka-policy", "role-ka-policy")
    return client


def test_without_findings_read_the_list_shows_policy_and_no_finding_content(
    policy_only,
):
    body = policy_only.get(BASE).json()
    assert body["redacted"] is True
    row = body["kinds"][0]
    assert row["key"] == kind_key()
    assert row["mode"] == "close"
    assert row["track_record"]["agreed"] == 59
    for name in ("signature", "source", "title", "rule_id", "mode_reason"):
        assert row[name] is None, name
    assert row["adoption"]["reason"] is None
    assert TITLE not in policy_only.get(BASE).text
    assert RULE not in policy_only.get(BASE).text


def test_without_findings_read_the_record_has_no_reasons_or_evidence(policy_only):
    answer = policy_only.get(f"{BASE}/{kind_key()}/events")
    assert answer.status_code == 200
    event = answer.json()["events"][0]
    assert event["event"] == "adopt"
    assert event["reason"] is None
    assert event["evidence"] == {}
    assert RULE not in answer.text


def test_without_findings_read_what_a_policy_closed_is_refused(policy_only):
    assert policy_only.get(f"{BASE}/{kind_key()}/closed").status_code == 403


def test_with_findings_read_the_list_keeps_its_content(client, admin):
    earn()
    body = client.get(BASE).json()
    assert body["redacted"] is False
    assert body["kinds"][0]["title"] == TITLE
    assert body["kinds"][0]["rule_id"] == RULE
