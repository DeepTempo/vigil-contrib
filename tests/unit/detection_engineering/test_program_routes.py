"""The routes end to end on real Postgres, through permission gates, with invented rows."""

import pytest
from sqlalchemy import text

from core.detections.inventory.readers import OVERLAY_SOURCE
from core.detections.inventory.record import RuleRecord
from core.detections.inventory.sync import sync_source
from core.storage.unit_of_work import unit_of_work

from .conftest import RULE

pytestmark = pytest.mark.database

BASE = "/api/detection-engineering"
SPL = 'ParentImage="*\\\\WINWORD.EXE" CommandLine="*-enc*"'


def _rule(key, name, techniques, language="sigma", content=None, query="x", **rest):
    return RuleRecord(
        native_key=key,
        name=name,
        language=language,
        path=f"{key}.yml",
        query=query,
        techniques=techniques,
        tactics=rest.pop("tactics", []),
        content=content or {"title": name},
        **rest,
    )


def _post(client, path, body=None, status=200):
    response = client.post(f"{BASE}{path}", json=body or {})
    assert response.status_code == status, response.text
    return response.json()


def _get(client, path):
    response = client.get(f"{BASE}{path}")
    assert response.status_code == 200, response.text
    return response.json()


def _state(coverage, technique):
    return next(r for r in coverage["techniques"] if r["technique"] == technique)


def test_empty_install_answers_every_program_route_with_nothing_invented(client, admin):
    coverage = _get(client, "/coverage")
    assert coverage["techniques"] == [] and coverage["rule_total"] == 0
    assert coverage["summary"]["percent_validated"] is None
    rules = _get(client, "/rules")
    assert (
        rules["rules"] == [] and rules["total"] == 0 and rules["fields_known"] is False
    )
    sources = _get(client, "/log-sources")
    assert sources["configured"] == [] and sources["stored"] == []
    assert all(kind["rows"] == 0 for kind in sources["kinds"])
    assert _get(client, "/proposals")["proposals"] == []
    assert _get(client, "/red-team")["runs"] == []
    assert _get(client, "/threat-model")["priority_techniques"] == []
    assert len(_get(client, "/targets")["targets"]) == 13


def test_a_rule_goes_from_paste_to_live_and_only_proof_changes_the_map(
    client, admin, add_case, add_event, attack_row, plain_row
):
    sync_source("repo:rules", [_rule("r1", "Encoded PowerShell", ["T1059.001"])])
    case_id = add_case()
    add_event(attack_row, case_id=case_id)
    add_event(plain_row)

    before = _get(client, "/coverage")
    assert _state(before, "T1059.001")["state"] == "unproven"
    assert before["summary"]["percent_validated"] == 0

    view = _post(client, "/proposals", {"sigma": RULE, "case_id": case_id})
    pid = view["proposal_id"]
    assert view["created_by"] == "de-admin"
    _post(client, f"/proposals/{pid}/lint")
    view = _post(client, f"/proposals/{pid}/replay")
    assert view["state"] == "replayed"
    assert _state(_get(client, "/coverage"), "T1059.001")["state"] == "unproven"

    view = _post(client, f"/proposals/{pid}/convert", {"pasted": {"splunk": SPL}})
    assert view["state"] == "converted"
    view = _post(client, f"/proposals/{pid}/shadow")
    assert view["state"] == "shadow"

    after = _get(client, "/coverage")
    row = _state(after, "T1059.001")
    assert row["state"] == "validated"
    assert row["proof"]["hits"] == 1 and row["proposal"]["proposal_id"] == pid
    assert after["summary"]["percent_validated"] == 100

    _post(client, f"/proposals/{pid}/live", status=422)
    view = _post(client, f"/proposals/{pid}/live", {"reason": "Reviewed"})
    assert view["state"] == "live"
    actors = {e["actor"] for e in view["events"]}
    assert actors == {"de-admin"}
    _post(client, f"/proposals/{pid}/reject", {"reason": "no"}, status=409)


def test_one_rules_copies_count_as_one_rule(client, admin):
    technique = "T1059.001"
    sync_source(
        OVERLAY_SOURCE,
        [
            _rule("sigma-copy", "Encoded PowerShell", [technique]),
            _rule("splunk-copy", "Encoded PowerShell", [technique], language="splunk"),
        ],
    )
    # In a SIEM's own inventory a repeated name is two rules.
    sync_source(
        "wazuh",
        [
            _rule("100", "Repeated name", [technique], language="wazuh"),
            _rule("101", "Repeated name", [technique], language="wazuh"),
        ],
    )

    coverage = _get(client, "/coverage")
    assert _state(coverage, technique)["rules"] == 3
    assert coverage["rule_total"] == 3
    rules = _get(client, "/rules")
    assert rules["rule_total"] == 3 and rules["mapped"] == 3
    assert rules["total"] == 4


def test_an_illegal_move_is_a_409_and_an_unknown_proposal_a_404(client, admin):
    view = _post(client, "/proposals", {"sigma": RULE})
    _post(client, f"/proposals/{view['proposal_id']}/convert", status=409)
    _post(client, f"/proposals/{view['proposal_id']}/live", {"reason": "x"}, status=409)
    _post(client, "/proposals/no-such/lint", status=404)


def test_a_person_can_tune_through_the_route(
    client, admin, add_case, add_event, attack_row, signed_macro_row
):
    case_id = add_case()
    add_event(attack_row, case_id=case_id)
    add_event(signed_macro_row)
    pid = _post(client, "/proposals", {"sigma": RULE, "case_id": case_id})[
        "proposal_id"
    ]
    _post(client, f"/proposals/{pid}/lint")
    view = _post(client, f"/proposals/{pid}/replay")
    assert view["latest"]["replay"]["evidence"]["false_positives"] == 1
    _post(client, f"/proposals/{pid}/convert", {"pasted": {"splunk": SPL}}, status=422)
    body = {
        "field": "ParentCommandLine",
        "match": "contains",
        "values": ["trusted-macros"],
        "reason": "Signed macros",
    }
    view = _post(client, f"/proposals/{pid}/tune", body)
    assert view["latest"]["replay"]["evidence"]["false_positives"] == 0
    _post(client, f"/proposals/{pid}/tune", {**body, "field": "bad|field"}, status=422)


def test_a_draft_with_no_provider_says_so_and_a_person_can_still_paste(
    client, admin, monkeypatch
):
    from core.llm import oneshot

    async def none(**_):
        raise oneshot.NoProviderConfigured(oneshot.NOT_CONFIGURED)

    monkeypatch.setattr(oneshot, "complete", none)
    response = client.post(f"{BASE}/proposals/draft", json={"technique": "T1059.001"})
    assert response.status_code == 409
    assert "No AI provider" in response.json()["detail"]
    assert _post(client, "/proposals", {"sigma": RULE})["state"] == "draft"


def test_heat_map_has_a_no_rule_cell_for_a_priority_and_for_what_alerts_show(
    client, admin, add_event, plain_row
):
    add_event(plain_row, mitre="T1071.001")
    model = {
        "sector": "Regional manufacturing",
        "crown_jewels": "Plant historian",
        "priority_techniques": ["t1486", "T1059.001", "T1486"],
    }
    response = client.put(f"{BASE}/threat-model", json=model)
    assert response.status_code == 200
    saved = response.json()
    assert saved["priority_techniques"] == ["T1486", "T1059.001"]
    assert saved["updated_by"] == "de-admin"

    sync_source("repo:rules", [_rule("r1", "Encoded PowerShell", ["T1059.001"])])
    coverage = _get(client, "/coverage")
    assert _state(coverage, "T1486")["state"] == "no_rule"
    assert _state(coverage, "T1486")["priority"] is True
    assert _state(coverage, "T1071.001")["seen"] == 1
    summary = coverage["summary"]
    assert (summary["basis"], summary["counted"], summary["percent_validated"]) == (
        "priority",
        2,
        0,
    )
    response = client.put(
        f"{BASE}/threat-model", json={"priority_techniques": ["nope"]}
    )
    assert response.status_code == 422


def test_a_rule_changed_after_it_was_proved_is_unproven_again(
    client, admin, add_case, add_event, attack_row, plain_row
):
    content = {
        "title": "Office starts PowerShell",
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.t1059.001"],
        "detection": {
            "selection": {"CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    }
    record = _rule("r2", "Office starts PowerShell", ["T1059.001"], content=content)
    sync_source("repo:rules", [record])
    with unit_of_work() as session:
        rule_id = session.execute(text("SELECT id FROM detection_rules")).scalar_one()
    add_event(attack_row, mitre="T1059.001")
    add_event(plain_row)

    view = _post(client, "/proposals/from-rule", {"rule_id": rule_id})
    assert view["rule_id"] == rule_id
    assert view["technique"] == "T1059.001"
    pid = view["proposal_id"]
    again = _post(client, "/proposals/from-rule", {"rule_id": rule_id})
    assert again["proposal_id"] == pid
    _post(client, f"/proposals/{pid}/lint")
    view = _post(client, f"/proposals/{pid}/replay")
    assert view["latest"]["replay"]["evidence"]["attack_basis"] == "labelled T1059.001"
    assert _state(_get(client, "/coverage"), "T1059.001")["state"] == "validated"

    changed = _rule(
        "r2",
        "Office starts PowerShell",
        ["T1059.001"],
        content=content,
        query="changed",
    )
    sync_source("repo:rules", [changed])
    assert _state(_get(client, "/coverage"), "T1059.001")["state"] == "unproven"


def test_a_tuned_copy_does_not_prove_the_rule_it_started_from(
    client, admin, add_event, attack_row, plain_row
):
    content = {
        "title": "Office starts PowerShell",
        "logsource": {"category": "process_creation", "product": "windows"},
        "tags": ["attack.t1059.001"],
        "detection": {
            "selection": {"CommandLine|contains": "-enc"},
            "condition": "selection",
        },
    }
    sync_source(
        "repo:rules",
        [_rule("r4", "Office starts PowerShell", ["T1059.001"], content=content)],
    )
    with unit_of_work() as session:
        rule_id = session.execute(text("SELECT id FROM detection_rules")).scalar_one()
    add_event(attack_row, mitre="T1059.001")
    add_event(plain_row)
    pid = _post(client, "/proposals/from-rule", {"rule_id": rule_id})["proposal_id"]
    _post(client, f"/proposals/{pid}/lint")
    _post(client, f"/proposals/{pid}/replay")
    assert _state(_get(client, "/coverage"), "T1059.001")["state"] == "validated"
    body = {
        "field": "ParentImage",
        "match": "contains",
        "values": ["explorer"],
        "reason": "Shell launches",
    }
    view = _post(client, f"/proposals/{pid}/tune", body)
    assert view["state"] == "replayed" and view["rule_id"] is None
    assert _state(_get(client, "/coverage"), "T1059.001")["state"] == "unproven"


def test_only_a_sigma_rule_can_be_proved_on_log_events(client, admin):
    sync_source("repo:rules", [_rule("r3", "A search", ["T1003"], language="splunk")])
    with unit_of_work() as session:
        rule_id = session.execute(text("SELECT id FROM detection_rules")).scalar_one()
    body = _post(client, "/proposals/from-rule", {"rule_id": rule_id}, status=422)
    assert "Only a Sigma rule" in body["detail"]["message"]


def test_rule_health_names_each_problem_where_it_is_known(
    client, admin, add_event, plain_row
):
    add_event(plain_row)
    sigma = lambda name, field: {  # noqa: E731
        "title": name,
        "detection": {
            "selection": {f"{field}|contains": "x"},
            "condition": "selection",
        },
    }
    sync_source(
        "repo:rules",
        [
            _rule(
                "h1", "Reads a logged field", ["T1059.001"], content=sigma("a", "Image")
            ),
            _rule(
                "h2", "Reads an unlogged field", ["T1003"], content=sigma("b", "Sha256")
            ),
            _rule("h3", "No technique", [], content=sigma("c", "Image")),
        ],
    )
    sync_source(
        "elastic",
        [
            _rule(
                "h4",
                "Broken in Kibana",
                ["T1021"],
                language="elastic",
                runs={"result": "fail", "reason": "index not found"},
            ),
            _rule(
                "h5", "Off in Kibana", ["T1021"], language="elastic", status="disabled"
            ),
        ],
    )
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO findings (finding_id, title, data_source, timestamp) "
                "VALUES ('f-h1', 'Reads a logged field', 'sysmon', now() - interval '1 day')"
            )
        )
    health = _get(client, "/rules")
    rows = {row["name"]: row for row in health["rules"]}
    assert (health["total"], health["mapped"]) == (5, 4)
    assert rows["Broken in Kibana"]["health"] == "fails_to_run"
    assert rows["Broken in Kibana"]["why"] == "index not found"
    assert rows["Off in Kibana"]["health"] == "disabled"
    assert rows["Reads an unlogged field"]["health"] == "missing_field"
    assert rows["Reads an unlogged field"]["missing_fields"] == ["Sha256"]
    assert (
        rows["Reads an unlogged field"]["why"]
        == "Absent from the newest 2,000 stored events: Sha256."
    )
    assert rows["Reads a logged field"]["health"] == "fires"
    assert rows["Reads a logged field"]["fires"] == 1
    assert rows["No technique"]["health"] == "never_fired"
    assert health["rules"][0]["name"] == "Broken in Kibana"
    assert health["fields_known"] is True
    assert "whose alerts do not reach Vigil" in health["limits"]


def test_log_sources_reports_what_is_stored_and_what_is_absent(
    client, admin, add_event, plain_row
):
    add_event(plain_row, source="sysmon")
    add_event({"query": "a.test"}, source="dns", event_class="DNS Activity")
    add_event({"query": "b.test"}, source="dns", event_class="DNS Activity")
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO federation_sources (source_id, enabled) "
                "VALUES ('crowdstrike', true)"
            )
        )
    sources = _get(client, "/log-sources")
    assert sources["total_rows"] == 3
    assert sources["stored"][0] == {
        **sources["stored"][0],
        "source": "dns",
        "event_class": "DNS Activity",
        "rows": 2,
    }
    kinds = {kind["kind"]: kind for kind in sources["kinds"]}
    assert kinds["DNS"]["rows"] == 2
    assert kinds["Mail"] == {"kind": "Mail", "rows": 0, "configured": False}
    assert kinds["Process and EDR"]["configured"] is True
    assert sources["configured"][0]["source_id"] == "crowdstrike"


def test_red_team_marks_each_step_and_tells_a_miss_from_no_way_to_join(client, admin):
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO findings (finding_id, title, data_source, timestamp, "
                "entity_context) VALUES "
                "('f-r', 'Rule alert', 'sysmon', '2026-10-01T10:05:00', "
                '\'{"hostname": "wks-test-1", "rule_name": "A rule"}\'), '
                "('f-l', 'LogLM alert', 'loglm', '2026-10-01T10:06:00', "
                '\'{"hostname": "wks-test-2"}\'), '
                "('f-b1', 'Rule alert', 'sysmon', '2026-10-01T10:07:00', "
                '\'{"hostname": "wks-test-3"}\'), '
                "('f-b2', 'LogLM alert', 'loglm', '2026-10-01T10:07:00', "
                '\'{"hostname": "wks-test-3"}\')'
            )
        )
    start = "2026-10-01T10:00:00Z"
    events = [
        {
            "id": "s1",
            "technique_id": "T1059.001",
            "hostname": "wks-test-1",
            "started_at": start,
        },
        {
            "id": "s2",
            "technique_id": "T1003",
            "hostname": "wks-test-2",
            "started_at": start,
        },
        {
            "id": "s3",
            "technique_id": "T1021",
            "hostname": "wks-test-3",
            "started_at": start,
        },
        {
            "id": "s4",
            "technique_id": "T1566",
            "hostname": "wks-test-9",
            "started_at": start,
        },
        {"id": "s5", "technique_id": "T1486"},
        {
            "Execution Time (UTC)": start,
            "Technique": "t1136",
            "Test Name": "Create a local account",
            "Hostname": "wks-test-1",
            "Username": "tester",
        },
    ]
    run = _post(client, "/red-team", {"name": "Quarterly run", "events": events})
    assert [s["verdict"] for s in run["steps"]] == [
        "rule",
        "loglm",
        "both",
        "missed",
        "missed",
        "rule",
    ]
    assert [s["could_not_correlate"] for s in run["steps"]] == [
        False,
        False,
        False,
        False,
        True,
        False,
    ]
    assert run["counts"] == {"rule": 2, "loglm": 1, "both": 1, "missed": 2}
    assert run["steps"][5]["technique_id"] == "T1136"
    assert run["steps"][5]["name"] == "Create a local account"
    assert run["steps"][0]["citations"][0]["rule_name"] == "A rule"
    assert run["uploaded_by"] == "de-admin"
    assert _get(client, "/red-team")["runs"][0]["name"] == "Quarterly run"
    assert client.post(f"{BASE}/red-team", json={"events": []}).status_code == 422
    _post(client, "/red-team", {"events": [1]}, status=422)


def test_a_viewer_can_read_a_proposal_but_not_move_it(client, admin):
    from core.storage.models import User
    from services.api.middleware.auth import get_current_user

    pid = _post(client, "/proposals", {"sigma": RULE})["proposal_id"]
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO principals (principal_id, kind, label) "
                "VALUES ('person:de-viewer', 'person', 'de-viewer') ON CONFLICT DO NOTHING"
            )
        )
        session.execute(
            text(
                "INSERT INTO users (user_id, username, email, password_hash, full_name, "
                "role_id, is_active, mfa_enabled, principal_id) VALUES ('de-viewer', "
                "'de-viewer', 'de-viewer@test.local', '', 'DE Viewer', 'role-viewer', true, "
                "false, 'person:de-viewer') ON CONFLICT (user_id) DO NOTHING"
            )
        )
    viewer = User(
        user_id="de-viewer",
        username="de-viewer",
        email="de-viewer@test.local",
        password_hash="",
        full_name="DE Viewer",
        role_id="role-viewer",
        is_active=True,
        mfa_enabled=False,
        principal_id="person:de-viewer",
    )
    client.app.dependency_overrides[get_current_user] = lambda: viewer
    assert _get(client, f"/proposals/{pid}")["state"] == "draft"
    assert client.post(f"{BASE}/proposals/{pid}/lint").status_code == 403


def _kinds(client):
    return {kind["kind"]: kind for kind in _get(client, "/log-sources")["kinds"]}


def test_a_windows_sign_in_log_does_not_paint_identity_or_edr(
    client, admin, add_event, plain_row
):
    add_event(plain_row, source="winsec", event_class="Authentication")
    add_event(plain_row, source="winsec", event_class="Process")
    kinds = _kinds(client)
    assert kinds["Windows events"]["rows"] == 2
    assert kinds["Identity"]["rows"] == 0
    assert kinds["Process and EDR"]["rows"] == 0


def test_a_log_kind_matches_a_whole_word_of_a_source_or_class(
    client, admin, add_event, plain_row
):
    add_event(plain_row, source="dnsmasq-logs", event_class="Other")
    add_event(plain_row, source="mailroom", event_class="Other")
    add_event(plain_row, source="palo-flow", event_class="Other")
    add_event(plain_row, source="x", event_class="DNS Activity")
    add_event(plain_row, source="y", event_class="Network Activity")
    add_event(plain_row, source="okta", event_class="Other")
    kinds = _kinds(client)
    assert kinds["DNS"]["rows"] == 1
    assert kinds["Mail"]["rows"] == 0
    assert kinds["Network flow"]["rows"] == 2
    assert kinds["Identity"]["rows"] == 1


def test_a_configured_source_matches_as_a_whole_word_too(client, admin):
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO federation_sources (source_id, enabled) "
                "VALUES ('microsoft_defender', true), ('mailguard', true)"
            )
        )
    kinds = _kinds(client)
    assert kinds["Process and EDR"]["configured"] is True
    assert kinds["Mail"]["configured"] is False


@pytest.mark.parametrize(
    "validated, counted, percent",
    [(199, 200, 99), (1, 3, 33), (2, 3, 66), (200, 200, 100), (0, 5, 0)],
)
def test_percent_validated_rounds_down_and_is_100_only_when_all_are(
    validated, counted, percent
):
    from core.detections.engineering.program import _summary

    rows = [
        {"state": "validated" if i < validated else "unproven", "priority": False}
        for i in range(counted)
    ]
    assert _summary(rows, set())["percent_validated"] == percent


def test_seen_counts_each_technique_in_the_database(client, admin):
    from sqlalchemy import event

    from core.detections.engineering.program import _seen
    from core.storage.connection import get_db_manager

    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO findings (finding_id, title, data_source, severity, timestamp) "
                "SELECT 'seen-' || g, 'Seen', 'sample', 'low', now() "
                "FROM generate_series(1, 2000) g"
            )
        )
        session.execute(
            text(
                "INSERT INTO finding_mitre_predictions (finding_id, technique_id) "
                "SELECT 'seen-' || g, 'T1059' FROM generate_series(1, 2000) g"
            )
        )
    fetched = []

    def count(_conn, cursor, _statement, _params, _context, _many):
        fetched.append(max(cursor.rowcount, 0))

    engine = get_db_manager().engine
    event.listen(engine, "after_cursor_execute", count)
    try:
        with unit_of_work() as session:
            seen = _seen(session)
    finally:
        event.remove(engine, "after_cursor_execute", count)
    assert seen == {"T1059": 2000}
    assert sum(fetched) < 20


def test_a_replay_window_is_hours_and_a_promotion_can_name_one(client, admin):
    made = _post(client, "/proposals", {"sigma": RULE})
    pid = made["proposal_id"]
    _post(client, f"/proposals/{pid}/lint")
    _post(client, f"/proposals/{pid}/replay", {"window_hours": 0}, status=422)
    _post(
        client, f"/proposals/{pid}/live", {"reason": "x", "window_hours": 0}, status=422
    )
    assert (
        client.get(f"{BASE}/proposals/{pid}/shadow-report?window_hours=0").status_code
        == 422
    )
