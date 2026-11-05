"""The incident and alert triage routes on real Postgres, with real roles and approvals."""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

from core.response.approval_service import ActionType, ApprovalService
from core.storage.models import (
    Case,
    CaseClosureInfo,
    CaseIOC,
    DetectionRule,
    EpisodicVerdict,
    Finding,
    FindingMitrePrediction,
    Investigation,
    LogEvent,
    WorkflowRun,
)
from core.storage.unit_of_work import unit_of_work
from core.time import utcnow

pytestmark = pytest.mark.database

ADMIN, VIEWER, NOBODY = "role-admin", "role-viewer", "role-inc-none"
SECRET_TITLE = "Payroll share copied out"


def add_finding(session, finding_id, title="Failed login for dana", **fields):
    fields.setdefault("data_source", "edr")
    fields.setdefault("entity_context", {"hostnames": ["wks-7"]})
    row = Finding(finding_id=finding_id, title=title, **fields)
    session.add(row)
    return row


def add_incident(
    case_id="case-inc", title=SECRET_TITLE, status="open", findings=("f-1", "f-2")
):
    with unit_of_work() as session:
        rows = [
            add_finding(
                session,
                fid,
                title=f"Alert {fid}",
                timestamp=utcnow() + timedelta(minutes=i),
            )
            for i, fid in enumerate(findings)
        ]
        session.flush()
        session.add(
            Case(
                case_id=case_id,
                title=title,
                status=status,
                priority="high",
                timeline=[],
                findings=rows,
            )
        )
    return case_id


def propose(case_id, action_type=ActionType.BLOCK_IP, **fields):
    return ApprovalService().create_action(
        action_type=action_type,
        title="Block the beacon target",
        description="Stop the traffic",
        target="198.51.100.7",
        confidence=0.6,
        reason="Beaconing seen",
        evidence=[],
        created_by="agent",
        parameters={"case_id": case_id},
        human_only=True,
        **fields,
    )


def test_a_clean_install_has_no_incidents(client, sign_in):
    sign_in(ADMIN)
    answer = client.get("/api/incidents")
    assert answer.status_code == 200
    assert answer.json() == {"total": 0, "items": []}


def test_a_case_with_one_alert_is_not_an_incident_and_the_refusal_says_why(
    client, sign_in
):
    sign_in(ADMIN)
    add_incident(findings=("only",))
    assert client.get("/api/incidents").json()["total"] == 0
    answer = client.get("/api/incidents/case-inc")
    assert answer.status_code == 404
    assert "has 1 alert" in answer.json()["detail"]
    assert "2 or more" in answer.json()["detail"]


def test_an_unknown_case_is_404(client, sign_in):
    sign_in(ADMIN)
    assert client.get("/api/incidents/case-nothing").status_code == 404


def test_a_role_without_the_read_gets_404_and_no_title(client, sign_in):
    add_incident()
    sign_in(NOBODY)
    for path in (
        "/api/incidents",
        "/api/incidents/case-inc",
        "/api/incidents/case-nothing",
    ):
        answer = client.get(path)
        assert answer.status_code == 404
        assert answer.json()["detail"] == "Not found"
        assert SECRET_TITLE not in answer.text


def test_the_list_keeps_open_incidents_unless_asked(client, sign_in):
    sign_in(ADMIN)
    add_incident("case-open", findings=("a1", "a2"))
    add_incident("case-shut", status="closed", findings=("b1", "b2"))
    assert [i["case_id"] for i in client.get("/api/incidents").json()["items"]] == [
        "case-open"
    ]
    everything = client.get("/api/incidents", params={"status": "all"}).json()
    assert {i["case_id"] for i in everything["items"]} == {"case-open", "case-shut"}
    assert everything["total"] == 2


def test_the_detail_tells_the_story_from_stored_rows(client, sign_in):
    sign_in(ADMIN)
    add_incident()
    with unit_of_work() as session:
        session.add(
            FindingMitrePrediction(
                finding_id="f-1", technique_id="T1059.001", confidence=0.9
            )
        )
        session.add(
            FindingMitrePrediction(
                finding_id="f-2", technique_id="T1071.001", confidence=0.7
            )
        )
        session.add(
            DetectionRule(
                source="sigma",
                native_key="rule-1",
                name="Encoded shell",
                language="sigma",
                techniques=["T1059.001"],
                status="active",
                latest_version=1,
            )
        )
        session.add(
            CaseIOC(
                case_id="case-inc",
                ioc_type="host",
                value="wks-7",
                threat_level="high",
                source="intel-feed",
            )
        )
        session.add(CaseIOC(case_id="case-inc", ioc_type="ip", value="203.0.113.9"))
        session.add(
            LogEvent(
                event_id="ev-1",
                time=utcnow(),
                source="dns",
                case_id="case-inc",
                loglm=0.95,
            )
        )
    story = client.get("/api/incidents/case-inc").json()
    assert story["alerts"] == 2
    assert [s["finding_id"] for s in story["steps"]] == ["f-1", "f-2"]
    assert story["steps"][0]["coverage"] == "rule_declared"
    assert story["steps"][0]["caught_by"] == "Encoded shell"
    assert [s["finding_id"] for s in story["unmatched_steps"]] == ["f-2"]
    assert story["log_events"] == 1
    assert story["rules_loaded"] == 1
    assert [i["value"] for i in story["intel"]] == ["wks-7"]
    reasons = {r["kind"] for r in story["reasons"]}
    assert {
        "shared_entity",
        "technique_chain",
        "flagged_intel",
        "log_events",
    } <= reasons
    assert story["verdict"]["value"] == "undetermined"
    assert story["report"] is None


def test_a_persons_closure_reads_back_as_the_verdict(client, sign_in):
    sign_in(ADMIN)
    add_incident(status="closed")
    with unit_of_work() as session:
        session.add(
            CaseClosureInfo(
                case_id="case-inc",
                closure_category="resolved",
                closed_by="dana",
                closed_by_text="dana",
                close_channel="cookie",
            )
        )
    verdict = client.get("/api/incidents/case-inc").json()["verdict"]
    assert verdict["value"] == "true_positive"
    assert verdict["by"] == "person"


def test_a_runs_report_and_proven_verdict_are_read_and_labelled(client, sign_in):
    sign_in(ADMIN)
    add_incident()
    at = utcnow()
    with unit_of_work() as session:
        session.add(
            WorkflowRun(
                run_id="run-inc",
                workflow_id="wf",
                workflow_name="Hunt",
                status="completed",
                trigger_context={"case_id": "case-inc"},
                result_summary="The model wrote this about the case.",
                started_at=at - timedelta(minutes=5),
                finished_at=at,
            )
        )
        session.add(
            Investigation(
                investigation_id="inv-old",
                case_id="case-inc",
                workflow_id="wf",
                trigger_type="finding",
                status="completed",
                workdir="/nowhere",
                master_review_notes="An older note.",
                completed_at=at - timedelta(days=1),
            )
        )
        session.add(
            EpisodicVerdict(
                investigation_kind="hunt",
                investigation_id="run-inc",
                hypothesis_id="h-1",
                statement="Lateral movement happened.",
                outcome="proven",
                rationale="Both hosts ran the tool.",
                attacker_influenceable_only=False,
                trust="agent",
                first_seen=at,
                last_seen=at,
                window_source="observed",
                concluded_at=at,
            )
        )
    story = client.get("/api/incidents/case-inc").json()
    assert story["report"]["text"] == "The model wrote this about the case."
    assert story["report"]["origin"] == "workflow_run"
    assert story["report"]["ref"] == "run-inc"
    assert story["verdict"]["value"] == "true_positive"
    assert story["verdict"]["by"] == "agent"
    assert "Both hosts ran the tool." in story["verdict"]["model_words"]
    listed = client.get("/api/incidents").json()["items"][0]
    assert listed["verdict"]["value"] == "true_positive"


def test_approving_goes_through_the_real_route_and_reads_back(client, sign_in):
    add_incident()
    action = propose("case-inc")

    sign_in(VIEWER)
    story = client.get("/api/incidents/case-inc").json()
    assert story["viewer"] == {"can_read_approvals": True, "can_decide": False}
    assert story["actions"][0]["status"] == "pending"
    assert story["actions"][0]["effect"] == "record_only"
    assert (
        client.post(f"/api/approvals/{action.action_id}/approve", json={}).status_code
        == 403
    )
    assert (
        client.get("/api/incidents/case-inc").json()["actions"][0]["status"]
        == "pending"
    )

    user = sign_in(ADMIN)
    listed = client.get("/api/incidents").json()["items"][0]
    assert listed["pending_approvals"] == 1
    assert (
        client.post(f"/api/approvals/{action.action_id}/approve", json={}).status_code
        == 200
    )

    story = client.get("/api/incidents/case-inc").json()
    assert story["viewer"]["can_decide"] is True
    assert story["actions"][0]["status"] == "approved"
    assert story["actions"][0]["approved_by"] == user.username
    assert [
        r["evidence"][0]["ref"]
        for r in story["reasons"]
        if r["kind"] == "person_approved"
    ] == [action.action_id]
    assert client.get("/api/incidents").json()["items"][0]["pending_approvals"] == 0


def test_an_approval_on_another_case_is_not_shown(client, sign_in):
    sign_in(ADMIN)
    add_incident()
    add_incident("case-other", findings=("o1", "o2"))
    propose("case-other")
    assert client.get("/api/incidents/case-inc").json()["actions"] == []


def test_an_approval_citing_this_cases_alert_is_shown(client, sign_in):
    sign_in(ADMIN)
    add_incident()
    created = ApprovalService().create_action(
        action_type=ActionType.ISOLATE_HOST,
        title="Isolate wks-7",
        description="Contain it",
        target="wks-7",
        confidence=0.6,
        reason="Beaconing seen",
        evidence=["f-1"],
        created_by="agent",
        human_only=True,
    )
    actions = client.get("/api/incidents/case-inc").json()["actions"]
    assert [a["action_id"] for a in actions] == [created.action_id]
    assert actions[0]["effect"] == "no_executor"
    assert [e["ref"] for e in actions[0]["evidence"]] == ["f-1"]


def test_alert_triage_groups_by_kind_with_real_outcomes(client, sign_in):
    sign_in(ADMIN)
    now = utcnow()
    with unit_of_work() as session:
        add_finding(
            session,
            "k-1",
            title="Failed login for dana",
            severity="high",
            entity_context={"usernames": ["dana"]},
            created_at=now - timedelta(minutes=10),
            noise_marked_at=now - timedelta(minutes=8),
            noise_reason="Known scanner",
        )
        add_finding(
            session,
            "k-2",
            title="Failed login for lee",
            severity="low",
            entity_context={"usernames": ["lee"]},
            created_at=now - timedelta(minutes=9),
            noise_marked_at=now - timedelta(minutes=5),
            noise_reason="Known scanner",
        )
        add_finding(
            session,
            "k-3",
            title="Failed login for sam",
            severity="low",
            entity_context={"usernames": ["sam"]},
            created_at=now - timedelta(minutes=4),
        )
        add_finding(
            session, "old", title="Too old", created_at=now - timedelta(hours=30)
        )
        closed = add_finding(
            session,
            "c-1",
            title="Share access",
            data_source="dns",
            created_at=now - timedelta(minutes=30),
        )
        session.flush()
        session.add(
            Case(
                case_id="case-c",
                title="Closed",
                status="closed",
                timeline=[],
                findings=[closed],
            )
        )
        session.flush()
        session.add(
            CaseClosureInfo(
                case_id="case-c",
                closure_category="resolved",
                closed_by="dana",
                close_channel="cookie",
                closed_at=now - timedelta(minutes=20),
            )
        )

    triage = client.get("/api/alert-triage", params={"hours": 24}).json()
    assert triage["alerts"] == 4
    assert triage["truncated"] is False
    logins, share = triage["kinds"]
    assert logins["key"] == "edr|Failed login for <entity>"
    assert logins["alerts"] == 3
    assert logins["source"] == "edr"
    assert {s["severity"]: s["alerts"] for s in logins["severities"]} == {
        "high": 1,
        "low": 2,
    }
    outcomes = {o["state"]: o["alerts"] for o in logins["outcomes"]}
    assert outcomes == {"dismissed": 2, "waiting": 1}
    assert logins["median_seconds_to_outcome"] == pytest.approx(180, abs=1)
    assert logins["timed_outcomes"] == 2
    assert share["outcomes"][0]["label"] == "Closed by a person"
    assert share["median_seconds_to_outcome"] == pytest.approx(600, abs=1)
    assert share["case_ids"] == ["case-c"]


def test_a_kind_with_no_stored_outcome_time_reports_none(client, sign_in):
    sign_in(ADMIN)
    with unit_of_work() as session:
        add_finding(session, "w-1", title="Port scan")
    kind = client.get("/api/alert-triage").json()["kinds"][0]
    assert kind["median_seconds_to_outcome"] is None
    assert kind["timed_outcomes"] == 0


def test_alert_triage_is_empty_on_a_clean_install_and_gated(client, sign_in):
    sign_in(ADMIN)
    with unit_of_work() as session:
        add_finding(session, "probe:health:today", title=None, data_source="probe")
    empty = client.get("/api/alert-triage").json()
    assert empty["alerts"] == 0
    assert empty["kinds"] == []
    sign_in(NOBODY)
    assert client.get("/api/alert-triage").status_code == 403


def _big_incident(case_id="case-big", count=5000):
    """A case holding ``count`` alerts, from SQL so the test measures the read."""
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO cases (case_id, title, status, priority, timeline) "
                "VALUES (:c, 'Big case', 'open', 'high', '[]'::jsonb)"
            ),
            {"c": case_id},
        )
        session.execute(
            text(
                "INSERT INTO findings (finding_id, title, data_source, severity, timestamp, "
                "entity_context) SELECT 'big-' || g, 'Big alert ' || g, "
                "CASE WHEN g % 2 = 0 THEN 'edr' ELSE 'ndr' END, 'low', "
                "now() + g * interval '1 second', "
                "jsonb_build_object('hostnames', jsonb_build_array('wks-' || g, 'shared-host')) "
                "FROM generate_series(1, :n) g"
            ),
            {"n": count},
        )
        session.execute(
            text(
                "INSERT INTO case_findings (case_id, finding_id, added_at) "
                "SELECT :c, 'big-' || g, now() FROM generate_series(1, :n) g"
            ),
            {"c": case_id, "n": count},
        )
    return case_id


def test_a_huge_case_answers_one_page_of_steps_and_says_how_many(client, sign_in):
    sign_in("role-admin")
    case_id = _big_incident()
    answer = client.get(f"/api/incidents/{case_id}")
    assert answer.status_code == 200, answer.text
    story = answer.json()
    assert story["alerts"] == 5000
    assert story["steps_total"] == 5000
    assert len(story["steps"]) == 200
    assert len(answer.content) < 400_000

    shared = next(e for e in story["entities"] if e["value"] == "shared-host")
    assert shared["named_by"] == 5000
    assert len(shared["finding_ids"]) <= 50
    assert story["entities_total"] == 5001
    assert len(story["entities"]) <= 200


def _fetched_during(work):
    from sqlalchemy import event

    from core.storage.connection import get_db_manager

    fetched = []

    def count(_conn, cursor, _statement, _params, _context, _many):
        fetched.append(max(cursor.rowcount, 0))

    engine = get_db_manager().engine
    event.listen(engine, "after_cursor_execute", count)
    try:
        answer = work()
    finally:
        event.remove(engine, "after_cursor_execute", count)
    return answer, sum(fetched)


def test_the_next_page_of_steps_is_read_in_the_database(client, sign_in):
    sign_in("role-admin")
    case_id = _big_incident()
    answer, fetched = _fetched_during(
        lambda: client.get(
            f"/api/incidents/{case_id}/steps", params={"offset": 200, "limit": 50}
        )
    )
    assert answer.status_code == 200, answer.text
    page = answer.json()
    assert (page["total"], page["offset"], len(page["steps"])) == (5000, 200, 50)
    assert page["steps"][0]["finding_id"] == "big-201"
    assert fetched < 200
    assert (
        client.get(
            f"/api/incidents/{case_id}/steps", params={"limit": 100_000}
        ).status_code
        == 422
    )


def test_steps_page_in_the_order_the_story_tells_them(client, sign_in):
    sign_in("role-admin")
    case_id = add_incident(findings=("f-3", "f-1", "f-2", "f-4"))
    with unit_of_work() as session:
        session.get(Finding, "f-4").timestamp = None
        session.get(Finding, "f-4").created_at = datetime(2020, 1, 1)
    story = client.get(f"/api/incidents/{case_id}").json()
    pages = [
        step
        for offset in range(4)
        for step in client.get(
            f"/api/incidents/{case_id}/steps", params={"offset": offset, "limit": 1}
        ).json()["steps"]
    ]
    assert pages == story["steps"]


def test_the_steps_of_something_that_is_not_an_incident_answer_like_its_story(
    client, sign_in
):
    sign_in("role-admin")
    case_id = add_incident(findings=("only-one",))
    assert client.get(f"/api/incidents/{case_id}/steps").status_code == 404
    assert client.get("/api/incidents/case-nothing/steps").status_code == 404


def test_the_steps_need_the_same_read_as_the_story(client, sign_in):
    case_id = add_incident()
    sign_in(NOBODY)
    answer = client.get(f"/api/incidents/{case_id}/steps")
    assert answer.status_code == 404
    assert answer.json()["detail"] == "Not found"


def test_the_list_pages_with_an_offset_and_keeps_its_total(client, sign_in):
    sign_in("role-admin")
    for n in range(3):
        add_incident(f"case-page-{n}", findings=(f"p{n}-1", f"p{n}-2"))
    first = client.get("/api/incidents", params={"limit": 2, "status": "all"}).json()
    rest = client.get(
        "/api/incidents", params={"limit": 2, "offset": 2, "status": "all"}
    ).json()
    assert (first["total"], rest["total"]) == (3, 3)
    assert len(first["items"]) == 2 and len(rest["items"]) == 1
    seen = {row["case_id"] for row in first["items"] + rest["items"]}
    assert seen == {"case-page-0", "case-page-1", "case-page-2"}


def test_the_list_does_not_read_each_alert_of_a_huge_case(client, sign_in):
    from sqlalchemy import event

    from core.storage.connection import get_db_manager

    sign_in("role-admin")
    _big_incident()
    fetched = []

    def count(_conn, cursor, _statement, _params, _context, _many):
        fetched.append(max(cursor.rowcount, 0))

    engine = get_db_manager().engine
    event.listen(engine, "after_cursor_execute", count)
    try:
        body = client.get("/api/incidents").json()
    finally:
        event.remove(engine, "after_cursor_execute", count)
    row = body["items"][0]
    assert row["alerts"] == 5000
    assert {s["source"]: s["alerts"] for s in row["sources"]} == {
        "edr": 2500,
        "ndr": 2500,
    }
    assert row["unmatched_steps"] is None
    assert sum(fetched) < 200


def test_the_lists_counts_agree_with_the_story(client, sign_in):
    from core.storage.models import FindingMitrePrediction

    sign_in("role-admin")
    case_id = add_incident(findings=("f-1", "f-2", "f-3", "f-4"))
    with unit_of_work() as session:
        session.add(FindingMitrePrediction(finding_id="f-1", technique_id="T1059"))
        session.get(Finding, "f-2").anomaly_score = 0.9
        session.get(Finding, "f-3").entity_context = {
            "hostnames": ["wks-7"],
            "rule_name": "Named rule",
        }
    story = client.get(f"/api/incidents/{case_id}").json()
    row = client.get("/api/incidents").json()["items"][0]
    assert row["unmatched_steps"] == story["unmatched_total"] == 2
    assert row["alerts"] == story["alerts"]
    assert row["sources"] == story["sources"]
    assert row["verdict"] == story["verdict"]
