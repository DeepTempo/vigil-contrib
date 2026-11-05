"""Who may see what a rule was tested on. Detection permissions alone do not open logs or cases."""

import pytest
from sqlalchemy import text

from core.detections.engineering import proposals
from core.storage.models import User
from core.storage.unit_of_work import unit_of_work
from services.api.middleware.auth import get_current_active_user, get_current_user

from .conftest import RULE

pytestmark = pytest.mark.database

BASE = "/api/detection-engineering"


@pytest.fixture
def sign_in_with(client):
    """A person whose role holds exactly these permissions."""

    def as_role(*permissions):
        short = "-".join(
            p.replace("detections.", "d").replace(".read", "r") for p in permissions
        )
        role = f"role-de-{short}"[:50]
        name = f"de-{short}"[:50]
        granted = "{" + ", ".join(f'"{p}": true' for p in permissions) + "}"
        with unit_of_work() as session:
            session.execute(
                text(
                    "INSERT INTO roles (role_id, name, description, permissions, "
                    "is_system_role) VALUES (:r, :r, 'test', :g, false) "
                    "ON CONFLICT (role_id) DO NOTHING"
                ),
                {"r": role, "g": granted},
            )
            session.execute(
                text(
                    "INSERT INTO principals (principal_id, kind, label) "
                    "VALUES (:p, 'person', :n) ON CONFLICT DO NOTHING"
                ),
                {"p": f"person:{name}", "n": name},
            )
            session.execute(
                text(
                    "INSERT INTO users (user_id, username, email, password_hash, full_name, "
                    "role_id, is_active, mfa_enabled, principal_id) VALUES (:n, :n, :e, '', "
                    ":n, :r, true, false, :p) ON CONFLICT (user_id) DO NOTHING"
                ),
                {
                    "n": name,
                    "e": f"{name}@test.local",
                    "r": role,
                    "p": f"person:{name}",
                },
            )
        user = User(
            user_id=name,
            username=name,
            email=f"{name}@test.local",
            password_hash="",
            full_name=name,
            role_id=role,
            is_active=True,
            mfa_enabled=False,
            principal_id=f"person:{name}",
        )
        client.app.dependency_overrides[get_current_user] = lambda: user
        client.app.dependency_overrides[get_current_active_user] = lambda: user
        return client

    yield as_role
    client.app.dependency_overrides.pop(get_current_user, None)
    client.app.dependency_overrides.pop(get_current_active_user, None)


@pytest.fixture
def replayed_on_a_case(add_case, add_event, attack_row, signed_macro_row, plain_row):
    case_id = add_case()
    add_event(attack_row, case_id=case_id, summary="secret attack row")
    add_event(signed_macro_row, summary="secret other row")
    add_event(plain_row)
    view = proposals.create(sigma=RULE, actor="dana.reviewer", case_id=case_id)
    view = proposals.lint(view["proposal_id"], "dana.reviewer")
    return proposals.replay(view["proposal_id"], "dana.reviewer")


DETECTIONS = ("detections.read", "detections.write")


@pytest.mark.parametrize(
    "body, needs",
    [
        ({"case_id": "case-de-1"}, "cases.read"),
        ({"case_id": "case-de-1"}, "findings.read"),
        ({"finding_id": "f-1"}, "findings.read"),
    ],
)
def test_drafting_from_a_case_or_finding_needs_the_right_to_read_it(
    sign_in_with, add_case, body, needs
):
    add_case()
    others = {"cases.read", "findings.read"} - {needs}
    client = sign_in_with(*DETECTIONS, *sorted(others))
    answer = client.post(f"{BASE}/proposals/draft", json=body)
    assert answer.status_code == 403
    assert needs in answer.json()["detail"]


def test_pasting_a_rule_onto_a_case_needs_the_right_to_read_that_case(
    sign_in_with, add_case
):
    add_case()
    client = sign_in_with(*DETECTIONS)
    refused = client.post(
        f"{BASE}/proposals", json={"sigma": RULE, "case_id": "case-de-1"}
    )
    assert refused.status_code == 403
    assert client.post(f"{BASE}/proposals", json={"sigma": RULE}).status_code == 200


def test_replaying_shows_log_rows_so_it_needs_findings_read(
    sign_in_with, replayed_on_a_case
):
    pid = replayed_on_a_case["proposal_id"]
    client = sign_in_with(*DETECTIONS)
    assert client.post(f"{BASE}/proposals/{pid}/replay", json={}).status_code == 403
    assert client.get(f"{BASE}/proposals/{pid}/shadow-report").status_code == 403


def test_replaying_a_rule_on_a_case_needs_cases_read_too(
    sign_in_with, replayed_on_a_case
):
    pid = replayed_on_a_case["proposal_id"]
    client = sign_in_with(*DETECTIONS, "findings.read")
    assert client.post(f"{BASE}/proposals/{pid}/replay", json={}).status_code == 403
    client = sign_in_with(*DETECTIONS, "findings.read", "cases.read")
    assert client.post(f"{BASE}/proposals/{pid}/replay", json={}).status_code == 200


def test_stored_replay_samples_are_withheld_from_a_reader_without_findings_read(
    sign_in_with, replayed_on_a_case
):
    pid = replayed_on_a_case["proposal_id"]
    assert replayed_on_a_case["latest"]["replay"]["evidence"]["hit_samples"]

    client = sign_in_with("detections.read")
    answer = client.get(f"{BASE}/proposals/{pid}")
    assert answer.status_code == 200
    assert "secret" not in answer.text
    evidence = answer.json()["latest"]["replay"]["evidence"]
    assert evidence["hit_samples"] == []
    assert evidence["false_positive_samples"] == []
    assert evidence["samples_withheld"] is True
    assert (evidence["hits"], evidence["false_positives"]) == (1, 1)
    assert all(
        e["evidence"].get("hit_samples", []) == [] for e in answer.json()["events"]
    )


def test_a_reader_without_cases_read_does_not_see_which_case_a_rule_came_from(
    sign_in_with, replayed_on_a_case
):
    pid = replayed_on_a_case["proposal_id"]
    client = sign_in_with("detections.read", "findings.read")
    answer = client.get(f"{BASE}/proposals/{pid}")
    assert "case-de-1" not in answer.text
    assert answer.json()["case_id"] is None
    listed = client.get(f"{BASE}/proposals")
    assert "case-de-1" not in listed.text


def test_a_reader_with_both_sees_the_samples_and_the_case(
    sign_in_with, replayed_on_a_case
):
    pid = replayed_on_a_case["proposal_id"]
    client = sign_in_with("detections.read", "findings.read", "cases.read")
    body = client.get(f"{BASE}/proposals/{pid}").json()
    assert body["case_id"] == "case-de-1"
    evidence = body["latest"]["replay"]["evidence"]
    assert evidence["hit_samples"][0]["summary"] == "secret attack row"
    assert "samples_withheld" not in evidence


def test_a_red_team_run_cites_findings_so_reading_them_needs_findings_read(
    sign_in_with, client
):
    from core.detections.engineering.program import RED_TEAM_KEY
    from core.storage.config_service import ConfigService

    ConfigService("seed").set_system_config(
        RED_TEAM_KEY,
        {"runs": [{"name": "r", "steps": [{"citations": [{"finding_id": "f-9"}]}]}]},
        description="test",
    )
    reader = sign_in_with("detections.read")
    assert "f-9" not in reader.get(f"{BASE}/red-team").text
    upload = {"events": [{"technique_id": "T1059"}]}
    writer = sign_in_with(*DETECTIONS)
    assert writer.post(f"{BASE}/red-team", json=upload).status_code == 403
