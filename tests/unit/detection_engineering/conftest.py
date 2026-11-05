"""These tests run against the throwaway Postgres named by VIGIL_TEST_POSTGRES_PORT, migrated with
``python -m core.upgrade``. Without it they skip and the root conftest's block stays, so they can
never reach an instance's database.
"""

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import pytest

# Startup skips the external integrations (MCP servers, Bifrost, Redis) under this flag.
os.environ["TESTING"] = "true"

RULE = """
title: Office application starts encoded PowerShell
status: experimental
description: An Office application starts PowerShell with an encoded command.
level: high
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\\WINWORD.EXE'
      - '\\EXCEL.EXE'
  selection_child:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection_parent and selection_child
falsepositives:
  - Signed macros that call PowerShell
"""


def pytest_collection_modifyitems(items):
    if os.environ.get("VIGIL_TEST_POSTGRES_PORT"):
        return
    skip = pytest.mark.skip(reason="needs VIGIL_TEST_POSTGRES_PORT: see this conftest")
    for item in items:
        if "tests/unit/detection_engineering/" in str(item.path) and (
            item.get_closest_marker("database")
        ):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _no_ambient_postgres(monkeypatch, tmp_path):
    port = os.environ.get("VIGIL_TEST_POSTGRES_PORT")
    if port:
        monkeypatch.setenv("POSTGRES_HOST", "127.0.0.1")
        monkeypatch.setenv("POSTGRES_PORT", port)
    else:
        monkeypatch.setenv("POSTGRES_HOST", "postgres-blocked-in-unit-tests.invalid")
        monkeypatch.setenv("POSTGRES_PORT", "1")
    monkeypatch.setenv("POSTGRES_PASSWORD", "throwaway-test-database")
    monkeypatch.setenv("VIGIL_DIR", str(tmp_path))
    monkeypatch.delenv("POSTGRESQL_CONNECTION_STRING", raising=False)
    monkeypatch.setattr(
        "core.storage.connection._load_connection_string_secret", lambda: None
    )
    from core.config import get_settings

    get_settings.cache_clear()
    yield


@pytest.fixture
def db():
    """An initialized manager and no detection engineering rows left behind."""
    from sqlalchemy import text

    from core.storage.connection import get_db_manager
    from core.storage.unit_of_work import unit_of_work

    get_db_manager().initialize()

    def clean():
        with unit_of_work() as session:
            session.execute(text("DELETE FROM detection_proposal_events"))
            session.execute(text("DELETE FROM detection_proposals"))
            session.execute(text("DELETE FROM log_events"))
            session.execute(text("DELETE FROM detection_rule_stages"))
            session.execute(text("DELETE FROM detection_rule_versions"))
            session.execute(text("DELETE FROM detection_rules"))
            session.execute(text("DELETE FROM finding_mitre_predictions"))
            session.execute(text("DELETE FROM case_findings"))
            session.execute(text("DELETE FROM findings"))
            session.execute(text("DELETE FROM cases WHERE case_id LIKE 'case-de-%'"))
            session.execute(
                text(
                    "DELETE FROM system_config WHERE key LIKE 'detection_engineering.%'"
                )
            )
            session.execute(text("DELETE FROM federation_sources"))

    clean()
    yield
    clean()


@pytest.fixture
def person():
    """A signed-in person, as get_current_user notes one for the request."""
    from core.cases.agent_closure import clear_http_actor, note_http_actor

    note_http_actor(
        username="dana.reviewer", principal_id=None, via="cookie", person=True
    )
    yield "dana.reviewer"
    clear_http_actor()


@pytest.fixture
def add_event(db):
    """Insert one log_events row."""
    from core.storage.models import LogEvent
    from core.storage.unit_of_work import unit_of_work

    def add(
        raw: Dict[str, Any],
        *,
        case_id: Optional[str] = None,
        source: str = "sysmon",
        event_class: str = "Process Activity",
        mitre: Optional[str] = None,
        age_days: float = 1,
        summary: str = "process started",
    ) -> str:
        event_id = uuid.uuid4().hex
        with unit_of_work() as session:
            session.add(
                LogEvent(
                    event_id=event_id,
                    time=datetime.now(timezone.utc) - timedelta(days=age_days),
                    source=source,
                    event_class=event_class,
                    severity="info",
                    summary=summary,
                    mitre=mitre,
                    case_id=case_id,
                    raw=raw,
                    tags=[],
                    search_text=summary.lower(),
                )
            )
        return event_id

    return add


@pytest.fixture
def add_case(db):
    from core.storage.models import Case
    from core.storage.unit_of_work import unit_of_work

    def add(case_id: str = "case-de-1") -> str:
        with unit_of_work() as session:
            session.add(
                Case(case_id=case_id, title="Macro to PowerShell on a test host")
            )
        return case_id

    return add


@pytest.fixture
def attack_row():
    return {
        "ParentImage": "C:\\Program Files\\Office\\WINWORD.EXE",
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgA",
    }


@pytest.fixture
def signed_macro_row():
    return {
        "ParentImage": "C:\\Program Files\\Office\\EXCEL.EXE",
        "ParentCommandLine": "EXCEL.EXE \\\\files\\trusted-macros\\report.xlsm",
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -enc UABpAG4AZwA=",
    }


@pytest.fixture
def plain_row():
    return {
        "ParentImage": "C:\\Windows\\explorer.exe",
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile",
    }


@pytest.fixture
def client(db):
    from fastapi.testclient import TestClient

    from services.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin(client):
    """Every request is a real admin row, so permission gates still run, and a signed-in person."""
    from sqlalchemy import text

    from core.cases.agent_closure import note_http_actor
    from core.storage.models import User
    from core.storage.unit_of_work import unit_of_work
    from services.api.middleware.auth import get_current_active_user, get_current_user

    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO principals (principal_id, kind, label) "
                "VALUES ('person:de-admin', 'person', 'de-admin') ON CONFLICT DO NOTHING"
            )
        )
        session.execute(
            text(
                "INSERT INTO users (user_id, username, email, password_hash, full_name, "
                "role_id, is_active, mfa_enabled, principal_id) VALUES ('de-admin', "
                "'de-admin', 'de-admin@test.local', '', 'DE Admin', 'role-admin', true, "
                "false, 'person:de-admin') ON CONFLICT (user_id) DO NOTHING"
            )
        )
    user = User(
        user_id="de-admin",
        username="de-admin",
        email="de-admin@test.local",
        password_hash="",
        full_name="DE Admin",
        role_id="role-admin",
        is_active=True,
        mfa_enabled=False,
        principal_id="person:de-admin",
    )

    async def signed_in():
        note_http_actor(
            username=user.username,
            principal_id=user.principal_id,
            via="cookie",
            person=True,
        )
        return user

    client.app.dependency_overrides[get_current_user] = signed_in
    client.app.dependency_overrides[get_current_active_user] = signed_in
    yield user
    client.app.dependency_overrides.pop(get_current_user, None)
    client.app.dependency_overrides.pop(get_current_active_user, None)
