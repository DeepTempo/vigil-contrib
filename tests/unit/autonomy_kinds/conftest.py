"""Per-kind autonomy runs on the throwaway Postgres named by VIGIL_TEST_POSTGRES_PORT,
migrated with ``python -m core.upgrade``. Without it the database tests skip."""

import os
from datetime import datetime, timedelta, timezone

import pytest

os.environ["TESTING"] = "true"

NOW = datetime.now(timezone.utc)
SOURCE = "sample-edr"
TITLE = "Sample scanner touched a share"
ENTITIES = {"hostnames": ["wks-sample-1"]}
PERSON = "person:ka-admin"


def pytest_collection_modifyitems(items):
    if os.environ.get("VIGIL_TEST_POSTGRES_PORT"):
        return
    skip = pytest.mark.skip(reason="needs VIGIL_TEST_POSTGRES_PORT: see this conftest")
    for item in items:
        if "tests/unit/autonomy_kinds/" in str(item.path) and item.get_closest_marker(
            "database"
        ):
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _no_ambient_postgres(monkeypatch):
    port = os.environ.get("VIGIL_TEST_POSTGRES_PORT")
    if port:
        monkeypatch.setenv("POSTGRES_HOST", "127.0.0.1")
        monkeypatch.setenv("POSTGRES_PORT", port)
    else:
        monkeypatch.setenv("POSTGRES_HOST", "postgres-blocked-in-unit-tests.invalid")
        monkeypatch.setenv("POSTGRES_PORT", "1")
    monkeypatch.setenv("POSTGRES_PASSWORD", "throwaway-test-database")
    monkeypatch.delenv("POSTGRESQL_CONNECTION_STRING", raising=False)
    monkeypatch.setattr(
        "core.storage.connection._load_connection_string_secret", lambda: None
    )
    from core.config import get_settings

    get_settings.cache_clear()
    yield


@pytest.fixture
def db():
    from sqlalchemy import text

    from core.coldstart import active
    from core.storage.connection import get_db_manager
    from core.storage.unit_of_work import unit_of_work

    get_db_manager().initialize()

    def clean():
        active.forget()
        with unit_of_work() as session:
            for statement in (
                "DELETE FROM kind_policy_events",
                "DELETE FROM kind_policies",
                "DELETE FROM case_closure_info",
                "DELETE FROM case_findings",
                "DELETE FROM cases",
                "DELETE FROM intake_triggers",
                "DELETE FROM findings",
                "DELETE FROM cold_start_runs",
                "DELETE FROM system_config WHERE key IN "
                "('kind_autonomy.settings', 'autonomy.ceiling')",
            ):
                session.execute(text(statement))

    clean()
    yield
    clean()


@pytest.fixture
def client(db):
    from fastapi.testclient import TestClient

    from services.api.main import app

    with TestClient(app) as c:
        yield c


def _user(user_id: str, role: str, service: bool = False):
    from sqlalchemy import text

    from core.storage.models import User
    from core.storage.unit_of_work import unit_of_work

    principal = f"person:{user_id}"
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO principals (principal_id, kind, label) "
                "VALUES (:p, 'person', :u) ON CONFLICT DO NOTHING"
            ),
            {"p": principal, "u": user_id},
        )
        session.execute(
            text(
                "INSERT INTO users (user_id, username, email, password_hash, full_name, "
                "role_id, is_active, mfa_enabled, principal_id, service_account) VALUES "
                "(:u, :u, :e, '', 'Sample Person', :r, true, false, :p, :s) "
                "ON CONFLICT (user_id) DO NOTHING"
            ),
            {
                "u": user_id,
                "e": f"{user_id}@test.local",
                "r": role,
                "p": principal,
                "s": service,
            },
        )
    return User(
        user_id=user_id,
        username=user_id,
        email=f"{user_id}@test.local",
        password_hash="",
        full_name="Sample Person",
        role_id=role,
        is_active=True,
        mfa_enabled=False,
        principal_id=principal,
        service_account=service,
    )


@pytest.fixture
def act_as(client):
    """Sign requests in as a real row, so permission gates still run."""
    from services.api.middleware.auth import get_current_active_user, get_current_user

    def sign_in(user_id: str, role: str = "role-admin", service: bool = False):
        user = _user(user_id, role, service)
        client.app.dependency_overrides[get_current_user] = lambda: user
        client.app.dependency_overrides[get_current_active_user] = lambda: user
        return user

    yield sign_in
    client.app.dependency_overrides.pop(get_current_user, None)
    client.app.dependency_overrides.pop(get_current_active_user, None)


@pytest.fixture
def admin(act_as):
    return act_as("ka-admin")


def add_finding(
    finding_id,
    *,
    severity="low",
    title=TITLE,
    source=SOURCE,
    at=None,
    noise_at=None,
    noise_by=None,
    noise_kind=None,
    noise_reason=None,
):
    from core.storage.models import Finding
    from core.storage.unit_of_work import unit_of_work

    moment = (at or NOW - timedelta(days=1)).replace(tzinfo=None)
    with unit_of_work() as session:
        session.add(
            Finding(
                finding_id=finding_id,
                title=title,
                data_source=source,
                severity=severity,
                timestamp=moment,
                entity_context=ENTITIES,
                noise_marked_at=noise_at.replace(tzinfo=None) if noise_at else None,
                noise_marked_by=noise_by,
                noise_marked_by_kind=noise_kind,
                noise_reason=noise_reason,
            )
        )
    return finding_id


def closed_case(
    case_id,
    finding_ids,
    *,
    category="false_positive",
    channel="cookie",
    by="person:ka-closer",
    at=None,
    status="closed",
):
    from sqlalchemy import text

    from core.storage.unit_of_work import unit_of_work

    moment = (at or NOW - timedelta(days=1)).replace(tzinfo=None)
    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO cases (case_id, title, status, priority, timeline) "
                "VALUES (:c, 'Sample case', :s, 'low', '[]'::jsonb)"
            ),
            {"c": case_id, "s": status},
        )
        for finding_id in finding_ids:
            session.execute(
                text(
                    "INSERT INTO case_findings (case_id, finding_id, added_at) "
                    "VALUES (:c, :f, now())"
                ),
                {"c": case_id, "f": finding_id},
            )
        session.execute(
            text(
                "INSERT INTO case_closure_info (case_id, closure_category, closed_by, "
                "close_channel, closed_at) VALUES (:c, :k, :b, :h, :a)"
            ),
            {"c": case_id, "k": category, "b": by, "h": channel, "a": moment},
        )


def earn(count=59, *, prefix="clean", source=SOURCE, title=TITLE, severity="low"):
    """People marking this kind noise one at a time, hours apart, so no burst drops them."""
    for i in range(count):
        at = NOW - timedelta(hours=2 * (i + 2))
        add_finding(
            f"{prefix}-{i}",
            severity=severity,
            source=source,
            title=title,
            at=at,
            noise_at=at,
            noise_by="ka-closer",
            noise_kind="analyst",
        )


def kind_key(source=SOURCE, title=TITLE):
    from core.coldstart.baseline import signature_of
    from core.coldstart.store import group_key

    return group_key(signature_of(source, title, ["host:wks-sample-1"]))


def row_of(client, key=None):
    body = client.get("/api/kind-autonomy").json()
    return next(k for k in body["kinds"] if k["key"] == (key or kind_key()))
