"""Incident tests that read a database run against the throwaway Postgres named by
VIGIL_TEST_POSTGRES_PORT, migrated with ``python -m core.upgrade``. Without it they skip
and the root conftest's block stays, so they can never reach an instance's database.
"""

import os

import pytest

# Startup skips the external integrations (MCP servers, Bifrost, Redis) under this flag.
os.environ["TESTING"] = "true"


def pytest_collection_modifyitems(items):
    if os.environ.get("VIGIL_TEST_POSTGRES_PORT"):
        return
    skip = pytest.mark.skip(reason="needs VIGIL_TEST_POSTGRES_PORT: see this conftest")
    for item in items:
        if "tests/unit/incidents/" in str(item.path) and item.get_closest_marker(
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
    """An initialized manager and no incident rows left behind."""
    from sqlalchemy import text

    from core.storage.connection import get_db_manager
    from core.storage.unit_of_work import unit_of_work

    get_db_manager().initialize()

    def clean():
        with unit_of_work() as session:
            for table in (
                "approval_actions",
                "episodic_verdicts",
                "investigations",
                "workflow_runs",
                "log_events",
                "case_iocs",
                "case_closure_info",
                "case_findings",
                "cases",
                "findings",
                "detection_rules",
            ):
                session.execute(text(f"DELETE FROM {table}"))

    clean()
    yield
    clean()


@pytest.fixture
def client(db):
    from fastapi.testclient import TestClient

    from services.api.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def sign_in(client):
    """Real user rows in real roles, so the permission gates still run."""
    from sqlalchemy import text

    from core.storage.models import User
    from core.storage.unit_of_work import unit_of_work
    from services.api.middleware.auth import get_current_active_user, get_current_user

    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO roles (role_id, name, description, permissions, is_system_role) "
                "VALUES ('role-inc-none', 'No reads', 'Holds nothing', '{}', false) "
                "ON CONFLICT DO NOTHING"
            )
        )

    def as_user(role_id: str) -> User:
        name = f"inc-{role_id}"
        principal = f"person:{name}"
        with unit_of_work() as session:
            session.execute(
                text(
                    "INSERT INTO principals (principal_id, kind, label) "
                    "VALUES (:principal, 'person', :name) ON CONFLICT DO NOTHING"
                ),
                {"principal": principal, "name": name},
            )
            session.execute(
                text(
                    "INSERT INTO users (user_id, username, email, password_hash, full_name, "
                    "role_id, is_active, mfa_enabled, principal_id) VALUES (:name, :name, "
                    ":email, '', :name, :role, true, false, :principal) "
                    "ON CONFLICT (user_id) DO NOTHING"
                ),
                {
                    "name": name,
                    "email": f"{name}@test.local",
                    "role": role_id,
                    "principal": principal,
                },
            )
        user = User(
            user_id=name,
            username=name,
            email=f"{name}@test.local",
            password_hash="",
            full_name=name,
            role_id=role_id,
            is_active=True,
            mfa_enabled=False,
            principal_id=principal,
        )
        client.app.dependency_overrides[get_current_user] = lambda: user
        client.app.dependency_overrides[get_current_active_user] = lambda: user
        return user

    yield as_user
    client.app.dependency_overrides.pop(get_current_user, None)
    client.app.dependency_overrides.pop(get_current_active_user, None)
