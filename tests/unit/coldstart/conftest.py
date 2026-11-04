"""Cold start's database tests run against the throwaway Postgres named by
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
        if "tests/unit/coldstart/" in str(item.path) and item.get_closest_marker(
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
    """An initialized manager and no cold start or federation rows left behind."""
    from sqlalchemy import text

    from core.coldstart import active
    from core.storage.connection import get_db_manager
    from core.storage.unit_of_work import unit_of_work

    get_db_manager().initialize()

    def clean():
        active.forget()
        with unit_of_work() as session:
            session.execute(text("DELETE FROM cold_start_runs"))
            session.execute(text("DELETE FROM federation_sources"))
            session.execute(
                text("DELETE FROM system_config WHERE key = 'federation.settings'")
            )
            session.execute(
                text(
                    "DELETE FROM integration_configs "
                    "WHERE integration_id IN ('elastic-siem', 'loglm')"
                )
            )

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
def analyst(client):
    """Every request is a real admin row, so permission gates still run."""
    from sqlalchemy import text

    from core.storage.models import User
    from core.storage.unit_of_work import unit_of_work
    from services.api.middleware.auth import get_current_active_user, get_current_user

    with unit_of_work() as session:
        session.execute(
            text(
                "INSERT INTO principals (principal_id, kind, label) "
                "VALUES ('person:cs-admin', 'person', 'cs-admin') ON CONFLICT DO NOTHING"
            )
        )
        session.execute(
            text(
                "INSERT INTO users (user_id, username, email, password_hash, full_name, "
                "role_id, is_active, mfa_enabled, principal_id) VALUES ('cs-admin', "
                "'cs-admin', 'cs-admin@test.local', '', 'CS Admin', 'role-admin', true, "
                "false, 'person:cs-admin') ON CONFLICT (user_id) DO NOTHING"
            )
        )
    user = User(
        user_id="cs-admin",
        username="cs-admin",
        email="cs-admin@test.local",
        password_hash="",
        full_name="CS Admin",
        role_id="role-admin",
        is_active=True,
        mfa_enabled=False,
        principal_id="person:cs-admin",
    )
    client.app.dependency_overrides[get_current_user] = lambda: user
    client.app.dependency_overrides[get_current_active_user] = lambda: user
    yield user
    client.app.dependency_overrides.pop(get_current_user, None)
    client.app.dependency_overrides.pop(get_current_active_user, None)
