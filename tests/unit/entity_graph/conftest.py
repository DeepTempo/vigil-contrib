"""Route tests run against the throwaway Postgres named by VIGIL_TEST_POSTGRES_PORT, migrated
with ``python -m core.upgrade``. Without it they skip and the root conftest's block stays,
so they can never reach an instance's database.
"""

import os

import pytest

os.environ["TESTING"] = "true"


def pytest_collection_modifyitems(items):
    if os.environ.get("VIGIL_TEST_POSTGRES_PORT"):
        return
    skip = pytest.mark.skip(reason="needs VIGIL_TEST_POSTGRES_PORT: see this conftest")
    for item in items:
        if "tests/unit/entity_graph/" in str(item.path) and item.get_closest_marker(
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

    from core.storage.connection import get_db_manager
    from core.storage.unit_of_work import unit_of_work

    get_db_manager().initialize()

    def clean():
        with unit_of_work() as session:
            session.execute(text("DELETE FROM log_events"))
            session.execute(text("DELETE FROM case_findings"))
            session.execute(text("DELETE FROM cases WHERE case_id LIKE 'eg-%'"))
            session.execute(text("DELETE FROM findings WHERE finding_id LIKE 'eg-%'"))

    clean()
    yield
    clean()


@pytest.fixture
def client(db):
    from fastapi.testclient import TestClient

    from services.api.main import app

    with TestClient(app) as c:
        yield c


def _sign_in_as(client, user_id, role_id):
    from sqlalchemy import text

    from core.storage.models import User
    from core.storage.unit_of_work import unit_of_work
    from services.api.middleware.auth import get_current_active_user, get_current_user

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
                "role_id, is_active, mfa_enabled, principal_id) VALUES (:u, :u, :e, '', "
                ":u, :r, true, false, :p) ON CONFLICT (user_id) DO NOTHING"
            ),
            {"u": user_id, "e": f"{user_id}@test.local", "r": role_id, "p": principal},
        )
    user = User(
        user_id=user_id,
        username=user_id,
        email=f"{user_id}@test.local",
        password_hash="",
        full_name=user_id,
        role_id=role_id,
        is_active=True,
        mfa_enabled=False,
        principal_id=principal,
    )
    client.app.dependency_overrides[get_current_user] = lambda: user
    client.app.dependency_overrides[get_current_active_user] = lambda: user
    return user


@pytest.fixture
def analyst(client):
    """Every request is a real admin row, so permission gates still run."""
    from services.api.middleware.auth import get_current_active_user, get_current_user

    yield _sign_in_as(client, "eg-admin", "role-admin")
    client.app.dependency_overrides.pop(get_current_user, None)
    client.app.dependency_overrides.pop(get_current_active_user, None)


@pytest.fixture
def custom_role_user(client):
    """Signs in a user holding exactly the named permissions."""
    import json

    from sqlalchemy import text

    from core.storage.unit_of_work import unit_of_work
    from services.api.middleware.auth import get_current_active_user, get_current_user

    def make(*permissions):
        role_id = "eg-role-" + "-".join(permissions).replace(".", "_")
        with unit_of_work() as session:
            session.execute(
                text(
                    "INSERT INTO roles (role_id, name, description, permissions) "
                    "VALUES (:r, :r, '', CAST(:p AS jsonb)) ON CONFLICT (role_id) "
                    "DO UPDATE SET permissions = EXCLUDED.permissions"
                ),
                {"r": role_id, "p": json.dumps({p: True for p in permissions})},
            )
        return _sign_in_as(client, role_id.replace("role", "user"), role_id)

    yield make
    client.app.dependency_overrides.pop(get_current_user, None)
    client.app.dependency_overrides.pop(get_current_active_user, None)
    with unit_of_work() as session:
        session.execute(text("DELETE FROM users WHERE user_id LIKE 'eg-user-%'"))
        session.execute(text("DELETE FROM roles WHERE role_id LIKE 'eg-role-%'"))
