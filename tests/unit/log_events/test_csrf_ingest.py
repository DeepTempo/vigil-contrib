"""Sending logs by token works with no CSRF cookie. The console's session stays covered."""

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from core.auth.auth_cookies import ACCESS_COOKIE_NAME
from services.api.middleware.csrf import CSRFMiddleware

INGEST = "/api/log-events/ingest"


@pytest.fixture
def client():
    async def ok(_request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/{path:path}", ok, methods=["POST"])])
    app.add_middleware(
        CSRFMiddleware,
        enabled=True,
        report_only=False,
        exempt_paths=(),
        cookie_secure=False,
    )
    return TestClient(app)


@pytest.mark.unit
def test_a_bearer_caller_with_no_session_cookie_can_ingest(client):
    assert client.post(INGEST).status_code == 200


@pytest.mark.unit
def test_a_session_cookie_still_needs_the_token_on_ingest(client):
    client.cookies.set(ACCESS_COOKIE_NAME, "a-session")
    assert client.post(INGEST).status_code == 403

    client.cookies.set("csrf_token", "matching")
    response = client.post(INGEST, headers={"X-CSRF-Token": "matching"})
    assert response.status_code == 200


@pytest.mark.unit
def test_other_log_routes_are_not_ingestion(client):
    assert client.post("/api/log-events/sweep").status_code == 403
    assert client.post(f"{INGEST}ible").status_code == 403
