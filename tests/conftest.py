import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import SecurityContext


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def auth_header():
    # identity.py only reads unverified claims from JWT structure.
    # For API tests we will monkeypatch build_security_context directly where needed.
    return {"Authorization": "Bearer dummy.token.value"}


@pytest.fixture
def security_context() -> SecurityContext:
    return SecurityContext(
        subject="user-123",
        user_id="user-123",
        tenant_id="tenant-a",
        roles=["user"],
        permissions=[
            "llm:chat",
            "tool:kb.lookup",
            "tool:browser.search",
        ],
        auth_level="standard",
        step_up_authenticated=True,
        issuer="test-issuer",
        audience="test-audience",
        claims={},
    )
