"""按权限范围的读写控制：匿名/越权区分、读写结论确定、越权写不改状态、公开行为回归。"""
import pytest
from fastapi.testclient import TestClient

from app.service import Decision
from app.tokens import issue_token
from main import create_app
from tests.conftest import log_case


@pytest.fixture
def client():
    return TestClient(create_app())


def _token(client, sub, scopes):
    resp = client.post("/tokens", json={"sub": sub, "scopes": scopes})
    assert resp.status_code == 201
    return resp.json()["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_public_root_behavior_unchanged(client):
    resp = client.get("/")
    log_case("public_root", {"path": "/"}, resp.status_code, resp.text)
    assert resp.status_code == 200
    assert resp.json() == {"Hello": "World"}


def test_anonymous_vs_forbidden_are_distinguished(client):
    token = _token(client, "alice", ["doc:read"])
    anon = client.get("/resources/doc")
    forbidden = client.put("/resources/doc", json={"content": "x"}, headers=_auth(token))
    log_case("anonymous", {"token": None}, anon.status_code, anon.json()["reason"])
    log_case("forbidden", {"scopes": ["doc:read"], "action": "write"},
             forbidden.status_code, forbidden.json()["reason"])
    assert anon.status_code == 401
    assert anon.json()["error"] == "deny_unauthenticated"
    assert forbidden.status_code == 403
    assert forbidden.json()["error"] == "deny_forbidden"


def test_read_write_conclusions_are_deterministic(client):
    reader = _token(client, "reader", ["doc:read"])
    writer = _token(client, "writer", ["doc:write"])
    cases = [
        (reader, "read", 200), (reader, "write", 403),
        (writer, "read", 403), (writer, "write", 200),
    ]
    for token, action, expected in cases:
        if action == "read":
            resp = client.get("/resources/doc", headers=_auth(token))
        else:
            resp = client.put("/resources/doc", json={"content": "v"}, headers=_auth(token))
        log_case("rw_matrix", {"action": action}, resp.status_code, resp.json().get("reason", "ok"))
        assert resp.status_code == expected


def test_unauthorized_write_does_not_change_state(client):
    reader = _token(client, "reader", ["doc:read"])
    writer = _token(client, "writer", ["doc:write"])
    assert client.put("/resources/doc", json={"content": "v1"}, headers=_auth(writer)).status_code == 200
    # 越权写（匿名 + 只读身份）
    assert client.put("/resources/doc", json={"content": "evil"}).status_code == 401
    assert client.put("/resources/doc", json={"content": "evil"}, headers=_auth(reader)).status_code == 403
    content = client.get("/resources/doc", headers=_auth(reader)).json()["content"]
    log_case("state_unchanged", {"attempts": ["anon", "reader"]}, content, "越权写后内容仍为 v1")
    assert content == "v1"


def test_wildcard_scope_grants_both(client):
    admin = _token(client, "admin", ["doc:*"])
    assert client.put("/resources/doc", json={"content": "v"}, headers=_auth(admin)).status_code == 200
    assert client.get("/resources/doc", headers=_auth(admin)).status_code == 200


def test_service_level_reasons_are_distinguishable(service, key_store):
    token = issue_token(sub="alice", scopes=["doc:read"], key=key_store.current(),
                        now=0, ttl=1000, jti="j1")
    anon = service.authorize(None, resource="doc", action="read", now=10)
    forbidden = service.authorize(token, resource="doc", action="write", now=10)
    log_case("svc_anonymous", {"token": None}, anon.decision, anon.reason)
    log_case("svc_forbidden", {"scopes": ["doc:read"], "need": "doc:write"},
             forbidden.decision, forbidden.reason)
    assert anon.decision == Decision.DENY_UNAUTHENTICATED
    assert forbidden.decision == Decision.DENY_FORBIDDEN
    assert "doc:write" in forbidden.reason
