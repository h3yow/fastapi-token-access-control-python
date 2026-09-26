"""HTTP 端到端：各入口下结论一致、错误可归类、公开行为不回归。"""

from __future__ import annotations

import concurrent.futures as futures

import pytest
from fastapi.testclient import TestClient

from app.api import create_app
from app.keys import KeyRing
from app.quota import FixedWindowQuota
from app.resources import ResourceStore
from app.revocation import RevocationList
from app.service import AuthService
from app.tokens import issue_token


@pytest.fixture
def client(
    keyring: KeyRing,
    revocations: RevocationList,
    quota: FixedWindowQuota,
) -> TestClient:
    auth = AuthService(keyring, revocations, quota)
    store = ResourceStore(initial={"docs": "hello"})
    app = create_app(
        auth, store, keyring=keyring, enable_issue_endpoint=True
    )
    app.state.auth = auth
    app.state.keyring = keyring
    app.state.store = store
    app.state.revocations = revocations
    app.state.quota = quota
    return TestClient(app)


def _auth(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def test_public_root_behavior_unchanged(client: TestClient) -> None:
    # 回归：根路径公开、无需鉴权、响应体保持既有形态
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json() == {"Hello": "World"}


def test_healthz_public(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}


def test_issue_endpoint_mints_usable_token(client: TestClient) -> None:
    resp = client.post(
        "/issue-token",
        json={"subject": "alice", "scopes": ["docs:read"], "ttl_seconds": 60},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    read = client.get("/resources/docs", headers=_auth(token))
    assert read.status_code == 200
    assert read.json()["value"] == "hello"


def test_anonymous_get_and_put_are_401(client: TestClient) -> None:
    for method, path in (("GET", "/resources/docs"), ("PUT", "/resources/docs")):
        resp = client.request(method, path, json={"value": "x"} if method == "PUT" else None)
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "missing_token"


def test_malformed_authorization_scheme_is_401_distinguishable(client: TestClient) -> None:
    resp = client.get("/resources/docs", headers={"Authorization": "Basic abc"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "malformed_token"


def test_tampered_token_401(client: TestClient) -> None:
    token = issue_token(
        client.app.state.keyring, "alice", frozenset({"docs:read"}), 60, jti="j"
    )
    resp = client.get("/resources/docs", headers=_auth(token + "xx"))
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "malformed_token"


def test_expired_token_401(client: TestClient, keyring: KeyRing) -> None:
    import time

    # 以过去时刻签发：exp 已早于当前墙钟时间
    old = issue_token(
        keyring,
        "alice",
        frozenset({"docs:read"}),
        60,
        now=int(time.time()) - 600,
        jti="j2",
    )
    resp = client.get("/resources/docs", headers=_auth(old))
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "token_expired"


def test_insufficient_scope_read_vs_write_403(
    client: TestClient, keyring: KeyRing
) -> None:
    token = issue_token(keyring, "alice", frozenset({"docs:read"}), 3600, jti="j")
    # 读允许
    assert client.get("/resources/docs", headers=_auth(token)).status_code == 200
    # 写被拒：403，且业务状态不变
    resp = client.put(
        "/resources/docs", headers=_auth(token), json={"value": "hacked"}
    )
    assert resp.status_code == 403
    body = resp.json()["error"]
    assert body["code"] == "insufficient_scope"
    assert body["resource"] == "docs" and body["action"] == "write"
    assert "docs:write" in body["message"]
    assert client.app.state.store.snapshot() == {"docs": "hello"}


def test_successful_write_changes_state(
    client: TestClient, keyring: KeyRing
) -> None:
    token = issue_token(keyring, "alice", frozenset({"docs:write"}), 3600, jti="jw")
    resp = client.put("/resources/docs", headers=_auth(token), json={"value": "v2"})
    assert resp.status_code == 200
    assert client.app.state.store.read("docs")["value"] == "v2"


def test_revoked_token_401(client: TestClient, keyring: KeyRing) -> None:
    token = issue_token(keyring, "alice", frozenset({"docs:read"}), 3600, jti="jrv")
    client.app.state.revocations.revoke("jrv")
    resp = client.get("/resources/docs", headers=_auth(token))
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "token_revoked"


def test_quota_exceeded_429_no_silent_degrade(
    client: TestClient, keyring: KeyRing
) -> None:
    token = issue_token(keyring, "alice", frozenset({"docs:read"}), 3600, jti="jq")
    statuses = [
        client.get("/resources/docs", headers=_auth(token)).status_code
        for _ in range(client.app.state.quota.limit + 2)
    ]
    assert statuses[: client.app.state.quota.limit] == [200] * client.app.state.quota.limit
    assert statuses[client.app.state.quota.limit :] == [429, 429]
    assert all(
        client.get("/resources/docs", headers=_auth(token)).json()["error"]["code"]
        == "quota_exceeded"
        for _ in range(1)
    )


def test_rotation_window_over_http(client: TestClient, keyring: KeyRing) -> None:
    # 旧密钥签发
    old = issue_token(keyring, "alice", frozenset({"docs:read"}), 3600, jti="old")
    kid_old = keyring.current_kid()
    # 用真实墙钟给足宽限时间，避免测试依赖时间注入
    new_kid = keyring.rotate(grace_seconds=3600)
    assert new_kid != kid_old
    new = issue_token(keyring, "bob", frozenset({"docs:read"}), 3600, jti="new")
    # 宽限期内两者都可用
    assert client.get("/resources/docs", headers=_auth(old)).status_code == 200
    assert client.get("/resources/docs", headers=_auth(new)).status_code == 200


