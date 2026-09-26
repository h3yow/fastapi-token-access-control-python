"""并发安全的配额限制：不超发、不漏计、超限以可区分状态拒绝。"""
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.quota import QuotaLimiter
from main import create_app
from tests.conftest import log_case


def test_sequential_limit_enforced():
    q = QuotaLimiter(limit=3, window_seconds=60)
    results = [q.acquire("u", now=0) for _ in range(4)]
    log_case("sequential", {"limit": 3, "requests": 4},
             [r.allowed for r in results], "前 3 允许，第 4 拒绝")
    assert [r.allowed for r in results] == [True, True, True, False]
    assert results[-1].used == 3  # 拒绝时不漏计也不多计


def test_window_rollover_resets():
    q = QuotaLimiter(limit=2, window_seconds=60)
    assert q.acquire("u", now=0).allowed
    assert q.acquire("u", now=0).allowed
    assert not q.acquire("u", now=59).allowed
    rollover = q.acquire("u", now=60)
    log_case("window_rollover", {"now": 60, "window": 60}, rollover.allowed, "新窗口重置计数")
    assert rollover.allowed


def test_concurrent_no_overissue_no_undercount():
    q = QuotaLimiter(limit=50, window_seconds=60)
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: q.acquire("u", now=0), range(500)))
    allowed = sum(1 for r in results if r.allowed)
    denied = sum(1 for r in results if not r.allowed)
    usage = q.usage("u", now=0)
    log_case("concurrent", {"limit": 50, "requests": 500, "workers": 32},
             {"allowed": allowed, "denied": denied, "usage": usage},
             "允许数恰为上限，不超发不漏计")
    assert allowed == 50
    assert denied == 450
    assert usage == 50
    # 已用配额序号无重复无空洞：1..50 各出现一次
    used_seq = sorted(r.used for r in results if r.allowed)
    assert used_seq == list(range(1, 51))


def test_subjects_are_isolated():
    q = QuotaLimiter(limit=1, window_seconds=60)
    assert q.acquire("a", now=0).allowed
    assert not q.acquire("a", now=0).allowed
    isolated = q.acquire("b", now=0)
    log_case("isolation", {"a_used": 1}, isolated.allowed, "主体间配额互不影响")
    assert isolated.allowed


def test_http_quota_exceeded_is_distinguishable():
    client = TestClient(create_app(quota_limit=2, quota_window_seconds=3600))
    token = client.post("/tokens", json={"sub": "alice", "scopes": ["doc:read"]}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    codes = [client.get("/resources/doc", headers=headers).status_code for _ in range(3)]
    last = client.get("/resources/doc", headers=headers)
    log_case("http_quota", {"limit": 2, "requests": 4}, codes + [last.status_code],
             last.json().get("reason", ""))
    assert codes == [200, 200, 429]
    assert last.status_code == 429
    body = last.json()
    assert body["error"] == "deny_quota_exceeded"
    assert "配额" in body["reason"]


def test_forbidden_requests_do_not_consume_quota():
    client = TestClient(create_app(quota_limit=1, quota_window_seconds=3600))
    token = client.post("/tokens", json={"sub": "alice", "scopes": ["doc:read"]}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    # 越权写不消耗配额
    assert client.put("/resources/doc", json={"content": "x"}, headers=headers).status_code == 403
    allowed = client.get("/resources/doc", headers=headers)
    log_case("forbidden_no_quota", {"forbidden_writes": 1}, allowed.status_code,
             "越权请求不计配额，后续合法请求仍被允许")
    assert allowed.status_code == 200
