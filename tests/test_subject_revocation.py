"""按主体一次性吊销：当前凭证全停、重复/并发安全、不波及其它主体与后续新凭证。"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.quota import QuotaLimiter
from app.service import AuthService, Decision
from app.tokens import TokenErrorKind, issue_token, verify_token
from main import create_app
from tests.conftest import log_case


def _issue(key_store, sub, jti):
    return issue_token(sub=sub, scopes=["doc:read"], key=key_store.current(),
                       now=0, ttl=1000, jti=jti)


def test_revoke_subject_stops_all_current_tokens(service, key_store, revocation):
    a1 = _issue(key_store, "alice", "j-a1")
    a2 = _issue(key_store, "alice", "j-a2")
    b1 = _issue(key_store, "bob", "j-b1")
    revocation.register("alice", "j-a1")
    revocation.register("alice", "j-a2")
    revocation.register("bob", "j-b1")

    count = revocation.revoke_subject("alice")
    log_case("revoke_subject", {"sub": "alice", "her_tokens": 2}, count,
             "alice 当前两张凭证全部新失效")
    assert count == 2
    for name, tok in (("a1", a1), ("a2", a2)):
        r = service.authorize(tok, resource="doc", action="read", now=10)
        log_case("after_subject_revoke", {"jti": name}, r.decision, r.reason)
        assert r.decision == Decision.DENY_UNAUTHENTICATED
        assert "revoked" in r.reason
    rb = service.authorize(b1, resource="doc", action="read", now=10)
    log_case("other_subject_unaffected", {"sub": "bob"}, rb.decision, rb.reason)
    assert rb.decision == Decision.ALLOW


def test_revoke_subject_is_idempotent(service, key_store, revocation):
    tok = _issue(key_store, "alice", "j-x")
    revocation.register("alice", "j-x")
    first = revocation.revoke_subject("alice")
    second = revocation.revoke_subject("alice")
    third = revocation.revoke_subject("alice")
    log_case("revoke_subject_repeat", {"calls": 3}, (first, second, third),
             "仅首次计数，之后幂等返回 0")
    assert (first, second, third) == (1, 0, 0)
    assert service.authorize(tok, resource="doc", action="read", now=10).decision == Decision.DENY_UNAUTHENTICATED


def test_revoke_subject_does_not_touch_later_issued_tokens(service, key_store, revocation):
    old = _issue(key_store, "alice", "j-old")
    revocation.register("alice", "j-old")
    assert revocation.revoke_subject("alice") == 1

    new = _issue(key_store, "alice", "j-new")
    revocation.register("alice", "j-new")
    r_old = service.authorize(old, resource="doc", action="read", now=10)
    r_new = service.authorize(new, resource="doc", action="read", now=10)
    log_case("reissue_after_revoke", {"old": "j-old", "new": "j-new"},
             (r_old.decision, r_new.decision), "旧证仍拒，新证可用")
    assert r_old.decision == Decision.DENY_UNAUTHENTICATED
    assert r_new.decision == Decision.ALLOW

    assert revocation.revoke_subject("alice") == 1
    assert service.authorize(new, resource="doc", action="read", now=11).decision == Decision.DENY_UNAUTHENTICATED


def test_concurrent_revoke_subject_safe_and_stable(key_store, revocation):
    svc = AuthService(key_store=key_store, revocation=revocation,
                      quota=QuotaLimiter(limit=10000, window_seconds=60))
    jtis = [f"j-c{i}" for i in range(50)]
    for jti in jtis:
        revocation.register("carol", jti)
    with ThreadPoolExecutor(max_workers=16) as pool:
        counts = list(pool.map(lambda _: revocation.revoke_subject("carol"), range(64)))
    log_case("concurrent_revoke_subject", {"tokens": 50, "calls": 64},
             {"total_newly_revoked": sum(counts), "nonzero_calls": sum(1 for c in counts if c)},
             "并发批量吊销：新失效总数恰为 50，只有一次调用计数")
    assert sum(counts) == 50
    assert sum(1 for c in counts if c) == 1
    # 已登记的 50 张凭证最终一致失效（访问全部被拒）
    for jti in jtis:
        tok = _issue(key_store, "carol", jti)
        decision = svc.authorize(tok, resource="doc", action="read", now=10).decision
        assert decision == Decision.DENY_UNAUTHENTICATED


def test_concurrent_revoke_while_other_subject_active(service, key_store, revocation):
    other = _issue(key_store, "dan", "j-dan")
    revocation.register("dan", "j-dan")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: revocation.revoke_subject("eve"), range(32)))
    r = service.authorize(other, resource="doc", action="read", now=10)
    log_case("revoke_empty_subject", {"revoked": "eve(无凭证)", "other": "dan"},
             r.decision, "吊销不存在凭证的主体不报错，也不波及其它主体")
    assert r.decision == Decision.ALLOW


def test_classification_after_bulk_revoke(service, key_store, revocation):
    """过期/合法但被批量吊销的凭证各归各类，结论只取决于输入。"""
    valid = issue_token(sub="alice", scopes=[], key=key_store.current(),
                        now=0, ttl=1000, jti="j-valid")
    expired = issue_token(sub="alice", scopes=[], key=key_store.current(),
                          now=0, ttl=10, jti="j-expired")
    revocation.register("alice", "j-valid")
    revocation.register("alice", "j-expired")
    revocation.revoke_subject("alice")
    r_exp = verify_token(expired, key_store.acceptable_keys(now=20), now=20)
    r_valid = service.authorize(valid, resource="doc", action="read", now=20)
    log_case("classification_after_bulk_revoke",
             {"expired_token": "expired?", "valid_token": "revoked?"},
             (r_exp.error, r_valid.decision), "过期归过期，合法但被批量吊销归 revoked")
    assert r_exp.error == TokenErrorKind.EXPIRED
    assert r_valid.decision == Decision.DENY_UNAUTHENTICATED
    assert "revoked" in r_valid.reason


# ---- HTTP 层 ----

def _issue_http(client, sub, scopes=("doc:read",)):
    r = client.post("/tokens", json={"sub": sub, "scopes": list(scopes)})
    assert r.status_code == 201
    return r.json()["token"]


def test_http_revoke_subject_endpoint_isolation_and_reissue():
    client = TestClient(create_app(quota_limit=10, quota_window_seconds=3600))
    a1 = _issue_http(client, "alice")
    a2 = _issue_http(client, "alice")
    b1 = _issue_http(client, "bob")

    r = client.post("/admin/revoke-subject", json={"sub": "alice"})
    log_case("http_revoke_subject", {"sub": "alice"}, r.status_code, r.text)
    assert r.status_code == 200
    assert r.json()["revoked_count"] == 2

    for tok in (a1, a2):
        assert client.get("/resources/doc",
                          headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    assert client.get("/resources/doc",
                      headers={"Authorization": f"Bearer {b1}"}).status_code == 200

    r2 = client.post("/admin/revoke-subject", json={"sub": "alice"})
    log_case("http_revoke_subject_repeat", {}, r2.status_code, r2.text)
    assert r2.json()["revoked_count"] == 0

    a3 = _issue_http(client, "alice")
    r3 = client.get("/resources/doc", headers={"Authorization": f"Bearer {a3}"})
    log_case("http_reissue", {"sub": "alice"}, r3.status_code, "重新签发的凭证不受历史吊销影响")
    assert r3.status_code == 200


def test_http_revoke_subject_isolates_renewed_chain():
    """批量吊销与续期协同：续期后的新凭证也在主体名下，可被一并吊销。"""
    client = TestClient(create_app(quota_limit=10, quota_window_seconds=3600))
    old = _issue_http(client, "frank")
    renewed = client.post("/tokens/renew",
                          headers={"Authorization": f"Bearer {old}"}).json()["token"]
    r = client.post("/admin/revoke-subject", json={"sub": "frank"})
    log_case("http_revoke_with_renew", {"sub": "frank"}, r.status_code, r.text)
    # 旧证已因续期失效，不计入；当前有效的新证被新吊销
    assert r.json()["revoked_count"] == 1
    assert client.get("/resources/doc",
                      headers={"Authorization": f"Bearer {renewed}"}).status_code == 401
    assert client.post("/tokens/renew",
                       headers={"Authorization": f"Bearer {renewed}"}).status_code == 401
