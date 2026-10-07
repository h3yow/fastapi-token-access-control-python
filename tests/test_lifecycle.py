"""凭证生命周期：在线续期与按主体批量吊销。

覆盖：
- 续期成功后旧凭证立即失效，新凭证身份/范围/TTL 一致，不能放大权限；
- 同一旧凭证并发续期只有一个成功，不产生多张有效新凭证；
- 续期失败归类稳定：匿名/过期/被吊销/不完整/异常凭证 -> 401，超配额 -> 429；
- 续期请求本身计配额，且超配额不消耗旧凭证；
- 按主体批量吊销：重复执行、并发执行均正确；仅影响该主体当前凭证，
  不影响其他主体，也不影响该主体之后重新签发的凭证；
- 与密钥轮换宽限期兼容。
"""
import base64
import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from app.keys import KeyStore, SigningKey
from app.quota import QuotaLimiter
from app.revocation import RevocationRegistry
from app.service import AuthService, Decision
from app.tokens import TokenErrorKind, issue_token, verify_token
from main import create_app
from tests.conftest import log_case


def _service(limit: int = 100000) -> AuthService:
    return AuthService(
        key_store=KeyStore(SigningKey("k1", b"secret-1"), grace_period=100),
        revocation=RevocationRegistry(),
        quota=QuotaLimiter(limit=limit, window_seconds=60),
    )


def _b64(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


# ---------- 续期：基本语义 ----------

def test_renew_success_invalidates_old_and_preserves_identity():
    svc = _service()
    old_token, _ = svc.issue(sub="alice", scopes=["doc:read"], ttl=1000, now=0)

    renewed = svc.renew(old_token, now=100)
    log_case("renew_ok", {"sub": "alice", "old_iat": 0, "renew_at": 100, "ttl": 1000},
             renewed.decision, renewed.reason)
    assert renewed.decision == Decision.ALLOW
    assert renewed.token != old_token
    assert renewed.expires_at == 1100  # 有效期自续期时刻重新计算，TTL 不变

    old_after = svc.authorize(old_token, resource="doc", action="read", now=100)
    new_after = svc.authorize(renewed.token, resource="doc", action="read", now=100)
    log_case("old_invalid", {"which": "old"}, old_after.decision, old_after.reason)
    log_case("new_valid", {"which": "new"}, new_after.decision, new_after.reason)
    assert old_after.decision == Decision.DENY_UNAUTHENTICATED
    assert "revoked" in old_after.reason
    assert new_after.decision == Decision.ALLOW

    # 身份与权限范围完全一致：仍是只读身份，借续期拿不到写权限
    old_claims = verify_token(old_token, [SigningKey("k1", b"secret-1")], now=10).claims
    assert renewed.claims.sub == "alice"
    assert renewed.claims.scopes == frozenset({"doc:read"})
    assert renewed.claims.jti != old_claims.jti
    write = svc.authorize(renewed.token, resource="doc", action="write", now=100)
    log_case("no_privilege_escalation", {"scopes": ["doc:read"], "action": "write"},
             write.decision, write.reason)
    assert write.decision == Decision.DENY_FORBIDDEN


def test_renewed_token_has_fresh_jti_and_full_ttl():
    svc = _service()
    token, _ = svc.issue(sub="bob", scopes=[], ttl=500, now=0)
    r = svc.renew(token, now=400)  # 旧凭证仅剩 100 秒
    assert r.decision == Decision.ALLOW
    log_case("fresh_ttl", {"old_exp": 500, "renew_at": 400, "ttl": 500},
             r.expires_at, "新凭证有效期重新计算为完整 TTL")
    assert r.expires_at == 900
    old_claims = verify_token(token, [SigningKey("k1", b"secret-1")], now=10).claims
    assert r.claims.jti != old_claims.jti


# ---------- 续期：并发只有一个成功 ----------

def test_concurrent_renew_only_one_succeeds():
    svc = _service()
    token, _ = svc.issue(sub="carol", scopes=["doc:read"], ttl=1000, now=0)
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: svc.renew(token, now=10), range(64)))
    winners = [r for r in results if r.decision is Decision.ALLOW]
    losers = [r for r in results if r.decision is not Decision.ALLOW]
    log_case("concurrent_renew", {"requests": 64, "workers": 32},
             {"allow": len(winners), "deny": len(losers)},
             "并发续期仅一张新凭证")
    assert len(winners) == 1
    assert len(losers) == 63
    # 失败方统一归类为 revoked（旧凭证已被首个请求消费）
    assert all(r.decision is Decision.DENY_UNAUTHENTICATED and "revoked" in r.reason
               for r in losers)

    # 旧凭证失效；唯一一张新凭证可用
    old_now = svc.authorize(token, resource="doc", action="read", now=10)
    new_now = svc.authorize(winners[0].token, resource="doc", action="read", now=10)
    new_tokens = {r.token for r in winners}
    log_case("concurrent_aftermath", {"distinct_new_tokens": len(new_tokens)},
             (old_now.decision, new_now.decision), "旧失效、新唯一有效")
    assert old_now.decision == Decision.DENY_UNAUTHENTICATED
    assert len(new_tokens) == 1
    assert new_now.decision == Decision.ALLOW


# ---------- 续期：失败归类 ----------

def test_renew_rejects_anonymous_and_malformed_http():
    client = TestClient(create_app())
    cases = [
        ("anonymous", None),
        ("empty_bearer", "Bearer "),
        ("two_parts", "Bearer a.b"),
        ("four_parts", "Bearer a.b.c.d"),
        ("garbage", "Bearer !!!.!!!.!!!"),
        ("wrong_scheme", "Basic abc"),
    ]
    for name, header in cases:
        resp = client.post("/tokens/renew",
                           headers=None if header is None else {"Authorization": header})
        log_case("renew_bad_input", {"case": name}, resp.status_code,
                 resp.json().get("reason", resp.text))
        assert resp.status_code == 401
        assert resp.json()["error"] == "deny_unauthenticated"


def test_renew_rejects_expired_tampered_revoked():
    key_store = KeyStore(SigningKey("k1", b"secret-1"), grace_period=100)
    svc = AuthService(key_store=key_store, revocation=RevocationRegistry(),
                      quota=QuotaLimiter(limit=100, window_seconds=60))
    # 过期
    expired, _ = svc.issue(sub="u", scopes=[], ttl=100, now=0)
    r_exp = svc.renew(expired, now=100)
    log_case("renew_expired", {"exp": 100, "now": 100}, r_exp.decision, r_exp.reason)
    assert r_exp.decision == Decision.DENY_UNAUTHENTICATED
    assert TokenErrorKind.EXPIRED.value in r_exp.reason

    # 篡改（替换签名末位）
    good, _ = svc.issue(sub="u", scopes=["doc:read"], ttl=1000, now=0)
    _, _, sig = good.split(".")
    tampered = good[:-1] + ("A" if sig[-1] != "A" else "B")
    r_tamper = svc.renew(tampered, now=10)
    log_case("renew_tampered", {"changed": "signature"}, r_tamper.decision, r_tamper.reason)
    assert r_tamper.decision == Decision.DENY_UNAUTHENTICATED
    assert TokenErrorKind.TAMPERED.value in r_tamper.reason

    # 已被吊销
    revoked, _ = svc.issue(sub="u", scopes=[], ttl=1000, now=0)
    revoked_claims = verify_token(revoked, key_store.acceptable_keys(now=0), now=0).claims
    svc._revocation.revoke(revoked_claims.jti)
    r_rev = svc.renew(revoked, now=10)
    log_case("renew_revoked", {"jti": revoked_claims.jti}, r_rev.decision, r_rev.reason)
    assert r_rev.decision == Decision.DENY_UNAUTHENTICATED
    assert TokenErrorKind.REVOKED.value in r_rev.reason


def test_renew_rejects_incomplete_claims():
    # 结构合法、签名正确、但缺少必要声明的凭证
    key_store = KeyStore(SigningKey("k1", b"secret-1"), grace_period=100)
    svc = AuthService(key_store=key_store, revocation=RevocationRegistry(),
                      quota=QuotaLimiter(limit=100, window_seconds=60))
    header = _b64({"alg": "HS256", "kid": "k1"})
    payload = _b64({"sub": "x"})  # 缺 scopes/exp/iat/jti/kid/gen
    signing_input = f"{header}.{payload}"
    sig = base64.urlsafe_b64encode(
        hmac.new(b"secret-1", signing_input.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    r = svc.renew(f"{signing_input}.{sig}", now=10)
    log_case("renew_incomplete", {"claims": ["sub"]}, r.decision, r.reason)
    assert r.decision == Decision.DENY_UNAUTHENTICATED
    assert TokenErrorKind.INCOMPLETE.value in r.reason


def test_renew_is_reproducible_after_consumption():
    svc = _service()
    token, _ = svc.issue(sub="u", scopes=[], ttl=1000, now=0)
    first = svc.renew(token, now=10)
    assert first.decision == Decision.ALLOW
    # 旧凭证再次续期：无论多少次、什么顺序，结论一致
    again = [svc.renew(token, now=n) for n in (11, 12, 500)]
    log_case("renew_replay", {"attempts": 3},
             [r.decision for r in again], "消费后再续期恒定拒绝")
    assert all(r.decision == Decision.DENY_UNAUTHENTICATED for r in again)
    assert all(TokenErrorKind.REVOKED.value in r.reason for r in again)


# ---------- 续期：配额 ----------

def test_renew_consumes_quota_and_quota_failure_keeps_old_token():
    client = TestClient(create_app(quota_limit=1, quota_window_seconds=3600))
    token = client.post("/tokens", json={"sub": "dave", "scopes": ["doc:read"]}).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    # 先做一次资源访问，用掉窗口内唯一配额
    assert client.get("/resources/doc", headers=headers).status_code == 200
    # 续期本身也要计配额：配额已尽 -> 429，且该结论与重试顺序无关
    over1 = client.post("/tokens/renew", headers=headers)
    over2 = client.post("/tokens/renew", headers=headers)
    log_case("renew_quota_exceeded", {"limit": 1}, (over1.status_code, over2.status_code),
             over1.json().get("reason", ""))
    assert over1.status_code == over2.status_code == 429
    assert over1.json()["error"] == "deny_quota_exceeded"
    # 配额拒绝发生在消费旧 jti 之前：旧凭证身份仍合法（下窗口可续期/访问）
    svc = client.app.state.service
    auth = svc.authenticate(token, now=4000)
    log_case("old_survives_quota_deny", {"now": 4000}, auth.decision, auth.reason)
    assert auth.decision == Decision.ALLOW

    # 续期成功本身确实占用一个配额槽：新窗口 limit=1，续期成功后
    # 同主体任何后续访问都应 429，证明续期不是绕过限流的后门
    client2 = TestClient(create_app(quota_limit=1, quota_window_seconds=3600))
    t2 = client2.post("/tokens", json={"sub": "dave2", "scopes": ["doc:read"]}).json()["token"]
    renewed = client2.post("/tokens/renew", headers={"Authorization": f"Bearer {t2}"})
    assert renewed.status_code == 200
    blocked = client2.get("/resources/doc",
                         headers={"Authorization": f"Bearer {renewed.json()['token']}"})
    log_case("renew_occupies_quota_slot", {"limit": 1}, blocked.status_code,
             blocked.json().get("reason", ""))
    assert blocked.status_code == 429


def test_concurrent_renew_does_not_bypass_quota():
    # 小配额 + 高并发：无论竞态如何，jti 至多被消费一次（安全底线），
    # 配额计数不超发（usage 不超过上限），落败请求只可能是 429 或 401
    svc = _service(limit=10)
    token, _ = svc.issue(sub="eve", scopes=["doc:read"], ttl=1000, now=0)
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: svc.renew(token, now=10), range(64)))
    allowed = [r for r in results if r.decision is Decision.ALLOW]
    others = [r for r in results if r.decision is not Decision.ALLOW]
    usage = svc._quota.usage("eve", now=10)
    log_case("renew_quota_concurrency", {"limit": 10, "requests": 64},
             {"allow": len(allowed), "other": len(others), "usage": usage},
             "续期不绕过配额，且仅一个消费成功")
    assert len(allowed) == 1  # 安全底线：不会复制出多张有效新凭证
    assert all(r.decision in (Decision.DENY_QUOTA_EXCEEDED,
                              Decision.DENY_UNAUTHENTICATED) for r in others)
    assert 1 <= usage <= 10  # 只有通过身份阶段的请求才计数，绝不超发


# ---------- 按主体批量吊销 ----------

def test_revoke_subject_invalidates_all_current_credentials():
    svc = _service()
    t1, _ = svc.issue(sub="frank", scopes=["doc:read"], ttl=1000, now=0)
    t2, _ = svc.issue(sub="frank", scopes=["doc:write"], ttl=1000, now=1)
    gen = svc.revoke_subject("frank")
    log_case("revoke_subject", {"sub": "frank"}, gen, "世代推进到 1")
    assert gen == 1
    r1 = svc.authorize(t1, resource="doc", action="read", now=10)
    r2 = svc.authorize(t2, resource="doc", action="write", now=10)
    log_case("all_credentials_dead", {"tokens": 2},
             (r1.decision, r2.decision), "该主体当前凭证全部失效")
    assert r1.decision == r2.decision == Decision.DENY_UNAUTHENTICATED
    assert "revoked" in r1.reason and "revoked" in r2.reason


def test_revoke_subject_is_isolated_and_future_tokens_survive():
    svc = _service()
    frank1, _ = svc.issue(sub="frank", scopes=["doc:read"], ttl=1000, now=0)
    grace1, _ = svc.issue(sub="grace", scopes=["doc:read"], ttl=1000, now=0)
    svc.revoke_subject("frank")
    # 其他主体不受影响
    other = svc.authorize(grace1, resource="doc", action="read", now=10)
    log_case("other_subject_unaffected", {"revoked": "frank", "other": "grace"},
             other.decision, other.reason)
    assert other.decision == Decision.ALLOW
    # 该主体之后重新签发的凭证不受影响
    frank2, _ = svc.issue(sub="frank", scopes=["doc:read"], ttl=1000, now=11)
    reborn = svc.authorize(frank2, resource="doc", action="read", now=12)
    old_still = svc.authorize(frank1, resource="doc", action="read", now=12)
    log_case("future_credential_unaffected", {"sub": "frank", "issued_after": 11},
             (reborn.decision, old_still.decision), "新凭证有效，旧凭证仍拒绝")
    assert reborn.decision == Decision.ALLOW
    assert old_still.decision == Decision.DENY_UNAUTHENTICATED


def test_revoke_subject_repeated_and_concurrent():
    svc = _service()
    token, _ = svc.issue(sub="hank", scopes=["doc:read"], ttl=1000, now=0)
    # 重复执行：世代单调推进、结论确定
    gens = [svc.revoke_subject("hank") for _ in range(3)]
    log_case("revoke_repeated", {"times": 3}, gens, "重复执行安全")
    assert gens == [1, 2, 3]

    # 并发执行：世代号 1..N 无重复无空洞
    svc2 = _service()
    with ThreadPoolExecutor(max_workers=16) as pool:
        concurrent_gens = list(pool.map(lambda _: svc2.revoke_subject("ivy"), range(100)))
    log_case("revoke_concurrent", {"sub": "ivy", "times": 100},
             sorted(concurrent_gens), "并发推进世代无丢失无重复")
    assert sorted(concurrent_gens) == list(range(1, 101))

    # 旧凭证恒拒绝；再签发的凭证携带新世代，可用
    dead = svc.authorize(token, resource="doc", action="read", now=10)
    fresh, _ = svc.issue(sub="hank", scopes=["doc:read"], ttl=1000, now=10)
    alive = svc.authorize(fresh, resource="doc", action="read", now=11)
    log_case("after_repeated_revoke", {}, (dead.decision, alive.decision),
             "多次吊销后旧凭证仍拒绝、新凭证可用")
    assert dead.decision == Decision.DENY_UNAUTHENTICATED
    assert alive.decision == Decision.ALLOW


def test_revoke_subject_http_endpoint_is_idempotent():
    client = TestClient(create_app())
    r1 = client.post("/admin/revoke-subject", json={"sub": "judy"})
    r2 = client.post("/admin/revoke-subject", json={"sub": "judy"})
    log_case("http_revoke_subject", {"sub": "judy"},
             (r1.json(), r2.json()), "重复调用世代单调推进")
    assert r1.status_code == r2.status_code == 200
    assert r1.json()["generation"] == 1
    assert r2.json()["generation"] == 2


# ---------- 与密钥轮换兼容 ----------

def test_renew_works_across_key_rotation_within_grace():
    key_store = KeyStore(SigningKey("k1", b"secret-1"), grace_period=100)
    svc = AuthService(key_store=key_store, revocation=RevocationRegistry(),
                      quota=QuotaLimiter(limit=100, window_seconds=60))
    old_token = issue_token(sub="kim", scopes=["doc:read"],
                            key=SigningKey("k1", b"secret-1"),
                            now=0, ttl=10000, jti="j-old", gen=0)
    key_store.rotate(SigningKey("k2", b"secret-2"), now=1000)
    # 宽限期内：旧密钥凭证可续期，换出的新凭证由当前密钥 k2 签发
    renewed = svc.renew(old_token, now=1050)
    log_case("renew_in_grace", {"rotated_at": 1000, "now": 1050, "grace": 100},
             (renewed.decision, renewed.claims.kid if renewed.claims else None),
             renewed.reason)
    assert renewed.decision == Decision.ALLOW
    assert renewed.claims.kid == "k2"
    assert renewed.claims.scopes == frozenset({"doc:read"})
    # 宽限期外：旧密钥凭证以 unknown_key 拒绝，不会被放行
    old2 = issue_token(sub="kim", scopes=["doc:read"],
                       key=SigningKey("k1", b"secret-1"),
                       now=0, ttl=100000, jti="j-old2", gen=0)
    rejected = svc.renew(old2, now=1100)
    log_case("renew_after_grace", {"now": 1100}, rejected.decision, rejected.reason)
    assert rejected.decision == Decision.DENY_UNAUTHENTICATED
    assert TokenErrorKind.UNKNOWN_KEY.value in rejected.reason
