"""在线续期：成功即旧证失效、身份与范围不放大、并发唯一成功、异常归类、配额计数。"""
from __future__ import annotations

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
from app.tokens import issue_token
from main import create_app
from tests.conftest import log_case


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, sort_keys=True).encode()).rstrip(b"=").decode()


def _signed(header: dict, payload: dict, secret: bytes) -> str:
    signing_input = _b64(header) + "." + _b64(payload)
    sig = base64.urlsafe_b64encode(
        hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"{signing_input}.{sig}"


def _high_quota_service(key_store, revocation):
    return AuthService(
        key_store=key_store,
        revocation=revocation,
        quota=QuotaLimiter(limit=10000, window_seconds=60),
    )


def test_renew_success_invalidates_old_and_preserves_identity(service, key_store):
    old = issue_token(sub="alice", scopes=["doc:read"], key=key_store.current(),
                      now=0, ttl=100, jti="j-old")
    result = service.renew(old, now=40)
    log_case("renew_ok", {"sub": "alice", "scopes": ["doc:read"], "now": 40},
             result.decision, result.reason)
    assert result.decision == Decision.ALLOW
    assert result.claims is not None
    # 身份与范围逐字沿用，不能借续期放大权限
    assert result.claims.sub == "alice"
    assert result.claims.scopes == frozenset({"doc:read"})
    assert result.claims.jti != "j-old"
    # 有效期重新计算：时长沿用原凭证（100），但起点为当前时刻
    assert (result.claims.iat, result.claims.exp) == (40, 140)

    # 旧凭证立即失效：再续期 / 普通访问都被拒，且归类为 revoked
    again = service.renew(old, now=41)
    old_access = service.authorize(old, resource="doc", action="read", now=41)
    log_case("old_invalid", {"old_jti": "j-old"},
             (again.decision, old_access.decision), (again.reason, old_access.reason))
    assert again.decision == Decision.DENY_UNAUTHENTICATED
    assert old_access.decision == Decision.DENY_UNAUTHENTICATED
    assert "revoked" in again.reason and "续期" in again.reason

    # 新凭证权限与旧凭证一致：可读不可写
    read_ok = service.authorize(result.token, resource="doc", action="read", now=50)
    write_denied = service.authorize(result.token, resource="doc", action="write", now=50)
    log_case("new_token_scopes", {"scopes": ["doc:read"]},
             (read_ok.decision, write_denied.decision), "范围一致，读允许写拒绝")
    assert read_ok.decision == Decision.ALLOW
    assert write_denied.decision == Decision.DENY_FORBIDDEN


def test_concurrent_renew_exactly_one_succeeds(key_store, revocation):
    svc = _high_quota_service(key_store, revocation)
    old = issue_token(sub="carol", scopes=["doc:read"], key=key_store.current(),
                      now=0, ttl=1000, jti="j-race")
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: svc.renew(old, now=10), range(32)))
    allowed = [r for r in results if r.decision == Decision.ALLOW]
    new_jtis = {r.claims.jti for r in allowed}
    log_case("renew_race", {"workers": 16, "requests": 32},
             {"allow": len(allowed), "unique_new_jti": len(new_jtis),
              "reject": len(results) - len(allowed)},
             "并发续期恰好一个成功，且只产生一张新凭证")
    assert len(allowed) == 1
    assert len(new_jtis) == 1
    assert not svc.renew(old, now=11).decision == Decision.ALLOW
    # 唯一新凭证持续有效
    assert svc.authorize(allowed[0].token, resource="doc", action="read", now=12).decision == Decision.ALLOW


def test_renew_with_abnormal_credentials_is_classified(service, key_store):
    key = key_store.current()
    expired = issue_token(sub="alice", scopes=[], key=key, now=0, ttl=100, jti="j-exp")
    good = issue_token(sub="alice", scopes=["doc:read"], key=key, now=0, ttl=1000, jti="j-good")
    header, payload, sig = good.split(".")
    forged_payload = _b64({
        "sub": "alice", "scopes": ["doc:read", "doc:write"],
        "exp": 1000, "iat": 0, "jti": "j-good", "kid": "k1",
    })  # 合法 JSON 但沿用旧签名 -> tampered，且续期绝不能让放大后的范围生效
    tampered = f"{header}.{forged_payload}.{sig}"
    incomplete = _signed(
        {"alg": "HS256", "kid": "k1"}, {"sub": "alice"}, key.secret
    )
    cases = [
        ("anonymous", None, "未携带"),
        ("malformed", "a.b.c", "malformed"),
        ("unparseable", "!.!.!", "malformed"),
        ("incomplete", incomplete, "incomplete"),
        ("tampered", tampered, "tampered"),
        ("expired", expired, "expired"),
    ]
    for name, token, expect in cases:
        r = service.renew(token, now=500)
        log_case("renew_abnormal", {"case": name}, r.decision, r.reason)
        assert r.decision == Decision.DENY_UNAUTHENTICATED
        assert expect in r.reason
    # 相同输入重复执行，结论一致（与请求先后顺序无关）
    first = service.renew(tampered, now=501)
    second = service.renew(tampered, now=501)
    assert (first.decision, first.reason) == (second.decision, second.reason)


def test_renewed_token_cannot_escalate_scopes(service, key_store):
    old = issue_token(sub="mallory", scopes=["doc:read"], key=key_store.current(),
                      now=0, ttl=1000, jti="j-m")
    r = service.renew(old, now=10)
    assert r.claims.scopes == frozenset({"doc:read"})
    # 再次续期链：范围始终不变
    r2 = service.renew(r.token, now=20)
    log_case("renew_chain_scopes", {"chain_len": 2}, r2.claims.scopes, "续期链上范围恒定")
    assert r2.claims.scopes == frozenset({"doc:read"})
    assert service.authorize(r2.token, resource="doc", action="write", now=21).decision == Decision.DENY_FORBIDDEN


def test_renew_requests_count_toward_quota(key_store, revocation):
    svc = AuthService(key_store=key_store, revocation=revocation,
                      quota=QuotaLimiter(limit=3, window_seconds=60))
    token = issue_token(sub="dave", scopes=["doc:read"], key=key_store.current(),
                        now=0, ttl=10000, jti="j-d0")
    outcomes = []
    for i in range(3):
        r = svc.renew(token, now=10 + i)
        outcomes.append(r.decision)
        token = r.token  # 每次续期成功后改用新凭证继续续
    assert outcomes == [Decision.ALLOW] * 3
    # 第 4 次续期本身受配额限制：429，且不消费掉当前凭证
    exceeded = svc.renew(token, now=14)
    log_case("renew_quota", {"limit": 3, "renew_requests": 4}, exceeded.decision, exceeded.reason)
    assert exceeded.decision == Decision.DENY_QUOTA_EXCEEDED
    # 新窗口内同一张凭证仍可续期（429 没有把凭证作废，也没有放行）
    later = svc.renew(token, now=60)
    assert later.decision == Decision.ALLOW


def test_renew_after_key_rotation_uses_current_key(service, key_store):
    old = issue_token(sub="alice", scopes=["doc:read"], key=key_store.current(),
                      now=0, ttl=10000, jti="j-rot")
    key_store.rotate(SigningKey("k2", b"secret-2"), now=10)
    r = service.renew(old, now=20)
    log_case("renew_rotation", {"old_kid": "k1", "current": "k2"},
             r.decision, f"新凭证 kid={r.claims.kid if r.claims else None}")
    assert r.decision == Decision.ALLOW
    assert r.claims.kid == "k2"  # 宽限期内旧凭证可验，新凭证一律用当前密钥签发
    # 宽限期外旧凭证以 unknown_key 拒绝，不能借续期绕过轮换
    old2 = issue_token(sub="alice", scopes=["doc:read"], key=SigningKey("k1", b"secret-1"),
                       now=0, ttl=10000, jti="j-rot2")
    denied = service.renew(old2, now=2000)
    assert denied.decision == Decision.DENY_UNAUTHENTICATED
    assert "unknown_key" in denied.reason


# ---- HTTP 层 ----

def _issue(client, sub="alice", scopes=("doc:read",)):
    resp = client.post("/tokens", json={"sub": sub, "scopes": list(scopes)})
    assert resp.status_code == 201
    return resp.json()["token"]


def test_http_renew_endpoint_lifecycle():
    client = TestClient(create_app(quota_limit=10, quota_window_seconds=3600))
    old = _issue(client)
    resp = client.post("/tokens/renew", headers={"Authorization": f"Bearer {old}"})
    log_case("http_renew", {"header": "Bearer <old>"}, resp.status_code, resp.text)
    assert resp.status_code == 200
    new = resp.json()["token"]
    assert client.get("/resources/doc", headers={"Authorization": f"Bearer {old}"}).status_code == 401
    again = client.post("/tokens/renew", headers={"Authorization": f"Bearer {old}"})
    log_case("http_renew_old_again", {}, again.status_code, again.json()["reason"])
    assert again.status_code == 401
    assert "续期" in again.json()["reason"]
    assert client.get("/resources/doc", headers={"Authorization": f"Bearer {new}"}).status_code == 200


def test_http_renew_abnormal_credentials_distinguished():
    client = TestClient(create_app())
    checks = [
        ("anonymous", None, 401),
        ("malformed", "Bearer abc", 401),
        ("three_parts_garbage", "Bearer a.b.c", 401),
        ("wrong_scheme", "Basic xyz", 401),
    ]
    for name, header_value, expect_code in checks:
        headers = None if header_value is None else {"Authorization": header_value}
        r1 = client.post("/tokens/renew", headers=headers)
        r2 = client.post("/tokens/renew", headers=headers)
        log_case("http_renew_abnormal", {"case": name}, r1.status_code, r1.json()["reason"])
        assert (r1.status_code, r1.json()) == (expect_code, r2.json())


def test_http_concurrent_renew_only_one_wins():
    app = create_app(quota_limit=100, quota_window_seconds=3600)
    issuer = TestClient(app)
    old = _issue(issuer)
    clients = [TestClient(app) for _ in range(16)]

    def do_renew(c):
        return c.post("/tokens/renew", headers={"Authorization": f"Bearer {old}"})

    with ThreadPoolExecutor(max_workers=16) as pool:
        responses = list(pool.map(do_renew, clients * 2))
    codes = [r.status_code for r in responses]
    new_tokens = {r.json()["token"] for r in responses if r.status_code == 200}
    log_case("http_renew_race", {"requests": len(codes)},
             {"200": codes.count(200), "401": codes.count(401),
              "distinct_new_tokens": len(new_tokens)},
             "HTTP 并发续期唯一成功")
    assert codes.count(200) == 1
    assert len(new_tokens) == 1
