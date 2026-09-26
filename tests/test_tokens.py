"""令牌签发与校验：正常、过期、篡改、不完整、未知密钥与可复现性。"""
import base64
import hashlib
import hmac
import json

from app.tokens import TokenErrorKind, issue_token, verify_token
from tests.conftest import log_case


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def test_valid_token_roundtrip(key_store):
    key = key_store.current()
    token = issue_token(sub="alice", scopes=["doc:read"], key=key, now=1000, ttl=100, jti="j1")
    result = verify_token(token, key_store.acceptable_keys(now=1000), now=1050)
    log_case("valid", {"sub": "alice", "now": 1050, "exp": 1100}, result.ok, result.detail or "ok")
    assert result.ok
    assert result.claims.sub == "alice"
    assert result.claims.scopes == frozenset({"doc:read"})


def test_verification_is_reproducible(key_store):
    key = key_store.current()
    token = issue_token(sub="alice", scopes=[], key=key, now=1000, ttl=100, jti="j1")
    keys = key_store.acceptable_keys(now=1000)
    first = verify_token(token, keys, now=1050)
    second = verify_token(token, keys, now=1050)
    log_case("reproducible", {"token": "same", "now": 1050}, first == second, "相同输入判定一致")
    assert first == second


def test_expired_token_rejected(key_store):
    key = key_store.current()
    token = issue_token(sub="alice", scopes=[], key=key, now=1000, ttl=100, jti="j1")
    result = verify_token(token, key_store.acceptable_keys(now=1000), now=1100)
    log_case("expired", {"now": 1100, "exp": 1100}, result.error, result.detail)
    assert result.error == TokenErrorKind.EXPIRED


def test_tampered_payload_rejected(key_store):
    key = key_store.current()
    token = issue_token(sub="alice", scopes=["doc:read"], key=key, now=1000, ttl=100, jti="j1")
    header, payload, sig = token.split(".")
    forged_payload = _b64({
        "sub": "alice", "scopes": ["doc:read", "doc:write"],
        "exp": 1100, "iat": 1000, "jti": "j1", "kid": "k1",
    })
    forged = f"{header}.{forged_payload}.{sig}"
    result = verify_token(forged, key_store.acceptable_keys(now=1000), now=1050)
    log_case("tampered", {"forged_scopes": ["doc:read", "doc:write"]}, result.error, result.detail)
    assert result.error == TokenErrorKind.TAMPERED


def test_malformed_token_rejected(key_store):
    for bad in ("", "abc", "a.b", "a.b.c.d", "!.!."):
        result = verify_token(bad, key_store.acceptable_keys(now=0), now=0)
        log_case("malformed", {"token": repr(bad)}, result.error, result.detail)
        assert result.error == TokenErrorKind.MALFORMED


def test_incomplete_claims_rejected(key_store):
    key = key_store.current()
    header = _b64({"alg": "HS256", "kid": "k1"})
    payload = _b64({"sub": "bob"})  # 缺少 scopes/exp/iat/jti/kid
    signing_input = f"{header}.{payload}"
    sig = base64.urlsafe_b64encode(
        hmac.new(key.secret, signing_input.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    result = verify_token(f"{signing_input}.{sig}", key_store.acceptable_keys(now=0), now=0)
    log_case("incomplete", {"claims": ["sub"]}, result.error, result.detail)
    assert result.error == TokenErrorKind.INCOMPLETE


def test_unknown_key_rejected(key_store):
    from app.keys import SigningKey

    outsider = SigningKey("k-outsider", b"other-secret")
    token = issue_token(sub="alice", scopes=[], key=outsider, now=0, ttl=100, jti="j1")
    result = verify_token(token, key_store.acceptable_keys(now=0), now=10)
    log_case("unknown_key", {"kid": "k-outsider"}, result.error, result.detail)
    assert result.error == TokenErrorKind.UNKNOWN_KEY
