"""凭证签发与校验：正常、过期、篡改、身份不完整，且失败原因可区分。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from app.errors import (
    ExpiredTokenError,
    IncompleteIdentityError,
    MalformedTokenError,
)
from app.keys import KeyRing
from app.tokens import issue_token, verify_token


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _reencode(payload: dict, header: dict, secret: bytes) -> str:
    h = _b64e(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64e(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


def test_valid_token_roundtrip(
    keyring: KeyRing, now: int, caplog: pytest.LogCaptureFixture
) -> None:
    token = issue_token(
        keyring, "alice", frozenset({"docs:read"}), 60, now=now, jti="j-1"
    )
    caplog.clear()
    claims = verify_token(token, keyring, now=now + 59)
    assert claims.sub == "alice"
    assert claims.scopes == frozenset({"docs:read"})
    assert claims.jti == "j-1"
    assert claims.exp == now + 60


def test_expired_at_boundary_and_after(
    keyring: KeyRing, now: int, caplog: pytest.LogCaptureFixture
) -> None:
    token = issue_token(keyring, "alice", frozenset(), 60, now=now, jti="j")
    for at in (now + 60, now + 61):
        caplog.clear()
        with pytest.raises(ExpiredTokenError) as exc:
            verify_token(token, keyring, now=at)
        assert exc.value.code == "token_expired"


def test_malformed_structures(keyring: KeyRing, now: int) -> None:
    token = issue_token(keyring, "alice", frozenset(), 60, now=now)
    cases = [
        "",
        "only-one",
        "a.b",
        "...",
        token + ".extra",
        token[:-2],
    ]
    for bad in cases:
        with pytest.raises(MalformedTokenError):
            verify_token(bad, keyring, now=now)


def test_tampered_payload_fails_signature(keyring: KeyRing, now: int) -> None:
    token = issue_token(
        keyring, "alice", frozenset({"docs:read"}), 60, now=now, jti="j"
    )
    h, p, s = token.split(".")
    payload = json.loads(_b64d(p))
    payload["sub"] = "bob"  # 越权改身份
    p2 = _b64e(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    with pytest.raises(MalformedTokenError) as exc:
        verify_token(f"{h}.{p2}.{s}", keyring, now=now)
    assert "signature" in exc.value.message


def test_signature_with_wrong_secret(keyring: KeyRing, now: int) -> None:
    token = issue_token(keyring, "alice", frozenset(), 60, now=now, jti="j")
    h, p, _ = token.split(".")
    forged = _b64e(hmac.new(b"attacker", f"{h}.{p}".encode(), hashlib.sha256).digest())
    with pytest.raises(MalformedTokenError):
        verify_token(f"{h}.{p}.{forged}", keyring, now=now)


def test_unknown_kid_rejected(now: int) -> None:
    ring_a = KeyRing(b"secret-a", now=1000.0)
    ring_b = KeyRing(b"secret-b", now=1000.0)
    token = issue_token(ring_a, "alice", frozenset(), 60, now=now, jti="j")
    with pytest.raises(MalformedTokenError) as exc:
        verify_token(token, ring_b, now=now)
    assert exc.value.code == "malformed_token"


def test_incomplete_identity_missing_sub(keyring: KeyRing, now: int) -> None:
    token = issue_token(keyring, "alice", frozenset(), 60, now=now, jti="j")
    h, _, s = token.split(".")
    payload = {"scopes": ["docs:read"], "jti": "j", "iat": now, "exp": now + 60}
    p = _b64e(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    sig = _b64e(
        hmac.new(b"primary-secret", f"{h}.{p}".encode(), hashlib.sha256).digest()
    )
    with pytest.raises(IncompleteIdentityError) as exc:
        verify_token(f"{h}.{p}.{sig}", keyring, now=now)
    assert exc.value.code == "incomplete_identity"


def test_incomplete_identity_bad_scopes(keyring: KeyRing, now: int) -> None:
    token = issue_token(keyring, "alice", frozenset(), 60, now=now, jti="j")
    h, _, _ = token.split(".")
    payload = {"sub": "alice", "scopes": "docs:read", "jti": "j", "iat": now, "exp": now + 60}
    p = _b64e(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    sig = _b64e(
        hmac.new(b"primary-secret", f"{h}.{p}".encode(), hashlib.sha256).digest()
    )
    with pytest.raises(IncompleteIdentityError):
        verify_token(f"{h}.{p}.{sig}", keyring, now=now)


def test_deterministic_results_regardless_of_order(
    keyring: KeyRing, now: int
) -> None:
    """相同输入反复校验结论一致；不同调用顺序也不改变结果。"""
    good = issue_token(keyring, "alice", frozenset(), 60, now=now, jti="g")
    expired = issue_token(keyring, "bob", frozenset(), 1, now=now - 10, jti="e")

    # 顺序一：先验好令牌，再验过期令牌
    assert verify_token(good, keyring, now=now).sub == "alice"
    with pytest.raises(ExpiredTokenError):
        verify_token(expired, keyring, now=now)

    # 顺序二：先验过期令牌，再验好令牌 —— 结论不变
    with pytest.raises(ExpiredTokenError):
        verify_token(expired, keyring, now=now)
    assert verify_token(good, keyring, now=now).sub == "alice"

    # 相同输入重复判定完全一致
    for _ in range(3):
        assert verify_token(good, keyring, now=now).jti == "g"
