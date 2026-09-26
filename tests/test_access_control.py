"""服务层门禁：认证/授权/吊销/配额的顺序、区分度与状态安全。"""

from __future__ import annotations

import pytest

from app.errors import (
    ExpiredTokenError,
    InsufficientScopeError,
    MalformedTokenError,
    MissingTokenError,
    QuotaExceededError,
    RevokedTokenError,
)
from app.keys import KeyRing
from app.quota import FixedWindowQuota
from app.resources import ResourceStore
from app.service import AuthService
from app.tokens import issue_token


def _tok(keyring: KeyRing, sub: str, scopes, now: int, jti: str, ttl: int = 60) -> str:
    return issue_token(keyring, sub, frozenset(scopes), ttl, now=now, jti=jti)


def test_anonymous_is_distinguished_from_insufficient_scope(
    auth: AuthService, now: int
) -> None:
    # 未携带身份：401 系
    with pytest.raises(MissingTokenError) as e1:
        auth.guard(None, "docs", "read", now=now)
    assert e1.value.status_code == 401
    # 空串/空白也按匿名处理
    with pytest.raises(MissingTokenError):
        auth.guard("   ", "docs", "read", now=now)


def test_authenticated_but_forbidden_is_403(
    auth: AuthService, keyring: KeyRing, now: int
) -> None:
    token = _tok(keyring, "alice", {"docs:read"}, now, "j1")
    # 身份合法，但写权限不足：403，与 401 明确区分
    with pytest.raises(InsufficientScopeError) as e:
        auth.guard(token, "docs", "write", now=now)
    assert e.value.status_code == 403
    assert "docs:write" in e.value.message


def test_read_and_write_decisions_are_independent(
    auth: AuthService, keyring: KeyRing, now: int, quota: FixedWindowQuota
) -> None:
    token = _tok(keyring, "alice", {"docs:write"}, now, "j1")
    # 只有写权限：写允许，读拒绝
    assert auth.guard(token, "docs", "write", now=now).subject == "alice"
    quota.reset()
    with pytest.raises(InsufficientScopeError):
        auth.guard(token, "docs", "read", now=now)


def test_unauthorized_write_does_not_change_state(
    auth: AuthService, keyring: KeyRing, now: int
) -> None:
    store = ResourceStore(initial={"docs": "original"})
    token = _tok(keyring, "mallory", {"docs:read"}, now, "j1")
    before = store.snapshot()
    # 越权写必须在门禁处被拒
    with pytest.raises(InsufficientScopeError):
        auth.guard(token, "docs", "write", now=now)
        store.write("docs", "hacked")  # 不应执行到
    assert store.snapshot() == before == {"docs": "original"}


def test_revoked_token_rejected_after_authentication(
    auth: AuthService, keyring: KeyRing, revocations, now: int
) -> None:
    token = _tok(keyring, "alice", {"docs:read"}, now, "j-rev")
    revocations.revoke("j-rev")
    with pytest.raises(RevokedTokenError) as e:
        auth.guard(token, "docs", "read", now=now)
    assert e.value.status_code == 401


def test_failure_priority_order_is_fixed(
    auth: AuthService, keyring: KeyRing, revocations, now: int, quota: FixedWindowQuota
) -> None:
    """同时满足多个失败条件时，结论由固定优先级决定，与入口无关。"""
    # 吊销 + 权限不足 + 配额已满：吊销（认证阶段）优先
    token = _tok(keyring, "alice", {"other:read"}, now, "j1")
    revocations.revoke("j1")
    for _ in range(quota.limit):
        quota.acquire("alice", now=float(now))
    with pytest.raises(RevokedTokenError):
        auth.guard(token, "docs", "read", now=now)

    # 未吊销但权限不足 + 配额满：权限不足（403）优先，且不消耗配额
    token2 = _tok(keyring, "alice", {"other:read"}, now, "j2")
    with pytest.raises(InsufficientScopeError):
        auth.guard(token2, "docs", "read", now=now)
    assert quota.usage("alice", now=float(now)) == quota.limit


def test_expired_and_malformed_classified(
    auth: AuthService, keyring: KeyRing, now: int
) -> None:
    expired = _tok(keyring, "alice", {"docs:read"}, now, "jexp", ttl=1)
    with pytest.raises(ExpiredTokenError):
        auth.guard(expired, "docs", "read", now=now + 10)
    with pytest.raises(MalformedTokenError):
        auth.guard("not-a-token", "docs", "read", now=now)


def test_quota_exceeded_is_distinct_and_consumes_no_extra_slot(
    auth: AuthService, keyring: KeyRing, now: int, quota: FixedWindowQuota
) -> None:
    token = _tok(keyring, "alice", {"docs:read"}, now, "j1")
    for i in range(quota.limit):
        principal = auth.guard(token, "docs", "read", now=now)
        assert principal.subject == "alice"
    with pytest.raises(QuotaExceededError) as e:
        auth.guard(token, "docs", "read", now=now)
    assert e.value.status_code == 429
    # 被拒请求不增加计数
    assert quota.usage("alice", now=float(now)) == quota.limit


def test_same_input_reproducible_across_entry_actions(
    auth: AuthService, keyring: KeyRing, now: int
) -> None:
    token = _tok(keyring, "alice", set(), now, "j1")
    for action in ("read", "write"):
        for _ in range(2):
            with pytest.raises(InsufficientScopeError):
                auth.guard(token, "docs", action, now=now)
