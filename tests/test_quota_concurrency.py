"""并发配额：高并发下不超发、不漏计，拒绝状态可区分。"""

from __future__ import annotations

import concurrent.futures as futures

import pytest

from app.errors import QuotaExceededError
from app.keys import KeyRing
from app.quota import FixedWindowQuota
from app.revocation import RevocationList
from app.service import AuthService
from app.tokens import issue_token


@pytest.mark.parametrize("workers", [1, 8, 32])
def test_concurrent_acquire_never_oversells(workers: int) -> None:
    quota = FixedWindowQuota(limit=250, window_seconds=60.0)
    total = 1000

    def one(_: int) -> bool:
        return quota.acquire("alice", now=1000.0).allowed

    with futures.ThreadPoolExecutor(max_workers=workers) as pool:
        decisions = list(pool.map(one, range(total)))

    accepted = sum(decisions)
    assert accepted == 250  # 恰好放行限额，不超发
    assert decisions.count(False) == total - 250  # 其余全部明确拒绝，不漏判
    assert quota.usage("alice", now=1000.0) == 250  # 计数不超发/漏计


def test_window_rollover_is_deterministic() -> None:
    quota = FixedWindowQuota(limit=2, window_seconds=10.0)
    assert quota.acquire("a", now=0.0).allowed
    assert quota.acquire("a", now=9.99).allowed
    assert not quota.acquire("a", now=9.99).allowed
    # 到达窗口边界即开新窗，结论只依赖时间
    assert quota.acquire("a", now=10.0).allowed
    assert quota.usage("a", now=10.0) == 1


def test_subjects_isolated() -> None:
    quota = FixedWindowQuota(limit=1, window_seconds=10.0)
    assert quota.acquire("a", now=0.0).allowed
    assert quota.acquire("b", now=0.0).allowed
    assert not quota.acquire("a", now=0.0).allowed


def test_quota_through_guard_raises_distinct_error() -> None:
    keyring = KeyRing(b"k")
    auth = AuthService(keyring, RevocationList(), FixedWindowQuota(1, 60.0))
    token = issue_token(keyring, "alice", frozenset({"docs:read"}), 60, now=1000, jti="j")
    assert auth.guard(token, "docs", "read", now=1000).subject == "alice"
    with pytest.raises(QuotaExceededError) as e:
        auth.guard(token, "docs", "read", now=1000)
    assert e.value.status_code == 429
    assert e.value.code == "quota_exceeded"
