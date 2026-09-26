"""密钥轮换：轮换窗口内新旧密钥接受语义明确，窗口外旧凭证被拒。"""

from __future__ import annotations

import pytest

from app.errors import MalformedTokenError
from app.keys import KeyRing
from app.tokens import issue_token, verify_token


def test_rotation_grace_window_accepts_both_keys() -> None:
    ring = KeyRing(b"old-secret", now=1000.0)
    old_token = issue_token(
        ring, "alice", frozenset({"docs:read"}), 100, now=1000, jti="old"
    )
    old_kid = ring.current_kid()

    new_kid = ring.rotate(b"new-secret", grace_seconds=60, now=1000.0)
    assert new_kid != old_kid

    # 新密钥签发的凭证可校验
    new_token = issue_token(
        ring, "bob", frozenset({"docs:read"}), 100, now=1000, jti="new"
    )
    # 宽限期内：新旧凭证都被接受
    assert ring.accepted_kids(now=1059.0) == (new_kid, old_kid)
    assert verify_token(new_token, ring, now=1059).sub == "bob"
    assert verify_token(old_token, ring, now=1059).sub == "alice"


def test_old_key_rejected_after_grace_window() -> None:
    ring = KeyRing(b"old-secret", now=1000.0)
    old_token = issue_token(
        ring, "alice", frozenset({"docs:read"}), 10_000, now=1000, jti="old"
    )
    new_kid = ring.rotate(b"new-secret", grace_seconds=60, now=1000.0)

    # 宽限期截止时刻：旧密钥立即不再被接受（即使令牌本身未过期）
    assert ring.accepted_kids(now=1060.0) == (new_kid,)
    with pytest.raises(MalformedTokenError) as exc:
        verify_token(old_token, ring, now=1060)
    assert exc.value.code == "malformed_token"
    assert "retired" in exc.value.message or "unknown" in exc.value.message


def test_rotation_requires_positive_grace() -> None:
    ring = KeyRing(b"k", now=0.0)
    with pytest.raises(ValueError):
        ring.rotate(b"k2", grace_seconds=0, now=1.0)


def test_second_rotation_cleans_expired_retired() -> None:
    ring = KeyRing(b"k0", now=0.0)
    kid0 = ring.current_kid()
    kid1 = ring.rotate(b"k1", grace_seconds=10, now=0.0)
    # 第二次轮换发生在第一把旧密钥退役之后：k0 被清理，接受集合只含 k2、k1
    kid2 = ring.rotate(b"k2", grace_seconds=10, now=20.0)
    assert ring.accepted_kids(now=20.0) == (kid2, kid1)
    assert kid0 not in ring.accepted_kids(now=20.0)
