"""测试公共夹具与日志配置。

开启 auth.* 日志，使单测日志中打印“输入 + 判定依据”。
"""

from __future__ import annotations

import logging

import pytest

from app.keys import KeyRing
from app.quota import FixedWindowQuota
from app.revocation import RevocationList
from app.service import AuthService


@pytest.fixture(autouse=True)
def _auth_logging(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="auth")


@pytest.fixture
def now() -> int:
    return 1_000_000_000


@pytest.fixture
def keyring() -> KeyRing:
    return KeyRing(b"primary-secret", now=1000.0)


@pytest.fixture
def revocations() -> RevocationList:
    return RevocationList()


@pytest.fixture
def quota() -> FixedWindowQuota:
    return FixedWindowQuota(limit=3, window_seconds=60.0)


@pytest.fixture
def auth(
    keyring: KeyRing,
    revocations: RevocationList,
    quota: FixedWindowQuota,
) -> AuthService:
    return AuthService(keyring, revocations, quota)
