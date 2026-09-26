import logging

import pytest

from app.keys import KeyStore, SigningKey
from app.quota import QuotaLimiter
from app.revocation import RevocationRegistry
from app.service import AuthService

logger = logging.getLogger("verify")


@pytest.fixture(autouse=True)
def _configure_logging():
    logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)


def log_case(case: str, inputs: dict, decision, reason: str) -> None:
    """单测日志：打印输入与判定依据。"""
    logger.info("[case=%s] inputs=%s -> decision=%s, reason=%s", case, inputs, decision, reason)


@pytest.fixture
def key_store() -> KeyStore:
    return KeyStore(SigningKey("k1", b"secret-1"), grace_period=100)


@pytest.fixture
def revocation() -> RevocationRegistry:
    return RevocationRegistry()


@pytest.fixture
def service(key_store, revocation) -> AuthService:
    return AuthService(
        key_store=key_store,
        revocation=revocation,
        quota=QuotaLimiter(limit=5, window_seconds=60),
    )
