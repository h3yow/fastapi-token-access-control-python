"""密钥管理：支持轮换窗口内新旧密钥并存。

语义（明确且可解释）：
- 当前签发密钥 ``expires_at is None``，用于签发新凭证；
- 校验接受集合 = {当前密钥} ∪ {未到退役截止时间的旧密钥}；
- 轮换时旧密钥被赋予 ``expires_at = now + grace_seconds`` 退役截止时间，
  宽限期内由旧密钥签发的令牌仍可校验；宽限期一过旧密钥立即不再被接受；
- 密钥环自身用锁保护，保证轮换与并发校验之间的可见性一致。
"""

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from time import time
from typing import Final

_DEFAULT_GRACE_SECONDS: Final[float] = 3600.0


@dataclass(frozen=True)
class SigningKey:
    """一枚 HMAC 签名密钥。"""

    kid: str
    secret: bytes
    issued_at: float
    expires_at: float | None = None  # 旧密钥的退役截止时间；None 表示当前密钥

    def accepted(self, now: float | None = None) -> bool:
        """该密钥在给定时刻是否仍可用于校验。"""
        moment = time() if now is None else now
        return self.expires_at is None or moment < self.expires_at

    def expired(self, now: float | None = None) -> bool:
        """旧密钥是否已过退役截止时间（当前密钥永不过期）。"""
        return not self.accepted(now)


def generate_secret(nbytes: int = 32) -> bytes:
    """生成密码学随机密钥材料。"""
    return secrets.token_bytes(nbytes)


def _new_kid() -> str:
    return secrets.token_hex(8)


class KeyRing:
    """密钥环，维护当前密钥与可接受的旧密钥。"""

    def __init__(
        self,
        secret: bytes | None = None,
        *,
        now: float | None = None,
    ) -> None:
        moment = time() if now is None else now
        current = SigningKey(
            kid=_new_kid(),
            secret=secret if secret is not None else generate_secret(),
            issued_at=moment,
            expires_at=None,
        )
        self._lock = threading.RLock()
        self._current = current
        self._retired: list[SigningKey] = []

    def current_kid(self) -> str:
        with self._lock:
            return self._current.kid

    def current_secret(self) -> bytes:
        with self._lock:
            return self._current.secret

    def secret_for(self, kid: str, *, now: float | None = None) -> bytes | None:
        """返回可接受密钥的 secret；未知或已退役返回 None。"""
        moment = time() if now is None else now
        with self._lock:
            if self._current.kid == kid:
                return self._current.secret
            for key in self._retired:
                if key.kid == kid:
                    return key.secret if key.accepted(moment) else None
            return None

    def rotate(
        self,
        new_secret: bytes | None = None,
        grace_seconds: float = _DEFAULT_GRACE_SECONDS,
        *,
        now: float | None = None,
    ) -> str:
        """轮换：当前密钥降级为带退役截止时间的旧密钥，装入新密钥。

        返回新密钥的 kid。宽限期 ``grace_seconds`` 必须为正。
        """
        if grace_seconds <= 0:
            raise ValueError("grace_seconds must be positive")
        moment = time() if now is None else now
        with self._lock:
            retired = SigningKey(
                kid=self._current.kid,
                secret=self._current.secret,
                issued_at=self._current.issued_at,
                expires_at=moment + grace_seconds,
            )
            self._retired.append(retired)
            # 顺带清理早已过期的旧密钥，避免无限增长。
            self._retired = [k for k in self._retired if k.accepted(moment)]
            self._current = SigningKey(
                kid=_new_kid(),
                secret=new_secret if new_secret is not None else generate_secret(),
                issued_at=moment,
                expires_at=None,
            )
            return self._current.kid

    def accepted_kids(self, *, now: float | None = None) -> tuple[str, ...]:
        """返回当前时刻仍被接受的全部 kid（当前密钥在前）。"""
        moment = time() if now is None else now
        with self._lock:
            kids = [self._current.kid]
            kids.extend(k.kid for k in self._retired if k.accepted(moment))
            return tuple(kids)


__all__ = ["SigningKey", "KeyRing", "generate_secret"]
