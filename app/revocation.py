"""凭证吊销列表（线程安全）。

以令牌的唯一标识 ``jti`` 记录吊销状态。吊销是单向操作：一旦吊销不可恢复，
保证被吊销凭证在任何入口、任何时刻都得到 RevokedToken 结论。
"""

from __future__ import annotations

import threading


class RevocationList:
    """以 jti 记录已吊销凭证。"""

    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    def revoke(self, jti: str) -> None:
        """吊销指定 jti；重复吊销幂等。"""
        if not isinstance(jti, str) or not jti:
            raise ValueError("jti must be a non-empty string")
        with self._lock:
            self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked

    def count(self) -> int:
        with self._lock:
            return len(self._revoked)


__all__ = ["RevocationList"]
