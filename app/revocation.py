"""凭证吊销登记。

按 jti 记录已吊销令牌；集合只增不减，判定为纯查询，
线程安全，任意并发下结论一致。
"""
from __future__ import annotations

import threading


class RevocationRegistry:
    """线程安全的已吊销 jti 集合。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revoked: set[str] = set()

    def revoke(self, jti: str) -> None:
        with self._lock:
            self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked
