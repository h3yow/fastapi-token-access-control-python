"""签名密钥管理与轮换。

轮换语义（明确且可解释）：
- 任意时刻只有一个“当前密钥”，新令牌一律用当前密钥签发；
- 轮换后旧密钥进入宽限期（grace_period 秒），宽限期内旧密钥签发的
  令牌仍可被接受（避免在途请求失败）；
- 宽限期以旧密钥被替换的时刻起算，超过宽限期后旧密钥被移出可接受集合，
  对应令牌以 UNKNOWN_KEY 被拒绝；
- 判定仅依赖 (令牌 kid, 当前时刻 now)，与请求处理顺序无关。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class SigningKey:
    kid: str
    secret: bytes


@dataclass(frozen=True)
class _RetiredKey:
    key: SigningKey
    retired_at: int  # 被替换的时刻


class KeyStore:
    """维护当前密钥与处于轮换宽限期内的旧密钥（线程安全）。"""

    def __init__(self, initial: SigningKey, *, grace_period: int = 300) -> None:
        if grace_period < 0:
            raise ValueError("grace_period 必须非负")
        self._lock = threading.Lock()
        self._current = initial
        self._grace_period = grace_period
        self._retired: list[_RetiredKey] = []

    @property
    def grace_period(self) -> int:
        return self._grace_period

    def current(self) -> SigningKey:
        with self._lock:
            return self._current

    def rotate(self, new_key: SigningKey, *, now: int | None = None) -> SigningKey:
        """轮换到 new_key，旧当前密钥进入宽限期。返回新的当前密钥。"""
        if now is None:
            now = int(time.time())
        with self._lock:
            if new_key.kid == self._current.kid:
                raise ValueError(f"新密钥与当前密钥 kid 重复: {new_key.kid}")
            self._retired.append(_RetiredKey(self._current, retired_at=now))
            self._current = new_key
            self._purge_locked(now)
            return self._current

    def acceptable_keys(self, *, now: int | None = None) -> list[SigningKey]:
        """当前时刻可接受验签的密钥集合：当前密钥 + 宽限期内的旧密钥。

        纯查询、不改变内部状态：相同 now 的多次调用结果一致，
        与调用顺序无关。
        """
        if now is None:
            now = int(time.time())
        with self._lock:
            retired = [
                r.key
                for r in self._retired
                if now < r.retired_at + self._grace_period
            ]
            return [self._current] + retired

    def _purge_locked(self, now: int) -> None:
        self._retired = [
            r for r in self._retired if now < r.retired_at + self._grace_period
        ]
