"""凭证吊销登记。

两类吊销，各自语义明确、线程安全：
- 按 jti 吊销：集合只增不减，判定为纯查询；既用于单个令牌吊销，
  也用于在线续期后旧凭证的一次性消费（revoke_once 原子判定是否首次）。
- 按主体批量吊销：每个主体维护单调递增的凭证世代（generation）。
  令牌签发时携带当时世代；推进世代后，该主体所有旧世代凭证立即失效，
  而推进之后签发的凭证携带新世代，不受影响；其他主体的世代不变。
"""
from __future__ import annotations

import threading


class RevocationRegistry:
    """线程安全的已吊销 jti 集合与主体凭证世代表。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revoked: set[str] = set()
        self._generations: dict[str, int] = {}

    def revoke(self, jti: str) -> None:
        with self._lock:
            self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked

    # ---- 凭证生命周期管理 ----

    def revoke_once(self, jti: str) -> bool:
        """原子地“一次性消费”jti：仅首次加入返回 True，之后恒返回 False。

        在线续期用它保证同一张旧凭证无论并发多少次续期请求，只有一个
        请求能换取新凭证；旧凭证随后等同被吊销。
        """
        with self._lock:
            if jti in self._revoked:
                return False
            self._revoked.add(jti)
            return True

    def current_generation(self, subject: str) -> int:
        """查询主体当前凭证世代；从未被整体吊销的主体世代为 0（纯查询）。"""
        with self._lock:
            return self._generations.get(subject, 0)

    def revoke_subject(self, subject: str) -> int:
        """吊销主体当前全部凭证：原子推进世代并返回推进后的世代号。

        重复/并发执行都安全：每次推进都使此前签发的凭证失效，
        而推进之后新签发的凭证携带最新世代，因此不受影响。
        """
        with self._lock:
            nxt = self._generations.get(subject, 0) + 1
            self._generations[subject] = nxt
            return nxt
