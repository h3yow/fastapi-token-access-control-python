"""凭证吊销登记与生命周期状态。

两类失效状态，均按 jti 记录、只增不减、线程安全：
- 吊销（revoke）：管理员显式吊销单个令牌，或按主体批量吊销其当前凭证；
- 已用于续期（consume）：令牌成功在线续期后，旧凭证立即失效，等价于被吊销。

按主体批量吊销依赖“签发绑定”：每个签发的 jti 登记到其主体名下；
revoke_subject 只吊销调用时绑定在该主体名下的 jti 快照，
不影响其他主体，也不影响之后重新签发（新 jti）的凭证。
重复执行与并发执行均安全：第二次起没有新凭证可吊销，返回 0。
"""
from __future__ import annotations

import threading


class RevocationRegistry:
    """线程安全的凭证失效登记（吊销 + 续期消费 + 主体绑定）。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revoked: set[str] = set()       # 被吊销的 jti
        self._consumed: set[str] = set()      # 已用于续期的旧 jti
        self._by_subject: dict[str, set[str]] = {}  # sub -> 当前绑定的 jti 集合

    def revoke(self, jti: str) -> None:
        with self._lock:
            self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        """jti 是否已失效（被吊销或已用于续期）。纯查询，并发下结论一致。"""
        with self._lock:
            return jti in self._revoked or jti in self._consumed

    def invalid_reason(self, jti: str) -> str | None:
        """返回失效原因描述；未失效返回 None。"""
        with self._lock:
            if jti in self._revoked:
                return "令牌已被吊销"
            if jti in self._consumed:
                return "令牌已用于续期，旧凭证立即失效"
            return None

    def register(self, sub: str, jti: str) -> None:
        """签发时把 jti 绑定到主体，供按主体批量吊销定位当前凭证。"""
        with self._lock:
            self._by_subject.setdefault(sub, set()).add(jti)

    def consume(self, jti: str) -> bool:
        """原子地标记 jti 已用于续期。

        仅当 jti 当前未吊销也未消费过时返回 True（本次续期成功）；
        已吊销或已消费过一律返回 False。检查与标记在同一把锁内完成，
        因此同一旧凭证并发续期时恰好一个成功，不可能复制出多张有效新凭证。
        """
        with self._lock:
            if jti in self._revoked or jti in self._consumed:
                return False
            self._consumed.add(jti)
            return True

    def revoke_subject(self, sub: str) -> int:
        """吊销该主体当前绑定的全部凭证，返回本次新失效的凭证数。

        只处理调用时绑定在该主体名下的 jti 快照：其他主体不受影响；
        之后重新签发的新 jti 不在快照内，同样不受影响。
        操作幂等：重复/并发调用时，后续调用返回 0。
        """
        with self._lock:
            jtis = self._by_subject.pop(sub, set())
            newly = 0
            for jti in jtis:
                if jti not in self._revoked and jti not in self._consumed:
                    newly += 1
                self._revoked.add(jti)
            return newly
