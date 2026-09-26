"""并发安全的配额限制。

策略：按主体（subject）的固定窗口计数。
- 窗口长度为 window_seconds，窗口起点对齐到 window_seconds 的整数倍，
  因此窗口边界只取决于 now，与请求到达顺序无关，判定可复现；
- acquire 在锁内完成“读计数 -> 判定 -> 递增”全过程，
  并发下不会超发（计数不超过 limit 的允许数）也不会漏计；
- 超出配额时返回 allowed=False 的显式结论，由上层以可区分状态拒绝，
  不做静默降级。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    used: int          # 本次请求计入后窗口内已用配额
    limit: int
    window_start: int


class QuotaLimiter:
    """按主体计数的固定窗口配额限制器（线程安全）。"""

    def __init__(self, *, limit: int, window_seconds: int) -> None:
        if limit <= 0:
            raise ValueError("limit 必须为正整数")
        if window_seconds <= 0:
            raise ValueError("window_seconds 必须为正整数")
        self._limit = limit
        self._window = window_seconds
        self._lock = threading.Lock()
        # subject -> (window_start, count)
        self._counters: dict[str, tuple[int, int]] = {}

    @property
    def limit(self) -> int:
        return self._limit

    def _window_start(self, now: int) -> int:
        return now - (now % self._window)

    def acquire(self, subject: str, *, now: int | None = None) -> QuotaDecision:
        """为 subject 申请一份配额，返回显式结论。"""
        if now is None:
            now = int(time.time())
        start = self._window_start(now)
        with self._lock:
            window_start, count = self._counters.get(subject, (start, 0))
            if window_start != start:
                window_start, count = start, 0
            if count >= self._limit:
                return QuotaDecision(False, used=count, limit=self._limit, window_start=start)
            count += 1
            self._counters[subject] = (window_start, count)
            return QuotaDecision(True, used=count, limit=self._limit, window_start=start)

    def usage(self, subject: str, *, now: int | None = None) -> int:
        """查询当前窗口已用配额（不消费）。"""
        if now is None:
            now = int(time.time())
        start = self._window_start(now)
        with self._lock:
            window_start, count = self._counters.get(subject, (start, 0))
            return count if window_start == start else 0
