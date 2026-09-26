"""并发安全的配额限制。

按主体 (subject) 做固定窗口计数：
- 每个窗口长度 ``window_seconds``，窗口内至多放行 ``limit`` 次；
- “读计数 + 判额度”在同一把锁的同一临界区完成，
  因此并发请求不会超发（第 limit+1 次确定被拒）也不会漏计；
- 超额时计数不增加，直接返回 allowed=False，由上层抛 QuotaExceededError，
  绝不静默降级放行；
- 窗口切换以时间为唯一依据，结论与请求到达顺序无关、可复现。
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    remaining: int
    limit: int
    window_used: int


@dataclass
class _Window:
    started_at: float
    count: int


class FixedWindowQuota:
    """每主体每个时间窗口固定次数配额。"""

    def __init__(self, limit: int, window_seconds: float) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._limit = limit
        self._window = float(window_seconds)
        self._windows: dict[str, _Window] = {}
        self._lock = threading.Lock()

    @property
    def limit(self) -> int:
        return self._limit

    def _rollover(self, win: _Window, now: float) -> _Window:
        """若当前窗口已结束，开启新窗口（调用方持锁）。"""
        if now - win.started_at >= self._window:
            return _Window(started_at=now, count=0)
        return win

    def acquire(self, subject: str, *, now: float | None = None) -> QuotaDecision:
        """尝试占用一个配额；超额返回 allowed=False 且不增加计数。"""
        moment = time.time() if now is None else float(now)
        with self._lock:
            win = self._windows.get(subject)
            if win is None:
                win = _Window(started_at=moment, count=0)
                self._windows[subject] = win
            else:
                rolled = self._rollover(win, moment)
                if rolled is not win:
                    self._windows[subject] = rolled
                    win = rolled

            if win.count >= self._limit:
                return QuotaDecision(
                    allowed=False,
                    remaining=0,
                    limit=self._limit,
                    window_used=win.count,
                )
            win.count += 1
            return QuotaDecision(
                allowed=True,
                remaining=self._limit - win.count,
                limit=self._limit,
                window_used=win.count,
            )

    def usage(self, subject: str, *, now: float | None = None) -> int:
        """返回当前窗口内已用量（主要供观测/测试）。"""
        moment = time.time() if now is None else float(now)
        with self._lock:
            win = self._windows.get(subject)
            if win is None:
                return 0
            win = self._rollover(win, moment)
            return win.count

    def reset(self, subject: str | None = None) -> None:
        """清空配额计数；subject 为 None 时清空全部主体。"""
        with self._lock:
            if subject is None:
                self._windows.clear()
            else:
                self._windows.pop(subject, None)


__all__ = ["QuotaDecision", "FixedWindowQuota"]
