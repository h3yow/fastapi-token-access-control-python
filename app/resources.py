"""受保护的示例业务资源。

使用锁保护内存状态；越权写请求在 ``AuthService`` 门禁处即被拒绝，
不会进入本模块，因此任何业务状态都不会被未授权写操作改变
（测试中以 ``snapshot()`` 前后对比来固化这一保证）。
"""

from __future__ import annotations

import threading


class ResourceStore:
    """内存键值资源存储。"""

    def __init__(self, initial: dict[str, str] | None = None) -> None:
        self._data: dict[str, str] = dict(initial or {})
        self._lock = threading.Lock()

    def read(self, resource: str) -> dict[str, str] | None:
        """读取资源；不存在返回 None。"""
        with self._lock:
            if resource not in self._data:
                return None
            return {"resource": resource, "value": self._data[resource]}

    def write(self, resource: str, value: str) -> None:
        """写入资源（调用方必须已通过写权限门禁）。"""
        with self._lock:
            self._data[resource] = value

    def snapshot(self) -> dict[str, str]:
        """返回当前状态副本，供断言状态未被改变。"""
        with self._lock:
            return dict(self._data)


__all__ = ["ResourceStore"]
