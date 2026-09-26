"""权限范围语义。

命名约定："<resource>:read" / "<resource>:write"。
- 读操作需要 "<resource>:read"；
- 写操作需要 "<resource>:write"；
- 读写相互独立：持有读权限不蕴含写权限，反之亦然，
  因此权限不足时同一资源的读与写结论各自确定；
- 支持通配 "*:*"（全权）与 "<resource>:*"（单资源全权），便于管理场景。
"""
from __future__ import annotations

READ_SUFFIX = ":read"
WRITE_SUFFIX = ":write"


def read_scope(resource: str) -> str:
    return resource + READ_SUFFIX


def write_scope(resource: str) -> str:
    return resource + WRITE_SUFFIX


def has_scope(granted: frozenset[str], required: str) -> bool:
    """判断已授予范围是否满足所需范围（确定性纯函数）。"""
    if required in granted:
        return True
    resource = required.rsplit(":", 1)[0]
    return "*:*" in granted or f"{resource}:*" in granted
