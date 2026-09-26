"""权限范围（scope）与读写访问控制。

scope 形如 ``<resource>:<action>``，action ∈ {read, write}。
- 读写分别授权：``docs:read`` 允许读，``docs:write`` 允许写；
- 写权限不自动蕴含读，反之亦然；需要两种能力须同时授予两个范围；
- 只认显式授予的范围，不做隐式提升，判定结果确定且可复现。
"""

from __future__ import annotations

from dataclasses import dataclass

from app.errors import InsufficientScopeError

READ = "read"
WRITE = "write"
_ACTIONS = frozenset({READ, WRITE})


@dataclass(frozen=True)
class Scope:
    resource: str
    action: str

    @staticmethod
    def parse(raw: str) -> "Scope":
        if not isinstance(raw, str):
            raise ValueError("scope must be a string")
        resource, sep, action = raw.rpartition(":")
        if not sep or not resource or action not in _ACTIONS:
            raise ValueError(
                f"invalid scope {raw!r}; expected '<resource>:read|write'"
            )
        return Scope(resource=resource, action=action)

    def __str__(self) -> str:
        return f"{self.resource}:{self.action}"


def has_scope(granted: frozenset[str], resource: str, action: str) -> bool:
    """判断授予范围中是否包含对某资源的某动作权限。"""
    if action not in _ACTIONS:
        raise ValueError(f"unknown action {action!r}")
    return f"{resource}:{action}" in granted


def require_scopes_for(
    granted: frozenset[str], resource: str, action: str
) -> None:
    """权限不足时抛出 InsufficientScopeError，并在消息中指明所需范围。"""
    if not has_scope(granted, resource, action):
        required = f"{resource}:{action}"
        raise InsufficientScopeError(
            f"requires scope {required!r}; granted={sorted(granted)}"
        )


__all__ = ["READ", "WRITE", "Scope", "has_scope", "require_scopes_for"]
