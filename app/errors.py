"""鉴权相关错误类型。

每类失败对应一个独立异常，错误码 (code) 用于对外输出可区分的失败原因，
保证同一输入在任何请求入口下结论一致。
"""

from __future__ import annotations


class AuthError(Exception):
    """所有鉴权/授权错误的基类。

    Attributes:
        code: 稳定的机器可读错误码。
        status_code: 建议的 HTTP 状态码。
        message: 人类可读说明（不泄露密钥等敏感细节）。
    """

    code: str = "auth_error"
    status_code: int = 401

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code


class MissingTokenError(AuthError):
    """未携带身份凭证（匿名访问受保护资源）。"""

    code = "missing_token"
    status_code = 401


class MalformedTokenError(AuthError):
    """凭证格式非法或被篡改（签名不匹配）。"""

    code = "malformed_token"
    status_code = 401


class IncompleteIdentityError(AuthError):
    """凭证通过签名校验，但身份信息不完整（缺少 sub / scopes 等）。"""

    code = "incomplete_identity"
    status_code = 401


class ExpiredTokenError(AuthError):
    """凭证已过期。"""

    code = "token_expired"
    status_code = 401


class RevokedTokenError(AuthError):
    """凭证已被吊销。"""

    code = "token_revoked"
    status_code = 401


class InsufficientScopeError(AuthError):
    """身份合法，但缺少所需权限范围。"""

    code = "insufficient_scope"
    status_code = 403


class QuotaExceededError(AuthError):
    """超出配额限制（显式拒绝，不做静默降级）。"""

    code = "quota_exceeded"
    status_code = 429


__all__ = [
    "AuthError",
    "MissingTokenError",
    "MalformedTokenError",
    "IncompleteIdentityError",
    "ExpiredTokenError",
    "RevokedTokenError",
    "InsufficientScopeError",
    "QuotaExceededError",
]
