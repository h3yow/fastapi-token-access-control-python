"""鉴权门面：组合校验链、吊销检查、权限判定与配额。

固定判定顺序（对任何入口一致、可复现，不因处理顺序不同而改变结论）：
1. 是否携带令牌                 -> MissingTokenError   (401)
2. 令牌合法性                   -> Malformed/Expired/IncompleteIdentity (401)
3. 是否已吊销                   -> RevokedTokenError   (401)
4. 是否具备所需 scope           -> InsufficientScopeError (403)
5. 是否仍有配额                 -> QuotaExceededError  (429)

注意顺序的解释性：“身份有问题”先于“权限不足”，因此匿名/失效凭证永远拿到 401，
只有身份合法才可能拿到 403；配额放在授权之后，权限不足的越权请求不会消耗配额，
也不可能在配额检查处产生副作用。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.errors import (
    MissingTokenError,
    QuotaExceededError,
    RevokedTokenError,
)
from app.keys import KeyRing
from app.quota import FixedWindowQuota
from app.revocation import RevocationList
from app.scopes import require_scopes_for
from app.tokens import Claims, verify_token

logger = logging.getLogger("auth.service")


@dataclass(frozen=True)
class Principal:
    """通过认证后的调用方身份。"""

    claims: Claims

    @property
    def subject(self) -> str:
        return self.claims.sub

    @property
    def scopes(self) -> frozenset[str]:
        return self.claims.scopes


class AuthService:
    """对外统一鉴权入口。"""

    def __init__(
        self,
        keyring: KeyRing,
        revocations: RevocationList,
        quota: FixedWindowQuota,
    ) -> None:
        self._keyring = keyring
        self._revocations = revocations
        self._quota = quota

    def authenticate(self, token: str | None, *, now: int | None = None) -> Principal:
        """步骤 1-3：存在性 -> 合法性 -> 吊销检查。"""
        if token is None or not token.strip():
            logger.info("decision=missing_token reason=no_credentials")
            raise MissingTokenError("authentication token is required")
        claims = verify_token(token, self._keyring, now=now)
        logger.info(
            "decision=authenticated sub=%s jti=%s scopes=%s exp=%s",
            claims.sub,
            claims.jti,
            sorted(claims.scopes),
            claims.exp,
        )
        if self._revocations.is_revoked(claims.jti):
            logger.info(
                "decision=revoked sub=%s jti=%s reason=jti_in_revocation_list",
                claims.sub,
                claims.jti,
            )
            raise RevokedTokenError(f"token {claims.jti} has been revoked")
        return Principal(claims=claims)

    def authorize(self, principal: Principal, resource: str, action: str) -> None:
        """步骤 4：权限判定。"""
        require_scopes_for(principal.scopes, resource, action)
        logger.info(
            "decision=authorized sub=%s resource=%s action=%s",
            principal.subject,
            resource,
            action,
        )

    def guard(
        self,
        token: str | None,
        resource: str,
        action: str,
        *,
        now: int | None = None,
    ) -> Principal:
        """完整门禁：认证 -> 授权 -> 配额占用，全部通过才返回身份。"""
        principal = self.authenticate(token, now=now)
        self.authorize(principal, resource, action)
        decision = self._quota.acquire(principal.subject, now=now)
        logger.info(
            "decision=quota_check sub=%s allowed=%s used=%s/%s resource=%s action=%s",
            principal.subject,
            decision.allowed,
            decision.window_used,
            decision.limit,
            resource,
            action,
        )
        if not decision.allowed:
            raise QuotaExceededError(
                f"quota exhausted for subject {principal.subject!r}: "
                f"{decision.window_used}/{decision.limit} in current window"
            )
        return principal


__all__ = ["Principal", "AuthService"]
