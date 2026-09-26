"""鉴权与访问控制门面：组合令牌校验、吊销、权限范围与配额。

判定顺序固定，保证可复现与可解释：
1. 身份：未携带凭证或凭证无效 -> DENY_UNAUTHENTICATED（原因细分见 reason）；
2. 吊销：凭证合法但已吊销     -> DENY_UNAUTHENTICATED（revoked）；
3. 权限：身份合法但范围不足   -> DENY_FORBIDDEN（不消耗配额、不改变业务状态）；
4. 配额：超出配额             -> DENY_QUOTA_EXCEEDED（显式拒绝，非静默降级）；
5. 全部通过                   -> ALLOW。
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass

from .keys import KeyStore
from .quota import QuotaLimiter
from .revocation import RevocationRegistry
from .scopes import has_scope, read_scope, write_scope
from .tokens import Claims, TokenErrorKind, verify_token


class Decision(enum.Enum):
    ALLOW = "allow"
    DENY_UNAUTHENTICATED = "deny_unauthenticated"   # 未携带身份或凭证无效
    DENY_FORBIDDEN = "deny_forbidden"               # 身份合法但权限不足
    DENY_QUOTA_EXCEEDED = "deny_quota_exceeded"     # 超出配额


@dataclass(frozen=True)
class AccessResult:
    decision: Decision
    reason: str
    claims: Claims | None = None


class AuthService:
    def __init__(
        self,
        *,
        key_store: KeyStore,
        revocation: RevocationRegistry,
        quota: QuotaLimiter,
    ) -> None:
        self._keys = key_store
        self._revocation = revocation
        self._quota = quota

    def authenticate(self, token: str | None, *, now: int | None = None) -> AccessResult:
        """仅校验身份：匿名与各类无效凭证在此区分。"""
        if now is None:
            now = int(time.time())
        if token is None or token == "":
            return AccessResult(Decision.DENY_UNAUTHENTICATED, "未携带身份凭证")
        result = verify_token(token, self._keys.acceptable_keys(now=now), now=now)
        if not result.ok:
            assert result.error is not None
            return AccessResult(
                Decision.DENY_UNAUTHENTICATED,
                f"凭证无效[{result.error.value}]: {result.detail}",
            )
        assert result.claims is not None
        if self._revocation.is_revoked(result.claims.jti):
            return AccessResult(
                Decision.DENY_UNAUTHENTICATED,
                f"凭证无效[{TokenErrorKind.REVOKED.value}]: 令牌已被吊销",
            )
        return AccessResult(Decision.ALLOW, "身份校验通过", claims=result.claims)

    def authorize(
        self,
        token: str | None,
        *,
        resource: str,
        action: str,
        now: int | None = None,
    ) -> AccessResult:
        """身份 + 权限 + 配额的完整访问判定。action 为 "read" 或 "write"。"""
        if now is None:
            now = int(time.time())
        if action == "read":
            required = read_scope(resource)
        elif action == "write":
            required = write_scope(resource)
        else:
            raise ValueError(f"不支持的操作: {action}")

        auth = self.authenticate(token, now=now)
        if auth.decision is not Decision.ALLOW:
            return auth
        assert auth.claims is not None

        if not has_scope(auth.claims.scopes, required):
            return AccessResult(
                Decision.DENY_FORBIDDEN,
                f"权限不足: 需要 {required}",
                claims=auth.claims,
            )

        quota = self._quota.acquire(auth.claims.sub, now=now)
        if not quota.allowed:
            return AccessResult(
                Decision.DENY_QUOTA_EXCEEDED,
                f"超出配额: 窗口内已用 {quota.used}/{quota.limit}",
                claims=auth.claims,
            )
        return AccessResult(Decision.ALLOW, "允许访问", claims=auth.claims)
