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
import uuid
from dataclasses import dataclass

from .keys import KeyStore
from .quota import QuotaLimiter
from .revocation import RevocationRegistry
from .scopes import has_scope, read_scope, write_scope
from .tokens import Claims, TokenErrorKind, issue_token, verify_token


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


@dataclass(frozen=True)
class RenewalResult:
    """续期结论：ALLOW 时携带新令牌串与新声明，否则携带可区分原因。"""

    decision: Decision
    reason: str
    token: str | None = None
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
        invalid = self._revocation.invalid_reason(result.claims.jti)
        if invalid is not None:
            return AccessResult(
                Decision.DENY_UNAUTHENTICATED,
                f"凭证无效[{TokenErrorKind.REVOKED.value}]: {invalid}",
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

    def renew(
        self,
        token: str | None,
        *,
        ttl: int | None = None,
        now: int | None = None,
    ) -> RenewalResult:
        """在线续期：旧凭证换发身份与范围完全一致的新凭证。

        判定顺序固定，与访问鉴权保持一致：
        1. 身份：旧凭证必须有效（匿名/不完整/篡改/过期/已吊销/已续期一律拒绝）；
        2. 配额：续期请求照常按主体计数（不构成绕过限流的后门），超限 429；
        3. 原子消费：同一旧凭证的并发续期恰好一个成功（consume 在锁内判定+标记），
           落败者按 revoked 拒绝；成功时旧凭证立即失效，新凭证的 sub/scopes
           逐字沿用旧凭证（权限不放大），有效期自 now 起重新计算。
        """
        if now is None:
            now = int(time.time())

        auth = self.authenticate(token, now=now)
        if auth.decision is not Decision.ALLOW:
            return RenewalResult(auth.decision, auth.reason)
        old = auth.claims
        assert old is not None

        # 有效期长度沿用原凭证：新 exp - now == 旧 exp - 旧 iat，避免借续期改变时长。
        effective_ttl = old.exp - old.iat if ttl is None else ttl

        quota = self._quota.acquire(old.sub, now=now)
        if not quota.allowed:
            return RenewalResult(
                Decision.DENY_QUOTA_EXCEEDED,
                f"超出配额: 窗口内已用 {quota.used}/{quota.limit}",
                claims=old,
            )

        if not self._revocation.consume(old.jti):
            reason = self._revocation.invalid_reason(old.jti) or "令牌已失效"
            return RenewalResult(
                Decision.DENY_UNAUTHENTICATED,
                f"凭证无效[{TokenErrorKind.REVOKED.value}]: {reason}",
                claims=old,
            )

        new_jti = uuid.uuid4().hex
        current_key = self._keys.current()
        new_token = issue_token(
            sub=old.sub,
            scopes=sorted(old.scopes),
            key=current_key,
            now=now,
            ttl=effective_ttl,
            jti=new_jti,
        )
        new_claims = Claims(
            sub=old.sub,
            scopes=old.scopes,
            exp=now + effective_ttl,
            iat=now,
            jti=new_jti,
            kid=current_key.kid,
        )
        self._revocation.register(old.sub, new_jti)
        return RenewalResult(Decision.ALLOW, "续期成功", token=new_token, claims=new_claims)
