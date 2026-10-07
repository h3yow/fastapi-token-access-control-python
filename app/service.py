"""鉴权与访问控制门面：组合令牌校验、吊销、权限范围与配额。

判定顺序固定，保证可复现与可解释：
1. 身份：未携带凭证或凭证无效 -> DENY_UNAUTHENTICATED（原因细分见 reason）；
   无效包括：结构/完整性问题、过期、密钥不可接受、签名被篡改、
   jti 已吊销（含已用于续期）、主体世代过期（按用户批量吊销）；
2. 权限：身份合法但范围不足   -> DENY_FORBIDDEN（不消耗配额、不改变业务状态）；
3. 配额：超出配额             -> DENY_QUOTA_EXCEEDED（显式拒绝，非静默降级）；
4. 全部通过                   -> ALLOW。

凭证生命周期：
- renew：以旧换新。顺序固定为 身份 -> 配额 -> 一次性消费旧 jti，
  续期请求照常计配额；并发续期只有一个能消费成功。
- revoke_subject：推进主体世代，使其当前所有凭证立即失效，
  不影响其他主体与该主体之后签发的凭证。
"""
from __future__ import annotations

import enum
import time
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
    """续期结论：成功时携带新凭证及其有效期与声明。"""

    decision: Decision
    reason: str
    token: str | None = None
    claims: Claims | None = None
    expires_at: int = 0


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
        claims = result.claims
        if self._revocation.is_revoked(claims.jti):
            return AccessResult(
                Decision.DENY_UNAUTHENTICATED,
                f"凭证无效[{TokenErrorKind.REVOKED.value}]: 令牌已被吊销",
            )
        if claims.gen != self._revocation.current_generation(claims.sub):
            return AccessResult(
                Decision.DENY_UNAUTHENTICATED,
                f"凭证无效[{TokenErrorKind.REVOKED.value}]: 主体已被整体吊销",
            )
        return AccessResult(Decision.ALLOW, "身份校验通过", claims=claims)

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

    # ---- 凭证生命周期管理 ----

    def issue(
        self,
        *,
        sub: str,
        scopes,
        ttl: int = 3600,
        now: int | None = None,
    ) -> tuple[str, int]:
        """按主体当前世代签发凭证，返回 (令牌, expires_at)。

        凭证携带签发时刻的世代；此后主体即使被整体吊销也不影响本凭证，
        因为本凭证已属于新世代。
        """
        if now is None:
            now = int(time.time())
        key = self._keys.current()
        gen = self._revocation.current_generation(sub)
        token = issue_token(
            sub=sub, scopes=scopes, key=key, now=now, ttl=ttl, gen=gen
        )
        return token, now + ttl

    def renew(self, token: str | None, *, now: int | None = None) -> RenewalResult:
        """在线续期：以一张有效旧凭证换取新凭证。

        固定顺序，保证可复现、不会放大权限、也不能绕过限流：
        1. 身份校验（匿名/过期/篡改/不完整/吊销/世代过期均在此归类拒绝）；
        2. 配额：续期请求本身按主体照常计数，超限以 429 语义拒绝且旧凭证保留；
        3. 一次性消费旧 jti：并发下只有一个请求成功，其余以 revoked 拒绝；
        4. 用当前密钥签发新凭证：sub/scopes/TTL 与旧凭证完全一致，
           新凭证携带主体当前世代（此时必与旧凭证相同）与全新 jti。
        """
        if now is None:
            now = int(time.time())
        auth = self.authenticate(token, now=now)
        if auth.decision is not Decision.ALLOW:
            return RenewalResult(auth.decision, auth.reason)
        old = auth.claims
        assert old is not None

        quota = self._quota.acquire(old.sub, now=now)
        if not quota.allowed:
            return RenewalResult(
                Decision.DENY_QUOTA_EXCEEDED,
                f"超出配额: 窗口内已用 {quota.used}/{quota.limit}",
            )

        if not self._revocation.revoke_once(old.jti):
            return RenewalResult(
                Decision.DENY_UNAUTHENTICATED,
                f"凭证无效[{TokenErrorKind.REVOKED.value}]: 旧凭证已用于续期或已被吊销",
            )

        ttl = old.exp - old.iat
        key = self._keys.current()
        new_token = issue_token(
            sub=old.sub,
            scopes=sorted(old.scopes),
            key=key,
            now=now,
            ttl=ttl,
            gen=self._revocation.current_generation(old.sub),
        )
        claims = verify_token(
            new_token, self._keys.acceptable_keys(now=now), now=now
        )
        assert claims.ok and claims.claims is not None
        return RenewalResult(
            Decision.ALLOW,
            "续期成功，旧凭证已失效",
            token=new_token,
            claims=claims.claims,
            expires_at=now + ttl,
        )

    def revoke_subject(self, subject: str) -> int:
        """按主体一次性吊销其当前全部凭证，返回推进后的世代号。

        幂等且线程安全：重复/并发执行只是连续推进世代，结论确定；
        仅影响该主体此前签发的凭证，不影响其他主体与之后新签发的凭证。
        """
        return self._revocation.revoke_subject(subject)
