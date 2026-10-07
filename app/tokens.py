"""令牌签发与校验。

令牌格式（类 JWT，自包含、无外部依赖）：
    base64url(header) "." base64url(payload) "." base64url(signature)
- header:  {"alg": "HS256", "kid": <密钥标识>}
- payload: {"sub", "scopes", "exp", "iat", "jti", "kid", "gen"?}
  （gen 为可选的主体凭证世代，用于按用户批量吊销；旧令牌缺省按 0 处理）
- signature: HMAC-SHA256(signing_input, secret)

校验完全由输入（令牌串、密钥集合、当前时刻）决定，
不依赖任何可变全局状态，因此相同输入下判定结果可复现。
"""
from __future__ import annotations

import base64
import enum
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Iterable, Protocol


class TokenErrorKind(enum.Enum):
    """令牌校验失败原因，各类原因可区分。"""

    MALFORMED = "malformed"            # 结构无法解析
    TAMPERED = "tampered"              # 签名校验失败（被篡改或密钥不符）
    EXPIRED = "expired"                # 已过期
    INCOMPLETE = "incomplete"          # 身份信息不完整（缺少必要声明）
    REVOKED = "revoked"                # 已被吊销
    UNKNOWN_KEY = "unknown_key"        # 签名密钥不在可接受集合内


@dataclass(frozen=True)
class Claims:
    """令牌携带的身份声明。"""

    sub: str
    scopes: frozenset[str] = field(default_factory=frozenset)
    exp: int = 0
    iat: int = 0
    jti: str = ""
    kid: str = ""
    gen: int = 0  # 主体凭证世代：用于按用户批量吊销（旧令牌缺省为 0）


@dataclass(frozen=True)
class VerifyResult:
    """校验结论：成功时携带 claims，失败时携带可区分的原因。"""

    ok: bool
    claims: Claims | None = None
    error: TokenErrorKind | None = None
    detail: str = ""


class _KeyLike(Protocol):
    kid: str
    secret: bytes


_REQUIRED_CLAIMS = ("sub", "scopes", "exp", "iat", "jti", "kid")


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(signing_input: str, secret: bytes) -> str:
    digest = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return _b64url_encode(digest)


def issue_token(
    *,
    sub: str,
    scopes: Iterable[str],
    key: _KeyLike,
    now: int | None = None,
    ttl: int = 3600,
    jti: str | None = None,
    gen: int = 0,
) -> str:
    """签发令牌。显式传入 now 以保证可复现；缺省取当前时间。

    gen 为主体凭证世代，用于按用户批量吊销：同一次登录周期内签发的
    凭证携带相同世代，主体被整体吊销时世代推进，旧世代凭证立即失效。
    """
    if now is None:
        now = int(time.time())
    payload = {
        "sub": sub,
        "scopes": sorted(set(scopes)),
        "exp": now + ttl,
        "iat": now,
        "jti": jti or uuid.uuid4().hex,
        "kid": key.kid,
        "gen": gen,
    }
    header = {"alg": "HS256", "kid": key.kid}
    signing_input = (
        _b64url_encode(json.dumps(header, sort_keys=True).encode("utf-8"))
        + "."
        + _b64url_encode(json.dumps(payload, sort_keys=True).encode("utf-8"))
    )
    return signing_input + "." + _sign(signing_input, key.secret)


def verify_token(
    token: str,
    keys: Iterable[_KeyLike],
    *,
    now: int | None = None,
) -> VerifyResult:
    """校验令牌，返回可区分失败原因的结论。

    检查顺序固定（结构 -> 完整性 -> 密钥 -> 签名 -> 有效期），
    保证相同输入下结论可复现，与请求处理顺序无关。
    """
    if now is None:
        now = int(time.time())

    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return VerifyResult(False, error=TokenErrorKind.MALFORMED, detail="令牌须为三段式结构")

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return VerifyResult(False, error=TokenErrorKind.MALFORMED, detail="令牌内容无法解析")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return VerifyResult(False, error=TokenErrorKind.MALFORMED, detail="令牌内容须为 JSON 对象")

    missing = [name for name in _REQUIRED_CLAIMS if name not in payload]
    if missing:
        return VerifyResult(
            False,
            error=TokenErrorKind.INCOMPLETE,
            detail=f"缺少必要声明: {', '.join(missing)}",
        )
    if not isinstance(payload["sub"], str) or not payload["sub"]:
        return VerifyResult(False, error=TokenErrorKind.INCOMPLETE, detail="sub 必须为非空字符串")
    if not isinstance(payload["scopes"], list) or not all(
        isinstance(s, str) for s in payload["scopes"]
    ):
        return VerifyResult(False, error=TokenErrorKind.INCOMPLETE, detail="scopes 必须为字符串数组")
    # gen 为可选声明（旧令牌不带），存在时必须为非负整数；缺失按世代 0 处理
    if "gen" in payload and (
        not isinstance(payload["gen"], int)
        or isinstance(payload["gen"], bool)
        or payload["gen"] < 0
    ):
        return VerifyResult(False, error=TokenErrorKind.INCOMPLETE, detail="gen 必须为非负整数")

    kid = payload["kid"]
    key = next((k for k in keys if k.kid == kid), None)
    if key is None:
        return VerifyResult(
            False, error=TokenErrorKind.UNKNOWN_KEY, detail=f"未知密钥标识: {kid}"
        )

    signing_input = parts[0] + "." + parts[1]
    expected = _sign(signing_input, key.secret)
    if not hmac.compare_digest(expected, parts[2]):
        return VerifyResult(False, error=TokenErrorKind.TAMPERED, detail="签名校验失败")

    try:
        exp = int(payload["exp"])
    except (TypeError, ValueError):
        return VerifyResult(False, error=TokenErrorKind.INCOMPLETE, detail="exp 必须为整数时间戳")
    if now >= exp:
        return VerifyResult(
            False, error=TokenErrorKind.EXPIRED, detail=f"令牌已于 exp={exp} 过期"
        )

    claims = Claims(
        sub=payload["sub"],
        scopes=frozenset(payload["scopes"]),
        exp=exp,
        iat=int(payload["iat"]),
        jti=str(payload["jti"]),
        kid=kid,
        gen=int(payload.get("gen", 0)),
    )
    return VerifyResult(True, claims=claims)
