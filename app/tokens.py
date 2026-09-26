"""令牌签发与校验。

令牌为自包含紧凑字符串：``b64url(header).b64url(payload).b64url(sig)``。

- header: ``{"alg": "HS256", "kid": "<签名密钥id>", "typ": "TAC1"}``
- payload: ``{"sub": 主体, "scopes": [范围...], "jti": 唯一id, "iat": 签发时间, "exp": 过期时间}``
- sig: HMAC-SHA256(header.payload, kid 对应密钥)

校验严格按固定顺序进行，任何入口下相同输入的结论一致、可复现：
1. 结构：必须为三段 -> MalformedToken
2. 签名：kid 未知/已退役、编码非法、签名不匹配 -> MalformedToken
3. 时间：exp < now -> ExpiredToken
4. 身份完整性：sub 非空字符串、scopes 为字符串列表 -> IncompleteIdentity
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from app.errors import (
    ExpiredTokenError,
    IncompleteIdentityError,
    MalformedTokenError,
)
from app.keys import KeyRing

_TOKEN_TYPE = "TAC1"
_ALG = "HS256"


@dataclass(frozen=True)
class Claims:
    """令牌中的身份声明。"""

    sub: str
    scopes: frozenset[str]
    jti: str
    iat: int
    exp: int


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(raw: str) -> bytes:
    # 严格 base64url：补齐 padding 并拒绝非法字符。
    try:
        padding = "=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode(raw + padding)
    except (ValueError, TypeError) as exc:
        raise MalformedTokenError("segment is not valid base64url") from exc


def _sign(signing_input: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, signing_input, hashlib.sha256).digest()


def _encode(segment: dict[str, Any]) -> str:
    return _b64encode(
        json.dumps(segment, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


def issue_token(
    keyring: KeyRing,
    subject: str,
    scopes: frozenset[str] | set[str] | tuple[str, ...],
    ttl_seconds: int,
    *,
    now: int | None = None,
    jti: str | None = None,
) -> str:
    """用当前密钥签发令牌。ttl 必须为正整数秒。"""
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    moment = int(time.time()) if now is None else int(now)
    kid = keyring.current_kid()
    secret = keyring.current_secret()
    header = {"alg": _ALG, "kid": kid, "typ": _TOKEN_TYPE}
    payload = {
        "sub": subject,
        "scopes": sorted(scopes),
        "jti": jti or secrets.token_hex(16),
        "iat": moment,
        "exp": moment + ttl_seconds,
    }
    h = _encode(header)
    p = _encode(payload)
    signing_input = f"{h}.{p}".encode("ascii")
    sig = _b64encode(_sign(signing_input, secret))
    return f"{h}.{p}.{sig}"


def _decode_json_segment(segment: str, what: str) -> Any:
    try:
        value = json.loads(_b64decode(segment).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedTokenError(f"{what} is not valid JSON") from exc
    return value


def verify_token(token: str, keyring: KeyRing, *, now: int | None = None) -> Claims:
    """校验令牌并返回声明；失败按固定优先级抛出可区分的 AuthError。"""
    moment = int(time.time()) if now is None else int(now)

    # 1) 结构：恰好三段
    if not isinstance(token, str) or token.count(".") != 2:
        raise MalformedTokenError("token must have 3 segments")
    h_b64, p_b64, s_b64 = token.split(".")
    if not h_b64 or not p_b64 or not s_b64:
        raise MalformedTokenError("empty segment")

    header = _decode_json_segment(h_b64, "header")
    payload = _decode_json_segment(p_b64, "payload")
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise MalformedTokenError("header/payload must be JSON objects")

    # 2) 签名：alg/typ 必须匹配，kid 必须仍被接受，签名必须常数时间相等
    if header.get("alg") != _ALG or header.get("typ") != _TOKEN_TYPE:
        raise MalformedTokenError("unsupported token type or algorithm")
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise MalformedTokenError("missing kid")
    secret = keyring.secret_for(kid, now=float(moment))
    if secret is None:
        raise MalformedTokenError("unknown or retired signing key")

    expected_sig = _sign(f"{h_b64}.{p_b64}".encode("ascii"), secret)
    try:
        provided_sig = _b64decode(s_b64)
    except MalformedTokenError:
        raise
    if not hmac.compare_digest(expected_sig, provided_sig):
        raise MalformedTokenError("signature mismatch")

    # 3) 过期（签名合法之后再看时间，避免用篡改内容触发误导性错误）
    exp = payload.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool):
        raise MalformedTokenError("exp must be an integer")
    # 语义：当前时间必须早于 exp；到达 exp 时刻即视为过期。
    if moment >= exp:
        raise ExpiredTokenError(f"token expired at {exp}")

    # 4) 身份完整性
    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise IncompleteIdentityError("subject (sub) is missing or empty")
    scopes_raw = payload.get("scopes")
    if not isinstance(scopes_raw, list) or not all(
        isinstance(s, str) for s in scopes_raw
    ):
        raise IncompleteIdentityError("scopes must be a list of strings")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise IncompleteIdentityError("jti is missing")
    iat = payload.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise IncompleteIdentityError("iat must be an integer")

    return Claims(
        sub=sub,
        scopes=frozenset(scopes_raw),
        jti=jti,
        iat=iat,
        exp=exp,
    )


__all__ = ["Claims", "issue_token", "verify_token"]
