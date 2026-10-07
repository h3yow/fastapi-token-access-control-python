"""HTTP 入口：令牌签发、受保护资源读写、吊销与密钥轮换。

状态码语义（可区分、非静默降级）：
- 401 未携带身份或凭证无效（reason 中细分 expired/tampered/incomplete/revoked/...）
- 403 身份合法但权限不足
- 429 超出配额
- 200 允许
"""
from __future__ import annotations

import base64
import json
import secrets
import threading
import time

import uvicorn
from fastapi import FastAPI, Header, Response
from pydantic import BaseModel

from app.keys import KeyStore, SigningKey
from app.quota import QuotaLimiter
from app.revocation import RevocationRegistry
from app.service import AuthService, Decision
from app.tokens import issue_token

_STATUS_BY_DECISION = {
    Decision.DENY_UNAUTHENTICATED: 401,
    Decision.DENY_FORBIDDEN: 403,
    Decision.DENY_QUOTA_EXCEEDED: 429,
}


class TokenRequest(BaseModel):
    sub: str
    scopes: list[str] = []
    ttl: int = 3600


class WriteRequest(BaseModel):
    content: str


class RevokeRequest(BaseModel):
    jti: str


class RevokeSubjectRequest(BaseModel):
    sub: str


def create_app(
    *,
    quota_limit: int = 100,
    quota_window_seconds: int = 60,
    rotation_grace_period: int = 300,
) -> FastAPI:
    key_store = KeyStore(
        SigningKey("k-initial", secrets.token_bytes(32)),
        grace_period=rotation_grace_period,
    )
    revocation = RevocationRegistry()
    quota = QuotaLimiter(limit=quota_limit, window_seconds=quota_window_seconds)
    service = AuthService(key_store=key_store, revocation=revocation, quota=quota)

    app = FastAPI(title="token-access-control")
    app.state.key_store = key_store
    app.state.revocation = revocation
    app.state.service = service
    # 业务状态：受保护资源内容；越权写不得改变它
    app.state.resources = {}
    app.state.resources_lock = threading.Lock()

    @app.get("/")
    def read_root():
        return {"Hello": "World"}

    @app.post("/tokens", status_code=201)
    def create_token(req: TokenRequest):
        key = key_store.current()
        now = int(time.time())
        token = issue_token(sub=req.sub, scopes=req.scopes, key=key, now=now, ttl=req.ttl)
        revocation.register(req.sub, _jti_of(token))
        return {"token": token, "kid": key.kid, "expires_at": now + req.ttl}

    @app.get("/resources/{name}")
    def read_resource(name: str, response: Response, authorization: str | None = Header(None)):
        token = _bearer_token(authorization)
        result = service.authorize(token, resource=name, action="read")
        if result.decision is not Decision.ALLOW:
            response.status_code = _STATUS_BY_DECISION[result.decision]
            return {"error": result.decision.value, "reason": result.reason}
        with app.state.resources_lock:
            content = app.state.resources.get(name)
        return {"name": name, "content": content}

    @app.put("/resources/{name}")
    def write_resource(
        name: str, req: WriteRequest, response: Response, authorization: str | None = Header(None)
    ):
        token = _bearer_token(authorization)
        result = service.authorize(token, resource=name, action="write")
        if result.decision is not Decision.ALLOW:
            # 越权/超限写：不触碰业务状态
            response.status_code = _STATUS_BY_DECISION[result.decision]
            return {"error": result.decision.value, "reason": result.reason}
        with app.state.resources_lock:
            app.state.resources[name] = req.content
        return {"name": name, "content": req.content}

    @app.post("/admin/revoke")
    def revoke_token(req: RevokeRequest):
        revocation.revoke(req.jti)
        return {"revoked": req.jti}

    @app.post("/tokens/renew")
    def renew_token(response: Response, authorization: str | None = Header(None)):
        token = _bearer_token(authorization)
        now = int(time.time())
        result = service.renew(token, now=now)
        if result.decision is not Decision.ALLOW:
            response.status_code = _STATUS_BY_DECISION[result.decision]
            return {"error": result.decision.value, "reason": result.reason}
        assert result.token is not None and result.claims is not None
        return {
            "token": result.token,
            "kid": result.claims.kid,
            "expires_at": result.claims.exp,
        }

    @app.post("/admin/revoke-subject")
    def revoke_subject(req: RevokeSubjectRequest):
        revoked = revocation.revoke_subject(req.sub)
        return {"sub": req.sub, "revoked_count": revoked}

    @app.post("/admin/keys/rotate", status_code=201)
    def rotate_keys():
        new_key = SigningKey(f"k-{secrets.token_hex(4)}", secrets.token_bytes(32))
        key_store.rotate(new_key)
        return {"current_kid": new_key.kid, "grace_period": key_store.grace_period}

    return app


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return value


def _jti_of(token: str) -> str:
    """从自包含令牌的 payload 中取出 jti（仅用于签发后的绑定登记）。"""
    payload_b64 = token.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))["jti"]


app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=0)
