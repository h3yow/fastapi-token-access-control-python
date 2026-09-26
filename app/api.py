"""HTTP 入口：公开接口与受保护资源接口。

所有受保护入口共用同一 ``AuthService.guard`` 门禁，
保证匿名、越权、失效凭证在 GET/PUT 等任何入口下结论一致、可解释。

路由：
- GET  /                      公开接口（保持既有行为 {"Hello": "World"}）
- GET  /healthz               公开健康检查
- POST /issue-token           测试/受信运维用的签发入口（默认关闭，显式启用）
- GET  /resources/{name}      受保护读（需要 <name>:read）
- PUT  /resources/{name}      受保护写（需要 <name>:write）

错误响应统一形如：
    {"error": {"code": "...", "message": "...", "resource": ..., "action": ...}}
不同 code 与 HTTP 状态码一一对应，失败原因可区分。
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.errors import AuthError, MalformedTokenError
from app.keys import KeyRing
from app.resources import ResourceStore
from app.service import AuthService
from app.tokens import issue_token

logger = logging.getLogger("auth.api")

_BEARER_PREFIX = "Bearer "


class IssueTokenRequest(BaseModel):
    subject: str = Field(min_length=1)
    scopes: list[str]
    ttl_seconds: int = Field(default=3600, gt=0)


class WriteResourceRequest(BaseModel):
    value: str = Field(min_length=1)


def _extract_bearer(request: Request) -> str | None:
    header = request.headers.get("Authorization")
    if header is None:
        return None
    if not header.startswith(_BEARER_PREFIX):
        # 携带了 Authorization 但方案不是 Bearer：凭证格式非法，
        # 与“完全匿名”（无头）区分：匿名 -> missing_token，方案错 -> malformed_token。
        raise MalformedTokenError(
            "authorization scheme must be Bearer"
        )
    token = header[len(_BEARER_PREFIX) :].strip()
    return token or None


def _error_body(exc: AuthError, **extra: Any) -> dict[str, Any]:
    detail: dict[str, Any] = {"code": exc.code, "message": exc.message}
    detail.update(extra)
    return {"error": detail}


def create_app(
    auth: AuthService,
    store: ResourceStore,
    keyring: KeyRing | None = None,
    *,
    enable_issue_endpoint: bool = False,
) -> FastAPI:
    """构造应用并注册路由与统一错误处理。

    ``enable_issue_endpoint`` 打开后才暴露 /issue-token，便于联调与测试；
    生产环境应保持关闭，由独立的受信签发服务颁发凭证。
    """
    app = FastAPI(title="Token Access Control API", version="0.1.0")

    @app.exception_handler(AuthError)
    async def _on_auth_error(request: Request, exc: AuthError) -> JSONResponse:
        # 输入（路径中资源、动作）与判定依据（错误码、消息）一并入日志。
        logger.warning(
            "rejected path=%s code=%s message=%s",
            request.url.path,
            exc.code,
            exc.message,
        )
        resource = request.path_params.get("name")
        action = getattr(request.state, "required_action", None)
        extra: dict[str, Any] = {}
        if resource is not None:
            extra["resource"] = resource
        if action is not None:
            extra["action"] = action
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_body(exc, **extra),
            headers={"WWW-Authenticate": "Bearer"}
            if exc.status_code == 401
            else None,
        )

    @app.get("/")
    def read_root() -> dict[str, str]:
        # 既有公开行为，回归中必须保持不变。
        return {"Hello": "World"}

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    if enable_issue_endpoint:
        if keyring is None:
            raise ValueError("keyring is required when issue endpoint is enabled")

        @app.post("/issue-token")
        def issue(body: IssueTokenRequest) -> dict[str, str]:
            token = issue_token(
                keyring,
                body.subject,
                frozenset(body.scopes),
                body.ttl_seconds,
            )
            return {"access_token": token, "token_type": "Bearer"}

    def _guard_request(request: Request, name: str, action: str) -> Any:
        request.state.required_action = action
        token = _extract_bearer(request)
        logger.info(
            "input resource=%s action=%s presented=%s",
            name,
            action,
            token is not None,
        )
        return auth.guard(token, name, action)

    @app.get("/resources/{name}")
    def read_resource(request: Request, name: str) -> dict[str, Any]:
        principal = _guard_request(request, name, "read")
        value = store.read(name)
        if value is None:
            return JSONResponse(
                status_code=404,
                content={"error": {"code": "not_found", "resource": name}},
            )
        value["subject"] = principal.subject
        return value

    @app.put("/resources/{name}")
    def write_resource(
        request: Request, name: str, body: WriteResourceRequest
    ) -> dict[str, str]:
        _guard_request(request, name, "write")
        store.write(name, body.value)
        return {"resource": name, "value": body.value, "status": "written"}

    return app


__all__ = ["create_app"]
