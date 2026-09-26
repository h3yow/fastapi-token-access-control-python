"""应用装配入口。

默认装配一套内存态的密钥环、吊销列表与配额，方便本地启动验证。
生产中应把密钥、吊销状态与配额替换为持久化/共享实现。
"""

from __future__ import annotations

import uvicorn

from app.api import create_app
from app.keys import KeyRing
from app.quota import FixedWindowQuota
from app.resources import ResourceStore
from app.revocation import RevocationList
from app.service import AuthService

keyring = KeyRing()
revocations = RevocationList()
quota = FixedWindowQuota(limit=100, window_seconds=60.0)
auth_service = AuthService(keyring, revocations, quota)
store = ResourceStore(initial={"docs": "welcome"})

app = create_app(
    auth_service,
    store,
    keyring=keyring,
    enable_issue_endpoint=True,  # 本地联调用；生产应关闭
)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
