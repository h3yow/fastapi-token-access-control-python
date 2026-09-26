"""冒烟与回归：应用可构造、公开接口既有行为保持不变。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import create_app
from app.keys import KeyRing
from app.quota import FixedWindowQuota
from app.resources import ResourceStore
from app.revocation import RevocationList
from app.service import AuthService


def test_public_root_keeps_legacy_shape() -> None:
    keyring = KeyRing(b"k")
    auth = AuthService(keyring, RevocationList(), FixedWindowQuota(1, 60.0))
    client = TestClient(create_app(auth, ResourceStore()))
    resp = client.get("/")
    assert resp.status_code == 200
    # 既有公开行为：未鉴权即可访问，响应体保持 {"Hello": "World"}
    assert resp.json() == {"Hello": "World"}
