"""凭证吊销与密钥轮换：吊销立即可拒、宽限期内新旧皆可、宽限期外旧密钥被拒。"""
from app.keys import SigningKey
from app.service import Decision
from app.tokens import issue_token
from tests.conftest import log_case


def test_revoked_token_rejected(service, key_store, revocation):
    token = issue_token(sub="alice", scopes=["doc:read"], key=key_store.current(),
                        now=0, ttl=1000, jti="j-revoke")
    before = service.authorize(token, resource="doc", action="read", now=10)
    log_case("before_revoke", {"jti": "j-revoke"}, before.decision, before.reason)
    assert before.decision == Decision.ALLOW

    revocation.revoke("j-revoke")
    after = service.authorize(token, resource="doc", action="read", now=11)
    log_case("after_revoke", {"jti": "j-revoke"}, after.decision, after.reason)
    assert after.decision == Decision.DENY_UNAUTHENTICATED
    assert "revoked" in after.reason


def test_revocation_does_not_affect_other_tokens(service, key_store, revocation):
    tok_a = issue_token(sub="a", scopes=["doc:read"], key=key_store.current(),
                        now=0, ttl=1000, jti="j-a")
    tok_b = issue_token(sub="b", scopes=["doc:read"], key=key_store.current(),
                        now=0, ttl=1000, jti="j-b")
    revocation.revoke("j-a")
    ra = service.authorize(tok_a, resource="doc", action="read", now=10)
    rb = service.authorize(tok_b, resource="doc", action="read", now=10)
    log_case("revoke_isolated", {"revoked": "j-a", "other": "j-b"},
             (ra.decision, rb.decision), "吊销仅影响目标 jti")
    assert ra.decision == Decision.DENY_UNAUTHENTICATED
    assert rb.decision == Decision.ALLOW


def test_rotation_grace_window_accepts_old_and_new(service, key_store):
    old_key = key_store.current()
    old_token = issue_token(sub="alice", scopes=["doc:read"], key=old_key,
                            now=0, ttl=10000, jti="j-old")
    key_store.rotate(SigningKey("k2", b"secret-2"), now=1000)
    new_token = issue_token(sub="alice", scopes=["doc:read"], key=key_store.current(),
                            now=1000, ttl=10000, jti="j-new")

    # 宽限期内（grace=100，轮换于 t=1000）：新旧令牌都接受
    r_old = service.authorize(old_token, resource="doc", action="read", now=1050)
    r_new = service.authorize(new_token, resource="doc", action="read", now=1050)
    log_case("grace_window", {"now": 1050, "rotated_at": 1000, "grace": 100},
             (r_old.decision, r_new.decision), "宽限期内新旧密钥均接受")
    assert r_old.decision == Decision.ALLOW
    assert r_new.decision == Decision.ALLOW


def test_after_grace_old_key_rejected_new_accepted(service, key_store):
    old_key = key_store.current()
    old_token = issue_token(sub="alice", scopes=["doc:read"], key=old_key,
                            now=0, ttl=100000, jti="j-old")
    key_store.rotate(SigningKey("k2", b"secret-2"), now=1000)
    new_token = issue_token(sub="alice", scopes=["doc:read"], key=key_store.current(),
                            now=1000, ttl=100000, jti="j-new")

    # 宽限期外（now=1100 == rotated_at + grace）：旧密钥以 unknown_key 拒绝
    r_old = service.authorize(old_token, resource="doc", action="read", now=1100)
    r_new = service.authorize(new_token, resource="doc", action="read", now=1100)
    log_case("after_grace", {"now": 1100, "rotated_at": 1000, "grace": 100},
             (r_old.decision, r_old.reason), "旧密钥移出可接受集合")
    assert r_old.decision == Decision.DENY_UNAUTHENTICATED
    assert "unknown_key" in r_old.reason
    assert r_new.decision == Decision.ALLOW


def test_rotation_semantics_deterministic(key_store):
    """轮换窗口判定只取决于 now，与查询顺序无关。"""
    key_store.rotate(SigningKey("k2", b"secret-2"), now=1000)
    kids = lambda now: [k.kid for k in key_store.acceptable_keys(now=now)]
    first = (kids(1050), kids(1100))
    second = (kids(1050), kids(1100))
    log_case("rotation_deterministic", {"now": [1050, 1100]}, first, "相同 now 判定一致")
    assert first == second == (["k2", "k1"], ["k2"])
