# FastAPI 令牌鉴权与细粒度访问控制

在既有 FastAPI 服务上补齐令牌鉴权、按权限范围的读写控制、凭证吊销、
密钥轮换与并发安全配额。所有判定对相同输入可复现，与请求处理顺序无关。

## 鉴权模型

令牌为自包含的三段式结构（类 JWT，仅依赖标准库 HMAC-SHA256）：

```
base64url(header) "." base64url(payload) "." base64url(signature)
```

- `header`: `{"alg": "HS256", "kid": <密钥标识>}`
- `payload`: `{"sub", "scopes", "exp", "iat", "jti", "kid"}`
- `signature`: `HMAC-SHA256(signing_input, secret)`

校验按固定顺序执行，失败原因可区分（`TokenErrorKind`）：

| 原因 | 含义 |
|---|---|
| `malformed` | 结构无法解析（非三段、非 JSON） |
| `incomplete` | 缺少必要声明（sub/scopes/exp/iat/jti/kid） |
| `unknown_key` | 签名密钥不在当前可接受集合内 |
| `tampered` | 签名校验失败（内容被篡改或密钥不符） |
| `expired` | 当前时刻不早于 `exp` |
| `revoked` | jti 已被吊销（在服务层判定） |

校验是纯函数：结果只取决于（令牌串、可接受密钥集合、当前时刻），
不依赖请求处理顺序，相同输入判定可复现。

## 权限范围语义

范围命名：`"<resource>:read"` / `"<resource>:write"`。

- 读、写权限相互独立，互不蕴含；权限不足时同一资源的读与写结论各自确定；
- 通配：`"<resource>:*"`（单资源全权）、`"*:*"`（全权）；
- 判定顺序固定：身份 → 吊销 → 权限 → 配额，结论映射为可区分的 HTTP 状态：

| 情形 | 结论 | 状态码 |
|---|---|---|
| 未携带凭证 / 凭证无效 / 已吊销 | `deny_unauthenticated` | 401 |
| 身份合法但权限不足 | `deny_forbidden` | 403 |
| 超出配额 | `deny_quota_exceeded` | 429 |
| 通过 | `allow` | 200 |

越权写操作在鉴权阶段即被拒绝，不触碰业务状态（测试
`test_unauthorized_write_does_not_change_state` 验证）。

## 吊销与密钥轮换

- **吊销**：按 `jti` 登记（`POST /admin/revoke`），集合只增不减、线程安全；
  吊销立即生效，仅影响目标 jti，以 `revoked` 原因拒绝。
- **轮换**（`POST /admin/keys/rotate`）：任意时刻只有一个当前密钥，新令牌
  一律用当前密钥签发；轮换后旧密钥进入宽限期（`grace_period` 秒，自轮换
  时刻起算），宽限期内新旧密钥签发的令牌均可接受；宽限期届满后旧密钥移出
  可接受集合，对应令牌以 `unknown_key` 拒绝。`acceptable_keys(now)` 为纯
  查询，相同 `now` 多次调用结果一致。

## 配额策略

按主体（`sub`）的固定窗口计数（`QuotaLimiter`）：

- 窗口起点对齐到窗口长度的整数倍，边界只取决于当前时刻；
- “读计数 → 判定 → 递增”在同一把锁内完成，并发下不超发（允许数恰为
  上限）也不漏计（拒绝请求不改变计数）；
- 仅对身份合法且权限足够的请求计配额；匿名与越权请求不消耗配额；
- 超限返回显式的 429 拒绝，不做静默降级；主体之间配额互不影响。

## HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/` | 公开探活（既有行为不变） |
| POST | `/tokens` | 签发令牌 `{sub, scopes, ttl}` |
| GET | `/resources/{name}` | 读资源（需 `<name>:read`） |
| PUT | `/resources/{name}` | 写资源（需 `<name>:write`） |
| POST | `/admin/revoke` | 按 jti 吊销 |
| POST | `/admin/keys/rotate` | 轮换签名密钥 |

身份通过 `Authorization: Bearer <token>` 头携带。

## 验证方法

```bash
uv run python -m pytest tests/ -q -s
```

`-s` 下每个用例会打印输入与判定依据（`[case=...] inputs=... -> decision=..., reason=...`）。
覆盖：正常签发校验、过期、篡改、声明不完整、未知密钥、匿名/越权区分、
越权写不改状态、吊销、轮换窗口（期内/期外）、并发配额（500 并发请求
对 50 上限）、配额窗口滚动、主体隔离，以及既有公开行为（`GET /`）回归。
