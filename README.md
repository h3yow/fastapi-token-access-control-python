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

## 凭证生命周期：在线续期与按主体批量吊销

### 在线续期（`POST /tokens/renew`）

持有**未过期、未失效**凭证的主体可直接换取一张新凭证，无需重新登录。

- **身份与范围不放大**：新凭证的 `sub`、`scopes` 逐字沿用旧凭证，
  有效期长度沿用原凭证（`exp - iat`），仅把起点重置为当前时刻；
  端点不接受任何请求体，客户端无法借续期改 ttl、加范围或换主体。
- **旧凭证立即失效**：续期成功的同一把锁内把旧 `jti` 标记为“已用于续期”，
  此后旧凭证无论是访问资源还是再次续期，一律以 `revoked` 原因拒绝
  （reason 中可区分“已用于续期”与“已被吊销”）。
- **并发唯一成功**：`consume(jti)` 在锁内完成“检查未失效 → 标记”，
  同一旧凭证的并发续期恰好一个成功，不会复制出多张同时有效的新凭证；
  落败者得到 401 而不是服务端故障。
- **续期请求照常计配额**：判定顺序为 身份 → 配额 → 原子消费。
  超配额得到 429 且**不**作废当前凭证（新窗口内仍可续期），续期不是
  绕过限流的后门；已失效凭证在身份阶段即被拒，不消耗配额。
- **与密钥轮换兼容**：旧凭证在轮换宽限期内仍可验签、可以续期；
  新凭证一律用**当前密钥**签发。宽限期外旧凭证以 `unknown_key` 拒绝，
  不能借续期跨越密钥轮换。

### 按主体批量吊销（`POST /admin/revoke-subject`）

运维场景下一次性停掉某用户当前所有有效凭证：

- 签发（及续期）时每个 `jti` 都登记到其 `sub` 名下；批量吊销只处理
  调用时刻该主体名下的 jti 快照：**不波及其他主体**；
- **不影响之后重新签发的凭证**：批量吊销后该 `sub` 新签发的新 jti
  不在快照内，照常有效；再次批量吊销只吊销这批新凭证，语义完全对称；
- **幂等且并发安全**：重复或并发调用不出错，响应中的 `revoked_count`
  为本次**新**失效的凭证数，第二次起为 0；并发下新失效总数恰等于凭证数；
- 已被吊销或已用于续期的旧 jti 不会重复计数；与单个吊销
  （`POST /admin/revoke`）共用同一失效登记，失效立即生效。

### 失败归类（与既有能力对齐）

续期与批量吊销相关请求的拒绝结果稳定、可区分，异常输入不会变成
服务端故障，也绝不会被放行：

| 输入情形 | 结论 | 状态码 |
|---|---|---|
| 未携带 / 非 Bearer 凭证 | `deny_unauthenticated`（未携带） | 401 |
| 结构残缺、内容无法解析 | `deny_unauthenticated`（malformed） | 401 |
| 缺少必要声明 | `deny_unauthenticated`（incomplete） | 401 |
| 签名不符 / 被篡改 | `deny_unauthenticated`（tampered） | 401 |
| 已过期 | `deny_unauthenticated`（expired） | 401 |
| 已吊销 / 已用于续期 | `deny_unauthenticated`（revoked） | 401 |
| 超出配额（含续期请求） | `deny_quota_exceeded` | 429 |

所有判定只取决于（令牌串、密钥集合、当前时刻、登记状态），相同输入
多次执行结论一致，与请求先后顺序无关。

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
| POST | `/tokens/renew` | 在线续期（Bearer 旧凭证，无请求体），成功即旧凭证失效 |
| GET | `/resources/{name}` | 读资源（需 `<name>:read`） |
| PUT | `/resources/{name}` | 写资源（需 `<name>:write`） |
| POST | `/admin/revoke` | 按 jti 吊销 |
| POST | `/admin/revoke-subject` | 按主体批量吊销其当前凭证 `{sub}`，返回 `revoked_count` |
| POST | `/admin/keys/rotate` | 轮换签名密钥 |

身份通过 `Authorization: Bearer <token>` 头携带。

## 验证方法

```bash
uv run python -m pytest tests/ -q -s
```

`-s` 下每个用例会打印输入与判定依据（`[case=...] inputs=... -> decision=..., reason=...`）。
覆盖：正常签发校验、过期、篡改、声明不完整、未知密钥、匿名/越权区分、
越权写不改状态、吊销、轮换窗口（期内/期外）、并发配额（500 并发请求
对 50 上限）、配额窗口滚动、主体隔离，以及续期与批量吊销：
续期成功后旧凭证立即失效、并发续期唯一成功、续期链范围不放大、
续期受配额约束且与密钥轮换兼容、不完整/异常凭证各归各类，
按主体批量吊销（含重复/并发执行）、不波及其它主体与重新签发的凭证，
以及既有公开行为（`GET /`）回归。

也可手动验证（先后两张令牌对比即可看到旧证立即失效）：

```bash
uv run uvicorn main:app --reload
TOK=$(curl -s -X POST localhost:8000/tokens \
  -H 'Content-Type: application/json' \
  -d '{"sub":"alice","scopes":["doc:read"]}' | python -c 'import sys,json;print(json.load(sys.stdin)["token"])')
# 续期：返回新 token，旧 token 立即失效
curl -s -X POST localhost:8000/tokens/renew -H "Authorization: Bearer $TOK"
# 按主体一次性吊销其当前所有凭证
curl -s -X POST localhost:8000/admin/revoke-subject \
  -H 'Content-Type: application/json' -d '{"sub":"alice"}'
```
