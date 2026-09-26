# 鉴权与访问控制说明

本文档描述服务的令牌鉴权模型、权限范围语义、吊销与密钥轮换规则、配额策略，
以及如何验证这些行为。

## 1. 总体模型

所有受保护接口（`GET/PUT /resources/{name}`）都经过同一个门禁
`AuthService.guard(token, resource, action)`。门禁按**固定顺序**执行五步判定，
任何入口、任何请求顺序下，相同输入的结论一致且可复现：

| 顺序 | 判定 | 失败错误码 | HTTP 状态 |
|----|------|-----------|----------|
| 1 | 是否携带凭证 | `missing_token` | 401 |
| 2 | 凭证是否合法（结构/签名/时间/身份完整性） | `malformed_token` / `token_expired` / `incomplete_identity` | 401 |
| 3 | 是否已吊销 | `token_revoked` | 401 |
| 4 | 是否具备所需权限范围 | `insufficient_scope` | **403** |
| 5 | 是否仍有配额 | `quota_exceeded` | **429** |

顺序的设计意图：

- “身份有问题”先于“权限不足”，因此匿名或失效凭证永远得到 401；
  只有身份合法才可能得到 403，**“未携带身份”与“身份合法但权限不足”被明确区分**。
- 配额放在授权之后：越权请求不会消耗配额，也不会触发配额副作用。
- 所有失败都以独立错误码 + 独立 HTTP 状态显式拒绝，**不做任何静默降级**。

错误响应统一格式：

```json
{
  "error": {
    "code": "insufficient_scope",
    "message": "requires scope 'docs:write'; granted=['docs:read']",
    "resource": "docs",
    "action": "write"
  }
}
```

判定依据会写入日志，例如
`decision=missing_token reason=no_credentials`、
`decision=quota_check sub=alice allowed=False used=3/3`，
测试日志中同步打印输入（resource/action/是否携带凭证）与判定依据。

## 2. 凭证（令牌）

令牌为自包含紧凑字符串：

```
base64url(header) . base64url(payload) . base64url(HMAC_SHA256(header.payload, key))
```

- header：`{"alg": "HS256", "typ": "TAC1", "kid": "<签名密钥id>"}`
- payload：`{"sub": 主体, "scopes": ["资源:动作", ...], "jti": 唯一id, "iat": 签发时间, "exp": 过期时间}`
- 时间均为 Unix 秒。

### 校验的固定优先级

1. **结构**：必须恰好为三段且无空段，否则 `malformed_token`。
2. **签名**：`kid` 未知/已退役、base64/JSON 非法、算法或类型不符、
   HMAC 不匹配（常数时间比较），均为 `malformed_token`。
   任何对 payload 的篡改都会使签名失效。
3. **过期**：签名合法后检查时间，**当前时间 `now >= exp` 即过期**，
   报 `token_expired`。
4. **身份完整性**：`sub` 必须是非空字符串、`scopes` 必须是字符串列表、
   `jti` 非空、`iat/exp` 为整数，否则 `incomplete_identity`。

因为先验签名再看内容，篡改过的令牌不会伪装成“过期”或“身份不完整”，
失败原因不会被攻击者通过构造内容误导。

## 3. 权限范围（Scope）语义

- 形式：`<resource>:<action>`，`action ∈ {read, write}`。
- 读写**分别授权**：`docs:read` 仅允许读，`docs:write` 仅允许写；
  写权限不自动蕴含读权限。需要两种能力必须同时授予两个范围。
- 只承认显式授予的范围，不做隐式提升，结论确定、可复现。
- 越权写请求在门禁处即被拒绝，业务存储的写方法不会被调用，
  因此**越权写不改变任何业务状态**（由测试用快照前后对比固化）。

## 4. 凭证吊销

- `RevocationList` 以 `jti` 记录吊销状态，线程安全，吊销幂等且不可逆。
- 吊销检查发生在签名/时间/完整性校验之后（第 3 步）：
  一个已经过期或被篡改的凭证仍按第 2 步归类；只有本身合法的凭证才会报
  `token_revoked`，保证原因归类稳定、不重叠。

## 5. 密钥轮换

`KeyRing` 维护一枚当前密钥和零到多枚旧密钥，均由锁保护。

- **签发**：始终使用当前密钥（`expires_at is None`）。
- **校验接受集合** = `{当前密钥} ∪ {未到退役截止时间的旧密钥}`。
- **轮换** `rotate(grace_seconds=g)`：当前密钥被降级为旧密钥，
  截止时间为 `now + g`，同时装入新的随机密钥并返回其 `kid`。
- **宽限期语义（明确可解释）**：
  - `now < 退役时刻`：新旧密钥签发的凭证都可校验，实现轮换窗口内的平滑过渡；
  - `now >= 退役时刻`：旧密钥立即不再被接受，即使其令牌本身的 `exp` 尚未到达，
    也会因 `kid` 退佚而报 `malformed_token`（unknown or retired signing key）；
  - 再次轮换时，已过退役期的旧密钥会被清理。
- 边界均为闭区间判断，时间可注入（`now=`），相同输入结论可复现。

## 6. 配额策略

`FixedWindowQuota` 按主体（`sub`）做**固定时间窗口**计数：

- 每个 `window_seconds` 窗口内至多放行 `limit` 次；
- “读计数 + 判额度”在同一把锁、同一临界区完成，
  因此并发下**不超发**（第 limit+1 次确定被拒）也**不漏计**（每次放行恰好 +1）；
- 超额时计数**不增加**，由门禁抛出 `quota_exceeded`（429），显式拒绝；
- 窗口以时间为唯一依据，到达边界即开新窗，与请求到达顺序无关；
- 不同主体的计数器相互独立。

## 7. 接口一览

| 方法 路径 | 鉴权 | 所需 scope | 说明 |
|----------|------|-----------|------|
| `GET /` | 无 | — | 公开，保持 `{"Hello": "World"}` |
| `GET /healthz` | 无 | — | 公开健康检查 |
| `POST /issue-token` | 无（默认关闭） | — | 联调/测试签发入口，生产关闭 |
| `GET /resources/{name}` | Bearer | `{name}:read` | 受保护读 |
| `PUT /resources/{name}` | Bearer | `{name}:write` | 受保护写 |

请求头：`Authorization: Bearer <token>`。
无头 → `missing_token`；有头但方案不是 Bearer → `malformed_token`。

## 8. 如何验证

```bash
# 运行全部单测（日志中可见输入与判定依据）
uv run python -m pytest -q

# 只看某一类场景
uv run python -m pytest tests/test_tokens.py            # 过期/篡改/身份不完整
uv run python -m pytest tests/test_keys.py              # 轮换窗口
uv run python -m pytest tests/test_quota_concurrency.py # 并发不超发
uv run python -m pytest tests/test_api.py               # 端到端错误归类/公开行为回归
```

测试覆盖：

- 正常：合法令牌读/写、签发即可用；
- 边界：过期边界 `now == exp`、轮换宽限期边界、配额窗口边界、并发 1/8/32 线程；
- 失败归类：匿名、错误方案、篡改、过期、身份不完整、越权、吊销、配额耗尽，
  各自错误码与 HTTP 状态一一对应；
- 顺序无关：改变校验/请求顺序结论不变；
- 状态安全：越权写后业务快照不变；
- 回归：`GET /` 公开行为与响应体保持不变。

手动联调：

```bash
uv run python main.py            # 启动，默认开启 /issue-token
curl -s localhost:8000/          # 公开
TOK=$(curl -s -X POST localhost:8000/issue-token \
  -H 'Content-Type: application/json' \
  -d '{"subject":"alice","scopes":["docs:read"],"ttl_seconds":3600}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s localhost:8000/resources/docs -H "Authorization: Bearer $TOK"
```
