# fastapi-token-access-control

基于 FastAPI 的令牌鉴权与细粒度访问控制示例：在统一门禁下一致、可解释地处理
匿名访问、越权访问与失效凭证，并支持凭证吊销、密钥轮换与并发安全配额。

## 能力一览

- **凭证签发与校验**：HMAC-SHA256 自包含令牌；过期、被篡改、身份不完整分别归类为
  `token_expired` / `malformed_token` / `incomplete_identity`；固定校验顺序，结论可复现。
- **细粒度读写控制**：`<resource>:read|write` 范围分别授权，写不蕴含读；
  匿名（401 `missing_token`）与合法但权限不足（403 `insufficient_scope`）明确区分；
  越权写不改变业务状态。
- **吊销与轮换**：按 `jti` 线程安全吊销；密钥轮换带宽限窗口，窗口内新旧密钥都接受，
  窗口外旧密钥立即失效，语义明确。
- **并发配额**：按主体固定窗口计数，锁内完成“判定+计数”，不超发、不漏计；
  超额返回 429 `quota_exceeded`，不静默降级。
- **可观测**：单测与运行日志打印输入（资源/动作/是否携带凭证）与判定依据。

## 目录结构

```
app/
  errors.py      # 可区分的鉴权错误类型（错误码 + HTTP 状态）
  keys.py        # 密钥环与轮换窗口
  tokens.py      # 令牌签发/校验（固定顺序）
  revocation.py  # 线程安全吊销列表
  scopes.py      # 权限范围解析与读写判定
  quota.py       # 并发安全固定窗口配额
  service.py     # 统一门禁 AuthService（认证→授权→配额）
  resources.py   # 受保护的业务状态
  api.py         # FastAPI 入口与统一错误响应
main.py          # 应用装配
tests/           # 正常/边界/并发/回归测试
docs/ACCESS_CONTROL.md  # 鉴权模型与规则的详细说明
```

## 快速开始

```bash
uv run python main.py
```

运行测试：

```bash
uv run python -m pytest -q
```

鉴权模型、范围语义、吊销/轮换规则、配额策略与验证方法详见
[docs/ACCESS_CONTROL.md](docs/ACCESS_CONTROL.md)。
