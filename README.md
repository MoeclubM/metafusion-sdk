# metafusion-sdk — 协议层 SDK

MetaFusion 各服务之间**共用的协议**：访问令牌的验签、权限码、HTTP 约定。
它解决的是"同一件事在 2–5 个仓库里各写一份、靠注释要求逐字一致"的问题
（证据见主仓库 `docs/architecture/decoupling-audit-2026-09.md` §3）。

**只放协议，不放业务。** 这个仓库不 import 任何 web 框架，也**没有任何第三方依赖**：
验签用标准库实现，因此引入它不会给各服务增加供应链面积。

## 包

| 包 | 内容 |
| --- | --- |
| `auth` | `Claims` 结构（字段名与账号服务的签发侧逐字一致）、RS256 验签（静态公钥或 JWKS 缓存 + 未知 `kid` 强制刷新 + 10 分钟 TTL）、存量不透明会话令牌的兜底 client（`GET /api/auth/me`）、凭据提取与转发、`net/http` 中间件 |
| `perms` | 全部权限码常量（按服务分组）、`Can`/`CanAny`、`ValidCode` 格式校验 |
| `httpx` | 统一错误体 `{"error":"机器码"}` 与状态码映射、分页参数解析（`limit/offset` 与 `page/page_size` 兼容）、`/health` 与 `/ready`、服务标记头 `X-MetaFusion-Service`、`X-Request-ID` 中间件 |

## 放进 SDK 的与明确不进的

| 放进 SDK | 明确不进 SDK |
| --- | --- |
| `Claims` 字段名、RS256 验签、JWKS 缓存与轮换 | 签发（私钥只属于账号服务）；本 SDK 没有签发路径 |
| 会话兜底 client 的请求/响应形状 | 数据库访问、迁移执行 |
| 权限码常量与 `Can` 语义 | 判定规则：哪个端点要哪个码、实体级复核、**老令牌的角色兜底** |
| `{"error"}` 形状与状态码映射、分页口径、健康探针、服务标记头、request-id | 各服务的业务错误码（`invalid_term`、`hash_mismatch` 之类）、UI、日志后端、部署编排 |

角色兜底（`permissions` 为空时按 `role` 放行）**故意不进 SDK**：容忍它就会把
"角色兜底"变成绕过权限组的后门。各服务要保留兼容逻辑就自己写一层，并在自己的 README 里说明何时删除。

## 用法

```go
verifier, err := auth.New(auth.Config{
    Issuer:   os.Getenv("AUTH_JWT_ISSUER"),
    Audience: os.Getenv("AUTH_JWT_AUDIENCE"),
    // 二选一：静态公钥（PEM 或其 base64）或账号服务的 JWKS 地址。
    PublicKey: os.Getenv("AUTH_JWT_PUBLIC_KEY"),
    JWKSURL:   os.Getenv("AUTH_JWKS_URL"),
})
if err != nil {
    log.Fatalf("token verifier initialization failed: %v", err)
}
// 存量不透明会话令牌的兜底：身份只能问账号服务。
verifier.SetFallback(auth.NewSessionClient(os.Getenv("AUTH_URL"), 5*time.Second))

// net/http 侧：
handler := httpx.Chain(mux,
    httpx.ServiceMarker("metafusion-community"),
    httpx.SecurityHeaders,
    httpx.RequestID,
    verifier.Middleware, // 解析但不拦截
)
mux.Handle("/api/community/topics", verifier.Require(createTopic))
mux.HandleFunc("/health", httpx.Health("metafusion-community"))
mux.HandleFunc("/ready", httpx.Ready(httpx.Dependency{
    Name: "postgres",
    Ping: func(ctx context.Context) error { return db.PingContext(ctx) },
}))

// gin 侧自己接（SDK 不 import gin）：
//   status, code := httpx.ErrorStatus(err); c.JSON(status, gin.H{"error": code})
//   p := auth.PrincipalFromContext(c.Request.Context())
//   if p == nil || !perms.Can(p.Permissions, perms.CommunityPostCreate) { ... }

// 分页：同一端点同时接受 limit/offset 与 page/page_size，统一收敛为 Limit/Offset。
page := httpx.Default.ParseRequest(r) // 通用口径 50/100；长列表用 httpx.Tags（200/500）
```

## 与各服务现有实现的关系

语义与 `backend/internal/catalog/token.go`、`metafusion-community/internal/auth`、
`metafusion-storage/internal/auth` 现有实现一致（字段名、10 分钟 JWKS TTL、未知 `kid` 强制刷新、
`*` 通配、`limit` 越界静默收敛），但**这次不改任何服务**：三个服务的切换由主仓库审计文档的
B2 批次执行。切换时要留意的行为差异：

| 差异 | 说明 |
| --- | --- |
| 静态公钥不接受私钥 | 现有子系统实现会接受私钥并只取公钥部分；本 SDK 直接报错，避免"把签发私钥配给只验签的进程"继续发生（审计决议 D3）。改配 `openssl rsa -in key.pem -pubout` 的输出 |
| `aud` 支持字符串与数组 | 现有目录侧只接受单字符串，`aud` 为数组时会解析失败；本 SDK 两者都接受，且要求集合里含配置的 audience |
| 缺少 `exp` 视为过期 | 与目录侧现有行为一致 |
| 没有公钥来源时 `Unavailable()` 为真，`Verify` 直接返回 `ErrUnavailable` | fail closed：配置缺失不会变成"匿名可写"；调用方应在启动日志里告警 |
| 历史错误码收敛 | `httpx.Canonical("unauthorized")` → `authentication_required`（存储侧现在的 401 码） |
| `offset < 0` 收敛为 0 | 目录侧现在会把负数直接交给 SQL |

## 版本与验证

- 版本：`v0.x`，按 semver 打 tag 后由各服务在 `go.mod` 里引入；协议字段的任何改名都是破坏性变更。
- 验证：`go build ./... && go vet ./... && go test ./... -count=1`，`gofmt -l .` 必须为空。
- 测试覆盖反例：过期/缺 `exp`、错 issuer、错 audience（含数组形态）、错算法（`none`/`HS256`）、
  载荷篡改、未知 `kid` 触发刷新、TTL 到期重拉、JWKS 不可用、静态公钥优先、并发验签、
  `Can` 通配与空集合、权限码冻结清单、分页越界收敛、`/ready` 失败不外泄细节、request-id 透传与超长丢弃。
