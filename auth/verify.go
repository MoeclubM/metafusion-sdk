package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 协议常量：算法、缓存与超时口径集中在这里，各服务不再各自声明。
const (
	// Algorithm 是唯一接受的签名算法：拒绝 none/HS*，避免算法混淆攻击。
	Algorithm = "RS256"
	// DefaultKeyCacheTTL 是 JWKS 公钥缓存的默认时长（到期后下一次验签重新拉取）。
	DefaultKeyCacheTTL = 10 * time.Minute
	// DefaultHTTPTimeout 是拉取 JWKS 的超时。
	DefaultHTTPTimeout = 5 * time.Second
	// SessionCookieName 是浏览器持有的会话 cookie 名：兜底解析与凭据转发都按它取。
	SessionCookieName = "mf_session"
)

// SessionResolver 是存量不透明会话令牌的兜底：用户可能还持有登录时发的 cookie 或
// 非 JWT 令牌，解 **只能问账号服务**（会话表在它那里），本服务不查任何人的库。
// nil 表示只接受 JWT（fail closed，不会静默放行）。
type SessionResolver interface {
	Resolve(ctx context.Context, bearer, cookie string) (*Principal, bool)
}

// Config 是验签器的装配参数。Issuer/Audience 必须与账号服务的签发侧一致，
// 否则存量令牌全部失效（两边都只读令牌，唯一要对齐的就是这两个值与公钥）。
type Config struct {
	Issuer   string
	Audience string
	// PublicKey 是静态公钥（PEM 或 base64 后的 PEM）。与 JWKSURL 同时配置时以它为准
	// （静态配置免一次网络往返，也便于账号服务未就绪时先启动）。
	PublicKey string
	// JWKSURL 指向账号服务的 JWKS 端点（如 http://auth:8081/api/oidc/jwks）。
	JWKSURL    string
	HTTPClient *http.Client
	// KeyCacheTTL 为 0 时用 DefaultKeyCacheTTL。
	KeyCacheTTL time.Duration
	// Now 可在测试中替换（TTL 与过期边界）；nil 表示 time.Now。
	Now func() time.Time
}

// Verifier 持有验签公钥并完成 RS256 验签，可并发使用。
//
// 没有静态公钥也没有 JWKS 地址时**不报错**：此时 Unavailable() 为真，一切令牌按未登录处理——
// 目录侧曾有"配置缺失就把写接口当匿名可写"的风险，这里保持 fail closed。
type Verifier struct {
	issuer   string
	audience string
	static   *rsa.PublicKey
	kid      string
	client   *http.Client
	jwksURL  string
	ttl      time.Duration
	now      func() time.Time

	fallback    SessionResolver
	unavailable bool

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// New 装配验签器。静态公钥解析失败（含误配私钥）时直接返回错误：这类配置错了就该
// 启动失败，而不是运行期才发现所有写请求都 401。
func New(cfg Config) (*Verifier, error) {
	v := &Verifier{
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		client:   cfg.HTTPClient,
		jwksURL:  strings.TrimSpace(cfg.JWKSURL),
		ttl:      cfg.KeyCacheTTL,
		now:      cfg.Now,
		keys:     map[string]*rsa.PublicKey{},
	}
	if v.client == nil {
		v.client = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	if v.ttl <= 0 {
		v.ttl = DefaultKeyCacheTTL
	}
	if v.now == nil {
		v.now = time.Now
	}
	if raw := strings.TrimSpace(cfg.PublicKey); raw != "" {
		key, err := ParsePublicKey(raw)
		if err != nil {
			return nil, err
		}
		v.static, v.kid = key, KeyID(key)
	}
	v.unavailable = v.static == nil && v.jwksURL == ""
	return v, nil
}

// Unavailable 表示既没有静态公钥也没有 JWKS 地址：所有令牌都会被拒绝。
func (v *Verifier) Unavailable() bool { return v == nil || v.unavailable }

// SetFallback 注入会话兜底解析器（nil 表示只接受 JWT）。
func (v *Verifier) SetFallback(r SessionResolver) { v.fallback = r }

// Issuer 与 Audience 返回生效的校验值（排障用：与账号服务的日志对照）。
func (v *Verifier) Issuer() string   { return v.issuer }
func (v *Verifier) Audience() string { return v.audience }

// KeyID 返回静态公钥的 kid；使用 JWKS 时为空（每个令牌自带 kid）。
func (v *Verifier) KeyID() string { return v.kid }

// Verify 校验签名、时间窗、issuer、audience 与 sub。任何一步失败都返回错误，
// 调用方据此按未登录处理（见 StatusFor）。
func (v *Verifier) Verify(token string) (*Claims, error) {
	if v == nil {
		return nil, ErrUnavailable
	}
	if v.unavailable {
		return nil, ErrUnavailable
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrMalformedToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header", ErrMalformedToken)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, fmt.Errorf("%w: header", ErrMalformedToken)
	}
	if header.Alg != Algorithm {
		return nil, fmt.Errorf("%w: %s", ErrUnexpectedAlgorithm, header.Alg)
	}
	key, err := v.publicKey(header.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature", ErrMalformedToken)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return nil, ErrBadSignature
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload", ErrMalformedToken)
	}
	var claims Claims
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload", ErrMalformedToken)
	}
	// exp 缺失等同于过期：签发侧一定会带 exp，缺字段的令牌只可能是伪造或旧格式。
	if claims.Expires == 0 || v.now().Unix() >= claims.Expires {
		return nil, ErrTokenExpired
	}
	if claims.Issuer != v.issuer {
		return nil, fmt.Errorf("%w: %s", ErrBadIssuer, claims.Issuer)
	}
	// audience 只认配置的那一个：id_token（aud 指向第三方客户端）不是给本服务的凭证。
	if v.audience != "" && !claims.Audience.Has(v.audience) {
		return nil, fmt.Errorf("%w: %v", ErrBadAudience, []string(claims.Audience))
	}
	if claims.Subject == "" {
		return nil, ErrMissingSubject
	}
	return &claims, nil
}

// publicKey 取验签公钥：静态公钥优先；否则按 kid 命中 JWKS 缓存。
// 未命中（含未知 kid，通常是账号服务刚轮换密钥）时强制刷新一次，再失败就报错。
func (v *Verifier) publicKey(kid string) (*rsa.PublicKey, error) {
	if v.static != nil {
		return v.static, nil
	}
	if v.unavailable {
		return nil, ErrUnavailable
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if key, ok := v.keys[kid]; ok && v.now().Sub(v.fetchedAt) < v.ttl {
		return key, nil
	}
	if err := v.refreshLocked(); err != nil {
		return nil, err
	}
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	// 轮换窗口：签名密钥可能刚换过，清空缓存再取一次。
	if err := v.refreshLocked(); err != nil {
		return nil, err
	}
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: kid=%s", ErrUnknownKey, kid)
}
