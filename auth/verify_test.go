package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testIssuer   = "https://findverse.cc/api"
	testAudience = "metafusion"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

// testPrivateKey 只用于**测试里伪造令牌**：SDK 本身没有签发路径（私钥只在账号服务）。
// 生成一次并复用：2048 位 RSA 生成很慢，每个用例一把会把测试拖到几十秒。
func testPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = key
	})
	return testKey
}

func publicKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func privateKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// claims 造一份可用的载荷；调用方按需覆盖字段。
func claimsFixture(exp time.Time) map[string]any {
	return map[string]any{
		"sub":                "user-uuid",
		"preferred_username": "curator",
		"email":              "curator@example.invalid",
		"role":               "editor",
		"groups":             []string{"member"},
		"permissions":        []string{"catalog.entity.edit"},
		"iss":                testIssuer,
		"aud":                testAudience,
		"iat":                exp.Add(-time.Minute).Unix(),
		"exp":                exp.Unix(),
		"jti":                "jti-1",
	}
}

// sign 按 RS256 签一份令牌；header 可覆盖（用于 none/HS256/未知 kid 等反例）。
func sign(t *testing.T, key *rsa.PrivateKey, header map[string]any, claims map[string]any) string {
	t.Helper()
	if _, ok := header["alg"]; !ok {
		header["alg"] = Algorithm
	}
	if _, ok := header["typ"]; !ok {
		header["typ"] = "JWT"
	}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signing := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func staticVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := New(Config{
		Issuer:    testIssuer,
		Audience:  testAudience,
		PublicKey: publicKeyPEM(t, testPrivateKey(t)),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func TestVerifyStaticPublicKey(t *testing.T) {
	v := staticVerifier(t)
	token := sign(t, testPrivateKey(t), map[string]any{}, claimsFixture(time.Now().Add(15*time.Minute)))
	claims, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-uuid" || claims.Username != "curator" || claims.Role != "editor" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if len(claims.Permissions) != 1 || claims.Permissions[0] != "catalog.entity.edit" {
		t.Fatalf("permissions not parsed: %+v", claims.Permissions)
	}
	if !claims.Audience.Has(testAudience) {
		t.Fatalf("audience not parsed: %+v", claims.Audience)
	}
	if v.Unavailable() {
		t.Fatal("verifier with static key must not be unavailable")
	}
}

func TestNewAcceptsBase64PEM(t *testing.T) {
	pemText := publicKeyPEM(t, testPrivateKey(t))
	encoded := base64.StdEncoding.EncodeToString([]byte(pemText))
	v, err := New(Config{Issuer: testIssuer, Audience: testAudience, PublicKey: encoded})
	if err != nil {
		t.Fatalf("New with base64 PEM: %v", err)
	}
	if _, err = v.Verify(sign(t, testPrivateKey(t), map[string]any{}, claimsFixture(time.Now().Add(time.Minute)))); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestNewRejectsPrivateKeyConfig(t *testing.T) {
	_, err := New(Config{Issuer: testIssuer, Audience: testAudience, PublicKey: privateKeyPEM(t, testPrivateKey(t))})
	if !errors.Is(err, ErrPrivateKeyNotAllowed) {
		t.Fatalf("want ErrPrivateKeyNotAllowed, got %v", err)
	}
	if !strings.Contains(err.Error(), "only the account service") {
		t.Fatalf("error should name the fix, got %v", err)
	}
}

func TestNewRejectsGarbageKey(t *testing.T) {
	if _, err := New(Config{PublicKey: "not-a-pem"}); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("want ErrMalformedKey, got %v", err)
	}
	blank, err := New(Config{PublicKey: "   "})
	if err != nil {
		t.Fatalf("blank key means \"not configured\", got %v", err)
	}
	if !blank.Unavailable() {
		t.Fatal("blank key must leave the verifier unavailable (fail closed)")
	}
}

func TestVerifyFailures(t *testing.T) {
	key := testPrivateKey(t)
	v := staticVerifier(t)
	now := time.Now()

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrMalformedToken},
		{"not three parts", "abc.def", ErrMalformedToken},
		{"non base64 header", "!!!.def.ghi", ErrMalformedToken},
	}
	for _, tc := range cases {
		if _, err := v.Verify(tc.token); !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", tc.name, tc.want, err)
		}
	}

	token := sign(t, key, map[string]any{}, claimsFixture(now.Add(-time.Second)))
	if _, err := v.Verify(token); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired token: want ErrTokenExpired, got %v", err)
	}

	noExp := claimsFixture(now.Add(time.Minute))
	delete(noExp, "exp")
	if _, err := v.Verify(sign(t, key, map[string]any{}, noExp)); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("token without exp: want ErrTokenExpired, got %v", err)
	}

	wrongIssuer := claimsFixture(now.Add(time.Minute))
	wrongIssuer["iss"] = "https://evil.invalid/api"
	if _, err := v.Verify(sign(t, key, map[string]any{}, wrongIssuer)); !errors.Is(err, ErrBadIssuer) {
		t.Errorf("wrong issuer: want ErrBadIssuer, got %v", err)
	}

	wrongAud := claimsFixture(now.Add(time.Minute))
	wrongAud["aud"] = "other-service"
	if _, err := v.Verify(sign(t, key, map[string]any{}, wrongAud)); !errors.Is(err, ErrBadAudience) {
		t.Errorf("wrong audience: want ErrBadAudience, got %v", err)
	}

	audList := claimsFixture(now.Add(time.Minute))
	audList["aud"] = []string{"third-party-client", testAudience}
	if _, err := v.Verify(sign(t, key, map[string]any{}, audList)); err != nil {
		t.Errorf("audience list containing the configured value must pass, got %v", err)
	}

	audListMiss := claimsFixture(now.Add(time.Minute))
	audListMiss["aud"] = []string{"third-party-client"}
	if _, err := v.Verify(sign(t, key, map[string]any{}, audListMiss)); !errors.Is(err, ErrBadAudience) {
		t.Errorf("audience list without the configured value: want ErrBadAudience, got %v", err)
	}

	noSub := claimsFixture(now.Add(time.Minute))
	delete(noSub, "sub")
	if _, err := v.Verify(sign(t, key, map[string]any{}, noSub)); !errors.Is(err, ErrMissingSubject) {
		t.Errorf("missing subject: want ErrMissingSubject, got %v", err)
	}

	// 算法混淆：none 与 HS256 都必须被拒（HS256 用公钥 PEM 当 HMAC 密钥是经典攻击）。
	noneToken := sign(t, key, map[string]any{"alg": "none"}, claimsFixture(now.Add(time.Minute)))
	if _, err := v.Verify(noneToken); !errors.Is(err, ErrUnexpectedAlgorithm) {
		t.Errorf("alg=none: want ErrUnexpectedAlgorithm, got %v", err)
	}
	hsToken := sign(t, key, map[string]any{"alg": "HS256"}, claimsFixture(now.Add(time.Minute)))
	if _, err := v.Verify(hsToken); !errors.Is(err, ErrUnexpectedAlgorithm) {
		t.Errorf("alg=HS256: want ErrUnexpectedAlgorithm, got %v", err)
	}

	// 篡改载荷：签名必须失效。
	valid := sign(t, key, map[string]any{}, claimsFixture(now.Add(time.Minute)))
	parts := strings.Split(valid, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"someone-else"}`)) + "." + parts[2]
	if _, err := v.Verify(tampered); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered payload: want ErrBadSignature, got %v", err)
	}
}

func TestVerifyWithoutKeySource(t *testing.T) {
	v, err := New(Config{Issuer: testIssuer, Audience: testAudience})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !v.Unavailable() {
		t.Fatal("verifier without key source must report Unavailable")
	}
	if _, err = v.Verify("a.b.c"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable (fail closed), got %v", err)
	}
}

// jwksServer 是一台可换钥匙的 JWKS：keys 按 kid 提供，hits 统计拉取次数。
type jwksServer struct {
	*httptest.Server
	hits int32
	mu   sync.Mutex
	keys map[string]*rsa.PublicKey
}

func newJWKSServer(t *testing.T) *jwksServer {
	t.Helper()
	s := &jwksServer{keys: map[string]*rsa.PublicKey{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.hits, 1)
		s.mu.Lock()
		defer s.mu.Unlock()
		type jwk struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		}
		out := struct {
			Keys []jwk `json:"keys"`
		}{Keys: []jwk{}}
		for kid, key := range s.keys {
			out.Keys = append(out.Keys, jwk{
				KID: kid, KTY: "RSA",
				N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				E: base64.RawURLEncoding.EncodeToString([]byte{byte(key.E >> 16), byte(key.E >> 8), byte(key.E)}),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) set(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	kid := KeyID(&key.PublicKey)
	s.mu.Lock()
	s.keys[kid] = &key.PublicKey
	s.mu.Unlock()
	return kid
}

func (s *jwksServer) fetched() int { return int(atomic.LoadInt32(&s.hits)) }

func TestVerifyJWKSCacheAndRotation(t *testing.T) {
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key A: %v", err)
	}
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key B: %v", err)
	}

	auth := newJWKSServer(t)
	kidA := auth.set(t, keyA)

	// 可控时钟：TTL 边界不靠 sleep。
	now := time.Now()
	var clockMu sync.Mutex
	v, err := New(Config{
		Issuer: testIssuer, Audience: testAudience, JWKSURL: auth.URL + "/api/oidc/jwks",
		KeyCacheTTL: 10 * time.Minute,
		Now:         func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	claims := claimsFixture(now.Add(15 * time.Minute))
	if _, err = v.Verify(sign(t, keyA, map[string]any{"kid": kidA}, claims)); err != nil {
		t.Fatalf("verify with rotated-in key: %v", err)
	}
	if got := auth.fetched(); got != 1 {
		t.Fatalf("first verify must fetch JWKS once, got %d", got)
	}
	if _, err = v.Verify(sign(t, keyA, map[string]any{"kid": kidA}, claims)); err != nil {
		t.Fatalf("cached verify: %v", err)
	}
	if got := auth.fetched(); got != 1 {
		t.Fatalf("cache hit must not refetch, got %d", got)
	}

	// 未知 kid 触发强制刷新：首次拉取 + 两次强制刷新。
	if _, err = v.Verify(sign(t, keyA, map[string]any{"kid": "nope"}, claims)); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown kid: want ErrUnknownKey, got %v", err)
	}
	if got := auth.fetched(); got != 3 {
		t.Fatalf("unknown kid must force one refresh (1 initial + 2), got %d fetches", got)
	}

	// 密钥轮换：账号服务换了签名 key，缓存里没有 → 刷新后放行。
	kidB := auth.set(t, keyB)
	if _, err = v.Verify(sign(t, keyB, map[string]any{"kid": kidB}, claims)); err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
	if got := auth.fetched(); got != 4 {
		t.Fatalf("rotation must refetch, got %d fetches", got)
	}

	// TTL 到期：即使 kid 已缓存也要重新拉一次，避免长期不更新。
	before := auth.fetched()
	clockMu.Lock()
	now = now.Add(11 * time.Minute)
	clockMu.Unlock()
	if _, err = v.Verify(sign(t, keyB, map[string]any{"kid": kidB}, claims)); err != nil {
		t.Fatalf("verify after ttl: %v", err)
	}
	if got := auth.fetched(); got != before+1 {
		t.Fatalf("expired cache must refetch once, got %d", got)
	}
}

func TestVerifyStaticKeyWinsOverJWKS(t *testing.T) {
	auth := newJWKSServer(t)
	v, err := New(Config{
		Issuer: testIssuer, Audience: testAudience,
		PublicKey: publicKeyPEM(t, testPrivateKey(t)),
		JWKSURL:   auth.URL,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err = v.Verify(sign(t, testPrivateKey(t), map[string]any{"kid": "whatever"}, claimsFixture(time.Now().Add(time.Minute)))); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := auth.fetched(); got != 0 {
		t.Fatalf("static key must not trigger JWKS fetch, got %d", got)
	}
}

func TestVerifyJWKSServerErrors(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(broken.Close)
	v, err := New(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: broken.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err = v.Verify(sign(t, testPrivateKey(t), map[string]any{"kid": "x"}, claimsFixture(time.Now().Add(time.Minute)))); err == nil {
		t.Fatal("unavailable JWKS must fail the verification")
	}

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(empty.Close)
	v2, err := New(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: empty.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err = v2.Verify(sign(t, testPrivateKey(t), map[string]any{"kid": "x"}, claimsFixture(time.Now().Add(time.Minute)))); err == nil {
		t.Fatal("JWKS without usable key must fail the verification")
	}
}

func TestVerifyConcurrent(t *testing.T) {
	auth := newJWKSServer(t)
	kid := auth.set(t, testPrivateKey(t))
	v, err := New(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: auth.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	token := sign(t, testPrivateKey(t), map[string]any{"kid": kid}, claimsFixture(time.Now().Add(time.Minute)))
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(token); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent verify failed: %v", err)
	}
}

func TestStatusForAlwaysUnauthorized(t *testing.T) {
	if StatusFor(nil) != http.StatusOK {
		t.Fatal("nil error means authenticated")
	}
	for _, err := range []error{ErrTokenExpired, ErrBadSignature, ErrUnavailable, fmt.Errorf("wrapped: %w", ErrBadIssuer)} {
		if got := StatusFor(err); got != http.StatusUnauthorized {
			t.Fatalf("StatusFor(%v) = %d, want 401", err, got)
		}
	}
}
