package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCredentials(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "bEaReR   token-value  ")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "cookie-value"})
	bearer, cookie := Credentials(req)
	if bearer != "token-value" {
		t.Fatalf("bearer parsing is case-insensitive and trims, got %q", bearer)
	}
	if cookie != "cookie-value" {
		t.Fatalf("cookie not read, got %q", cookie)
	}

	plain := httptest.NewRequest(http.MethodGet, "/", nil)
	plain.Header.Set("Authorization", "Basic abc")
	if b, c := Credentials(plain); b != "" || c != "" {
		t.Fatalf("non-bearer credentials must be ignored, got %q %q", b, c)
	}
	if b, c := Credentials(nil); b != "" || c != "" {
		t.Fatal("nil request must be anonymous")
	}
}

func TestCredentialsRoundTripThroughContext(t *testing.T) {
	ctx := WithCredentials(context.Background(), "t", "c")
	b, c := CredentialsFrom(ctx)
	if b != "t" || c != "c" {
		t.Fatalf("credentials lost: %q %q", b, c)
	}
	if b, c := CredentialsFrom(context.Background()); b != "" || c != "" {
		t.Fatal("context without credentials must be anonymous")
	}
}

func TestMiddlewareResolvesWithoutBlocking(t *testing.T) {
	v := staticVerifier(t)
	token := sign(t, testPrivateKey(t), map[string]any{}, claimsFixture(time.Now().Add(time.Minute)))

	var got *Principal
	var forwardedBearer string
	handler := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = PrincipalFromContext(r.Context())
		forwardedBearer, _ = CredentialsFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("middleware must not block anonymous-allowed routes, got %d", rec.Code)
	}
	if got == nil || got.ID != "user-uuid" {
		t.Fatalf("principal not resolved: %+v", got)
	}
	if forwardedBearer != token {
		t.Fatal("credentials must be forwarded for downstream calls")
	}

	// 没有令牌也不拦截，但身份为 nil。
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("anonymous request must pass, got %d", rec.Code)
	}
}

func TestRequireRejectsAnonymous(t *testing.T) {
	v := staticVerifier(t)
	handler := v.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous must be 401, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != `{"error":"authentication_required"}` {
		t.Fatalf("401 body must use the shared error shape, got %s", body)
	}

	token := sign(t, testPrivateKey(t), map[string]any{}, claimsFixture(time.Now().Add(time.Minute)))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid token must pass, got %d", rec.Code)
	}
}

func TestResolveFallsBackToSessionClient(t *testing.T) {
	srv, _ := authMeServer(t, map[string]any{
		"id": "user-9", "username": "legacy", "role": "user",
		"groups": []string{}, "permissions": []string{},
	})
	// 没有公钥来源的验签器（Unavailable）只能靠兜底：这正是存量不透明令牌的路径。
	v, err := New(Config{Issuer: testIssuer, Audience: testAudience})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.SetFallback(NewSessionClient(srv.URL, time.Second))

	if p := v.Resolve(context.Background(), "opaque", ""); p == nil || p.ID != "user-9" {
		t.Fatalf("fallback must resolve legacy tokens, got %+v", p)
	}
	v.SetFallback(nil)
	if p := v.Resolve(context.Background(), "opaque", ""); p != nil {
		t.Fatal("without fallback only JWTs are accepted")
	}
}
