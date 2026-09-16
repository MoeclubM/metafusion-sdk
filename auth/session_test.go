package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// authServer 替身账号服务的 /api/auth/me：断言凭据被原样转发。
func authMeServer(t *testing.T, user map[string]any) (*httptest.Server, *http.Request) {
	t.Helper()
	seen := &http.Request{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/me" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		*seen = *r
		if user == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(user)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

func TestSessionClientResolve(t *testing.T) {
	srv, seen := authMeServer(t, map[string]any{
		"id": "user-1", "username": "curator", "role": "admin",
		"groups": []string{"member", "admin"}, "permissions": []string{"*"},
	})
	client := NewSessionClient(srv.URL+"/", 2*time.Second)
	p, ok := client.Resolve(context.Background(), "opaque-token", "cookie-value")
	if !ok {
		t.Fatal("valid session must resolve")
	}
	if p.ID != "user-1" || p.Role != "admin" || len(p.Groups) != 2 || len(p.Permissions) != 1 {
		t.Fatalf("unexpected principal: %+v", p)
	}
	if got := seen.Header.Get("Authorization"); got != "Bearer opaque-token" {
		t.Fatalf("bearer not forwarded, got %q", got)
	}
	if ck, err := seen.Cookie(SessionCookieName); err != nil || ck.Value != "cookie-value" {
		t.Fatalf("cookie %s not forwarded: %v", SessionCookieName, err)
	}
}

func TestSessionClientRejects(t *testing.T) {
	srv, _ := authMeServer(t, nil)
	client := NewSessionClient(srv.URL, time.Second)
	if _, ok := client.Resolve(context.Background(), "bad", ""); ok {
		t.Fatal("401 from the account service must not resolve")
	}
	if _, ok := NewSessionClient("", time.Second).Resolve(context.Background(), "x", ""); ok {
		t.Fatal("empty base URL means the fallback is disabled")
	}
	if _, ok := client.Resolve(context.Background(), "", ""); ok {
		t.Fatal("no credentials must not resolve (no upstream call)")
	}
	var nilClient *SessionClient
	if _, ok := nilClient.Resolve(context.Background(), "x", "y"); ok {
		t.Fatal("nil client must not resolve")
	}
}

func TestSessionClientRejectsMalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	t.Cleanup(srv.Close)
	client := NewSessionClient(srv.URL, time.Second)
	if _, ok := client.Resolve(context.Background(), "x", ""); ok {
		t.Fatal("malformed body must not resolve")
	}

	// id 为空同样视为未登录：账号服务返回的 User 一定带 id。
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"username":"curator"}`))
	}))
	t.Cleanup(empty.Close)
	if _, ok := NewSessionClient(empty.URL, time.Second).Resolve(context.Background(), "x", ""); ok {
		t.Fatal("user without id must not resolve")
	}
}

func TestSessionClientFallsBackToDefaultTimeout(t *testing.T) {
	client := NewSessionClient("http://example.invalid", 0)
	if client.http.Timeout != DefaultHTTPTimeout {
		t.Fatalf("timeout must fall back to the default, got %v", client.http.Timeout)
	}
}
