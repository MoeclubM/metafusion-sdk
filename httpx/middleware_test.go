package httpx

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestServiceMarker(t *testing.T) {
	rec := httptest.NewRecorder()
	ServiceMarker("metafusion-storage")(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get(ServiceHeader); got != "metafusion-storage" {
		t.Fatalf("marker = %q", got)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := httptest.NewRecorder()
	SecurityHeaders(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"X-Frame-Options":        "SAMEORIGIN",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestRequestIDGeneratesAndEchoes(t *testing.T) {
	hexRe := regexp.MustCompile("^[0-9a-f]{32}$")

	var fromContext string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fromContext = RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	generated := rec.Header().Get(RequestIDHeader)
	if !hexRe.MatchString(generated) {
		t.Fatalf("generated id = %q, want 32 hex chars", generated)
	}
	if fromContext != generated {
		t.Fatalf("context id %q != response header %q", fromContext, generated)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, "caller-supplied-id")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get(RequestIDHeader); got != "caller-supplied-id" {
		t.Fatalf("incoming id must be forwarded, got %q", got)
	}

	// 超长 id 会被丢弃重生成：客户端给的 id 会进日志，不限长等于放任日志注入。
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, string(make([]byte, MaxRequestIDLen+1)))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get(RequestIDHeader); !hexRe.MatchString(got) {
		t.Fatalf("oversized id must be replaced, got %q", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, "   ")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get(RequestIDHeader); !hexRe.MatchString(got) {
		t.Fatalf("blank id must be replaced, got %q", got)
	}
}

func TestRequestIDFromWithoutMiddleware(t *testing.T) {
	if got := RequestIDFrom(httptest.NewRequest(http.MethodGet, "/", nil).Context()); got != "" {
		t.Fatalf("missing id must read as empty, got %q", got)
	}
}

func TestChainAppliesInWrittenOrder(t *testing.T) {
	var order []string
	mark := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	handler := Chain(okHandler(), mark("first"), mark("second"))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("middleware order = %v", order)
	}
	// 组合场景：标记头、安全头、request id 一起上，三者都要出现在响应里。
	rec = httptest.NewRecorder()
	Chain(okHandler(), ServiceMarker("metafusion-auth"), SecurityHeaders, RequestID).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get(ServiceHeader) == "" || rec.Header().Get(RequestIDHeader) == "" ||
		rec.Header().Get("X-Frame-Options") == "" {
		t.Fatalf("combined middleware lost headers: %v", rec.Header())
	}
}
