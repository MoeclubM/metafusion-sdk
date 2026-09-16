package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// ServiceHeader 是切流自检用的服务标记：网关按它逐前缀确认流量落到了哪个上游。
	ServiceHeader = "X-MetaFusion-Service"
	// RequestIDHeader 是请求 id 的头名（入站透传、出站回写）。
	RequestIDHeader = "X-Request-ID"
	// MaxRequestIDLen 限制回显长度：客户端给的 id 会进日志，不限长等于放任日志注入。
	MaxRequestIDLen = 128
)

type requestIDKey struct{}

// ServiceMarker 给每个响应打上服务标记（值形如 metafusion-catalog）。
func ServiceMarker(service string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(ServiceHeader, service)
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders 是最小安全响应头（各服务现在手抄的是同一组）。
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next.ServeHTTP(w, r)
	})
}

// RequestID 透传入站 X-Request-ID（空白或超长视为没有），缺失时生成 16 字节随机 hex；
// 结果同时写进响应头与 context，日志与跨服务排查用同一个 id。
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := strings.TrimSpace(r.Header.Get(RequestIDHeader))
		if len(rid) > MaxRequestIDLen {
			rid = ""
		}
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set(RequestIDHeader, rid)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, rid)))
	})
}

// RequestIDFrom 读当前请求的 id（没有则空串）。
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

// Chain 按书写顺序套用中间件：Chain(h, A, B) 的请求先过 A 再过 B。
func Chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// 随机源不可用也要给出可用的 id：时间戳退化总好过没有 id。
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(b[:])
}
