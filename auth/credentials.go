package auth

import (
	"context"
	"net/http"
	"strings"
)

type credentialsKey struct{}

// Credentials 从请求里取调用者的两种凭据：Authorization: Bearer 与 mf_session cookie。
func Credentials(r *http.Request) (bearer, cookie string) {
	if r == nil {
		return "", ""
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) > 7 && strings.EqualFold(authz[:7], "bearer ") {
		bearer = strings.TrimSpace(authz[7:])
	}
	if ck, err := r.Cookie(SessionCookieName); err == nil && ck.Value != "" {
		cookie = ck.Value
	}
	return bearer, cookie
}

// WithCredentials 把凭据写进 context：本服务调用目录服务时必须原样转发调用者的令牌，
// 否则可见性判定会退化成匿名，草稿/待审条目会被误判为不可见。
func WithCredentials(ctx context.Context, bearer, cookie string) context.Context {
	return context.WithValue(ctx, credentialsKey{}, [2]string{bearer, cookie})
}

// CredentialsFrom 读出调用者凭据；缺失即匿名（返回空串）。
func CredentialsFrom(ctx context.Context) (string, string) {
	if v, ok := ctx.Value(credentialsKey{}).([2]string); ok {
		return v[0], v[1]
	}
	return "", ""
}
