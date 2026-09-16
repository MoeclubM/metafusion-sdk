package auth

import (
	"context"
	"net/http"

	"github.com/MoeclubM/metafusion-sdk/httpx"
)

type principalKey struct{}

// WithPrincipal 把已验签的身份放进 context。
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext 读当前请求者，未登录为 nil。
// gin 侧用 PrincipalFromContext(c.Request.Context()) 取，不需要 SDK 依赖 gin。
func PrincipalFromContext(ctx context.Context) *Principal {
	if v, ok := ctx.Value(principalKey{}).(*Principal); ok {
		return v
	}
	return nil
}

// Resolve 依次尝试 JWT 验签与会话兜底；都失败返回 nil（匿名）。
func (v *Verifier) Resolve(ctx context.Context, bearer, cookie string) *Principal {
	if v == nil {
		return nil
	}
	if claims, err := v.Verify(bearer); err == nil {
		return claims.Principal()
	}
	if v.fallback != nil {
		if p, ok := v.fallback.Resolve(ctx, bearer, cookie); ok {
			return p
		}
	}
	return nil
}

// Middleware 解析身份但不拦截：解析成功时把身份与凭据写进 context，
// 供"需要以调用者身份访问下游服务"的 handler 使用（见 CredentialsFrom）。
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, cookie := Credentials(r)
		ctx := WithCredentials(r.Context(), bearer, cookie)
		if p := v.Resolve(ctx, bearer, cookie); p != nil {
			ctx = WithPrincipal(ctx, p)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Require 要求已登录：无有效身份直接 401，错误体是 httpx 的统一形状
// （{"error":"authentication_required"}），与目录侧闸门逐字一致。
func (v *Verifier) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer, cookie := Credentials(r)
		ctx := WithCredentials(r.Context(), bearer, cookie)
		p := v.Resolve(ctx, bearer, cookie)
		if p == nil {
			httpx.WriteCode(w, http.StatusUnauthorized, httpx.CodeAuthenticationRequired)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(ctx, p)))
	})
}
