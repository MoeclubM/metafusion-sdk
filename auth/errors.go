package auth

import (
	"errors"
	"net/http"
)

// 验签失败的原因。handler 只需据此返回 401，排障时用 errors.Is 区分到底是
// 过期、签发方不符还是公钥没配上——这些原因以前散在三个服务的字符串里，对不上号。
var (
	ErrMalformedToken       = errors.New("malformed token")
	ErrUnexpectedAlgorithm  = errors.New("unexpected algorithm")
	ErrBadSignature         = errors.New("bad signature")
	ErrTokenExpired         = errors.New("token expired")
	ErrBadIssuer            = errors.New("bad issuer")
	ErrBadAudience          = errors.New("bad audience")
	ErrMissingSubject       = errors.New("missing subject")
	ErrUnknownKey           = errors.New("unknown signing key")
	ErrUnavailable          = errors.New("token verifier unavailable")
	ErrMalformedKey         = errors.New("AUTH_JWT_PUBLIC_KEY must be a PEM or base64 PEM RSA public key")
	ErrPrivateKeyNotAllowed = errors.New("AUTH_JWT_PUBLIC_KEY is a private key: only the account service may hold it")
)

// StatusFor 把验签错误映射成 HTTP 状态码：一律 401。
// 验签器不可用（没配公钥也没配 JWKS）同样是 401——fail closed，不能因为
// "配置缺失"就把写接口放行成匿名可写。
func StatusFor(err error) int {
	if err == nil {
		return http.StatusOK
	}
	return http.StatusUnauthorized
}
