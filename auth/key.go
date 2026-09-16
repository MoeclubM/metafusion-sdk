package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
)

// ParsePublicKey 解析验签公钥：接受 PEM 文本或 base64 后的 PEM，DER 支持 PKIX 与 PKCS#1。
//
// 刻意**不接受私钥**：审计决议 D3 是"只有账号服务持私钥"，容忍私钥输入会让
// "顺手把私钥配给只验签的进程"继续发生；需要时用 openssl rsa -pubout 导出公钥。
func ParsePublicKey(raw string) (*rsa.PublicKey, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil, ErrMalformedKey
	}
	if !strings.Contains(text, "BEGIN") {
		if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
			text = string(decoded)
		}
	}
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, ErrMalformedKey
	}
	if key, err := parseRSAPublic(block.Bytes); err == nil {
		return key, nil
	}
	if _, err := parseRSAPrivate(block.Bytes); err == nil {
		return nil, ErrPrivateKeyNotAllowed
	}
	return nil, ErrMalformedKey
}

func parseRSAPublic(der []byte) (*rsa.PublicKey, error) {
	if parsed, err := x509.ParsePKIXPublicKey(der); err == nil {
		if key, ok := parsed.(*rsa.PublicKey); ok {
			return key, nil
		}
	}
	if key, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return key, nil
	}
	return nil, ErrMalformedKey
}

func parseRSAPrivate(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if parsed, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if key, ok := parsed.(*rsa.PrivateKey); ok {
			return key, nil
		}
	}
	return nil, ErrMalformedKey
}

// KeyID 取公钥 SPKI DER 的 SHA-256 前 8 字节的 base64url，作为稳定且不泄露密钥的 kid。
// 账号服务用它给 JWKS 里的 key 命名，验签侧用它比对 kid——两边必须是同一算法。
func KeyID(pub *rsa.PublicKey) string {
	if pub == nil {
		return ""
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "default"
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:8])
}
