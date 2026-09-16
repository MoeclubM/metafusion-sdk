package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
)

// refreshLocked 拉取并替换 JWKS 缓存，调用方必须持有 v.mu。
// 只接受 kty=RSA 的 key；一份全是无法解析的 key 的文档视为失败，不做部分替换——
// 半份缓存会让"轮换中的旧令牌"在容器间时好时坏。
func (v *Verifier) refreshLocked() error {
	if v.jwksURL == "" {
		return errors.New("no jwks url configured")
	}
	req, err := http.NewRequest(http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("jwks unavailable")
	}
	var doc struct {
		Keys []struct {
			KID string `json:"kid"`
			KTY string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if !strings.EqualFold(k.KTY, "RSA") {
			continue
		}
		key, err := rsaFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.KID] = key
	}
	if len(keys) == 0 {
		return errors.New("jwks has no usable key")
	}
	v.keys = keys
	v.fetchedAt = v.now()
	return nil
}

// rsaFromJWK 把 JWK 的 n/e（base64url、无填充）还原成 RSA 公钥。
func rsaFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, errors.New("invalid exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
