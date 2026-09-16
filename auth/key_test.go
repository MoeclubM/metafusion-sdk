package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
)

func TestParsePublicKeyAcceptsPKIXAndPKCS1(t *testing.T) {
	key := testPrivateKey(t)

	pkix, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal PKIX: %v", err)
	}
	if _, err = ParsePublicKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}))); err != nil {
		t.Fatalf("PKIX PEM: %v", err)
	}
	pkcs1 := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	if _, err = ParsePublicKey(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1}))); err != nil {
		t.Fatalf("PKCS1 PEM: %v", err)
	}
	// 前后空白与 base64 形态都要能用（env 里粘贴 PEM 常带缩进或换行差异）。
	wrapped := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix}))
	if _, err = ParsePublicKey("  " + wrapped + "\n"); err != nil {
		t.Fatalf("base64 PEM: %v", err)
	}
}

func TestParsePublicKeyRejectsPrivateAndGarbage(t *testing.T) {
	if _, err := ParsePublicKey(privateKeyPEM(t, testPrivateKey(t))); !errors.Is(err, ErrPrivateKeyNotAllowed) {
		t.Fatalf("private key: want ErrPrivateKeyNotAllowed, got %v", err)
	}
	broken := "-----BEGIN PUBLIC KEY-----\nzzz\n-----END PUBLIC KEY-----"
	for _, raw := range []string{"", "   ", "not-a-pem", broken} {
		if _, err := ParsePublicKey(raw); err == nil {
			t.Fatalf("garbage input %q must be rejected", raw)
		}
	}
}

func TestKeyIDIsStableAndKeyScoped(t *testing.T) {
	a := KeyID(&testPrivateKey(t).PublicKey)
	if a == "" || KeyID(&testPrivateKey(t).PublicKey) != a {
		t.Fatalf("KeyID must be stable for the same key, got %q", a)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate second key: %v", err)
	}
	if KeyID(&other.PublicKey) == a {
		t.Fatal("different keys must produce different kids")
	}
	if KeyID(nil) != "" {
		t.Fatal("nil key has no kid")
	}
}
