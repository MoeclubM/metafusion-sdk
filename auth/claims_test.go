package auth

import (
	"encoding/json"
	"testing"
)

func TestAudienceParsesStringAndArray(t *testing.T) {
	var single Claims
	if err := json.Unmarshal([]byte(`{"aud":"metafusion"}`), &single); err != nil {
		t.Fatalf("string aud: %v", err)
	}
	if !single.Audience.Has("metafusion") || single.Audience.Has("other") {
		t.Fatalf("unexpected audience: %+v", single.Audience)
	}

	var many Claims
	if err := json.Unmarshal([]byte(`{"aud":["metafusion","third-party"]}`), &many); err != nil {
		t.Fatalf("array aud: %v", err)
	}
	if len(many.Audience) != 2 || !many.Audience.Has("third-party") {
		t.Fatalf("unexpected audience: %+v", many.Audience)
	}
}

func TestAudienceRejectsOtherJSONTypes(t *testing.T) {
	var claims Claims
	if err := json.Unmarshal([]byte(`{"aud":123}`), &claims); err == nil {
		t.Fatal("numeric aud must be rejected instead of silently ignored")
	}
}

func TestClaimsPrincipal(t *testing.T) {
	claims := &Claims{
		Subject: "user-1", Username: "curator", Role: "editor",
		Groups: []string{"member"}, Permissions: []string{"catalog.entity.edit"},
	}
	p := claims.Principal()
	if p.ID != "user-1" || p.Username != "curator" || p.Role != "editor" {
		t.Fatalf("unexpected principal: %+v", p)
	}
	if len(p.Permissions) != 1 || p.Permissions[0] != "catalog.entity.edit" {
		t.Fatalf("permissions not carried over: %+v", p.Permissions)
	}
	var nilClaims *Claims
	if nilClaims.Principal() != nil {
		t.Fatal("nil claims must not produce a principal")
	}
}
