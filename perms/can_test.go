package perms

import (
	"reflect"
	"strings"
	"testing"
)

func TestCan(t *testing.T) {
	cases := []struct {
		name    string
		granted []string
		code    string
		want    bool
	}{
		{"empty collection denies everything", []string{}, CatalogEntityEdit, false},
		{"nil collection denies everything", nil, CatalogEntityEdit, false},
		{"exact code", []string{CatalogEntityEdit}, CatalogEntityEdit, true},
		{"other code", []string{CatalogEntityEdit}, CatalogRelationEdit, false},
		{"wildcard grants everything", []string{Wildcard}, CatalogEntityEdit, true},
		{"wildcard among others", []string{"community.post.create", Wildcard}, StorageAssetUpload, true},
		{"code from another service is not implied", []string{CommunityPostCreate}, CatalogEntityEdit, false},
		{"blank code never passes", []string{Wildcard}, "", false},
	}
	for _, tc := range cases {
		if got := Can(tc.granted, tc.code); got != tc.want {
			t.Errorf("%s: Can(%v, %q) = %v, want %v", tc.name, tc.granted, tc.code, got, tc.want)
		}
	}
}

func TestCanAny(t *testing.T) {
	granted := []string{CatalogShelvesManage}
	if !CanAny(granted, CatalogEntityEdit, CatalogShelvesManage) {
		t.Fatal("any-of must pass when one code matches")
	}
	if CanAny(granted, CatalogEntityEdit, CatalogRelationEdit) {
		t.Fatal("any-of must fail when no code matches")
	}
	if CanAny(nil) {
		t.Fatal("no candidate codes means no access")
	}
	if !CanAny([]string{Wildcard}, CatalogEntityEdit) {
		t.Fatal("wildcard must satisfy any-of")
	}
}

func TestValidCode(t *testing.T) {
	for _, code := range append(AllCodes(), Wildcard) {
		if !ValidCode(code) {
			t.Errorf("%q must be a valid permission code", code)
		}
	}
	for _, code := range []string{"", "catalog", "Catalog.entity.edit", "catalog..edit", "1catalog.entity.edit", "a.b.c.d.e", "catalog.entity.edit "} {
		if ValidCode(code) {
			t.Errorf("%q must be rejected", code)
		}
	}
}

// 冻结清单：这张表是"权限码单一来源"的守卫——任何一处增删都要同步改这里，
// 否则各服务引用的码会与账号服务下发的清单悄悄错开。
func TestCodeListsAreFrozen(t *testing.T) {
	wantAuth := []string{"auth.users.manage", "auth.groups.manage", "auth.invites.manage", "auth.settings.manage", "auth.oauth.manage"}
	wantCatalog := []string{"catalog.entity.edit", "catalog.relation.edit", "catalog.definitions.manage", "catalog.lifecycle.manage", "catalog.shelves.manage"}
	wantCommunity := []string{"community.post.create", "community.post.moderate", "community.topic.pin", "community.board.manage"}
	wantStorage := []string{"storage.asset.upload", "storage.asset.moderate"}

	if got := AuthCodes(); !reflect.DeepEqual(got, wantAuth) {
		t.Errorf("AuthCodes() = %v, want %v", got, wantAuth)
	}
	if got := CatalogCodes(); !reflect.DeepEqual(got, wantCatalog) {
		t.Errorf("CatalogCodes() = %v, want %v", got, wantCatalog)
	}
	if got := CommunityCodes(); !reflect.DeepEqual(got, wantCommunity) {
		t.Errorf("CommunityCodes() = %v, want %v", got, wantCommunity)
	}
	if got := StorageCodes(); !reflect.DeepEqual(got, wantStorage) {
		t.Errorf("StorageCodes() = %v, want %v", got, wantStorage)
	}

	wantAll := append(append(append(append([]string{}, wantAuth...), wantCatalog...), wantCommunity...), wantStorage...)
	if got := AllCodes(); !reflect.DeepEqual(got, wantAll) {
		t.Errorf("AllCodes() = %v, want %v", got, wantAll)
	}
	for _, code := range AllCodes() {
		if code == Wildcard {
			t.Fatal("wildcard is not a declarable code: it must stay out of AllCodes")
		}
		if !strings.HasPrefix(code, "auth.") && !strings.HasPrefix(code, "catalog.") &&
			!strings.HasPrefix(code, "community.") && !strings.HasPrefix(code, "storage.") {
			t.Errorf("%q must carry the declaring service prefix", code)
		}
	}
}

func TestServiceListsDeclareOwnCodesOnly(t *testing.T) {
	for _, tc := range []struct {
		prefix string
		codes  []string
	}{
		{"auth.", AuthCodes()},
		{"catalog.", CatalogCodes()},
		{"community.", CommunityCodes()},
		{"storage.", StorageCodes()},
	} {
		for _, code := range tc.codes {
			if !strings.HasPrefix(code, tc.prefix) {
				t.Errorf("%q is declared by the wrong service (want prefix %s)", code, tc.prefix)
			}
		}
	}
}
