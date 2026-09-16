package httpx

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	authRequiredBody = `{"error":"authentication_required"}`
	forbiddenBody    = `{"error":"forbidden"}`
	internalBody     = `{"error":"internal_error"}`
)

func TestStatusFor(t *testing.T) {
	cases := map[string]int{
		CodeAuthenticationRequired: http.StatusUnauthorized,
		CodeForbidden:              http.StatusForbidden,
		CodeInvalidPayload:         http.StatusBadRequest,
		CodeInvalidID:              http.StatusBadRequest,
		CodeConstraintViolation:    http.StatusBadRequest,
		CodeNotFound:               http.StatusNotFound,
		CodeVersionConflict:        http.StatusConflict,
		CodeRateLimited:            http.StatusTooManyRequests,
		CodeInternal:               http.StatusInternalServerError,
		"unregistered_code":        http.StatusBadRequest,
	}
	for code, want := range cases {
		if got := StatusFor(code); got != want {
			t.Errorf("StatusFor(%q) = %d, want %d", code, got, want)
		}
	}
}

func TestCanonicalMatchesStatusMapping(t *testing.T) {
	// 历史别名必须走同一条状态码映射，否则"同一个错误两种状态码"会继续扩散。
	if got := Canonical("unauthorized"); got != CodeAuthenticationRequired {
		t.Fatalf("Canonical(unauthorized) = %q", got)
	}
	if StatusFor("unauthorized") != http.StatusUnauthorized {
		t.Fatal("legacy code must map through Canonical")
	}
	if got := Canonical(CodeForbidden); got != CodeForbidden {
		t.Fatalf("known code must pass through, got %q", got)
	}
	if got := Canonical("catalog.specific_code"); got != "catalog.specific_code" {
		t.Fatalf("service-private code must pass through, got %q", got)
	}
}

func TestErrorStatus(t *testing.T) {
	if status, code := ErrorStatus(nil); status != http.StatusOK || code != "" {
		t.Fatalf("nil error = (%d, %q), want (200, empty)", status, code)
	}
	if status, code := ErrorStatus(New("unauthorized")); status != http.StatusUnauthorized || code != CodeAuthenticationRequired {
		t.Fatalf("New(unauthorized) = (%d, %q)", status, code)
	}
	// %w 包裹后仍要还原状态码：目录侧曾因全等比较把 403 退化成 400。
	wrapped := fmt.Errorf("attributes.x: %w", New(CodeVersionConflict))
	if status, code := ErrorStatus(wrapped); status != http.StatusConflict || code != CodeVersionConflict {
		t.Fatalf("wrapped = (%d, %q)", status, code)
	}
	if status, code := ErrorStatus(NewStatus(http.StatusTeapot, "teapot")); status != http.StatusTeapot || code != "teapot" {
		t.Fatalf("explicit status lost: (%d, %q)", status, code)
	}
	// 未知 err 一律 500 + 固定码：内部错误不透传原文。
	if status, code := ErrorStatus(errors.New("pq: relation does not exist")); status != http.StatusInternalServerError || code != CodeInternal {
		t.Fatalf("plain error = (%d, %q)", status, code)
	}
	var typedNil *Error
	if status, code := ErrorStatus(typedNil); status != http.StatusInternalServerError || code != CodeInternal {
		t.Fatalf("typed nil error = (%d, %q)", status, code)
	}
}

func TestErrorStringIsTheMachineCode(t *testing.T) {
	if got := New("unauthorized").Error(); got != CodeAuthenticationRequired {
		t.Fatalf("Error() = %q, want the canonical code", got)
	}
	// nil 接收者不能 panic：handler 里 err 变量为 nil 是常态。
	if got := (*Error)(nil).Error(); got != "" {
		t.Fatalf("nil *Error must not panic, got %q", got)
	}
}

func TestWriteCode(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteCode(rec, http.StatusUnauthorized, "unauthorized")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Body.String(); got != authRequiredBody {
		t.Fatalf("body = %s, want %s", got, authRequiredBody)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content type = %q", ct)
	}
}

func TestWriteError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, New(CodeForbidden))
	if rec.Code != http.StatusForbidden || rec.Body.String() != forbiddenBody {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	WriteError(rec, errors.New("boom"))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != internalBody {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
}
