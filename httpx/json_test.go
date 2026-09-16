package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	JSON(rec, http.StatusCreated, map[string]string{"id": "x"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content type = %q", ct)
	}
	if got := rec.Body.String(); got != `{"id":"x"}` {
		t.Fatalf("body = %s", got)
	}
}

func TestJSONEncodingFailureIsInternalError(t *testing.T) {
	// 函数不可 JSON 编码：此时不能再走一次编码路径，必须给出固定错误体。
	rec := httptest.NewRecorder()
	JSON(rec, http.StatusOK, func() {})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if got := rec.Body.String(); got != internalBody {
		t.Fatalf("body = %s, want %s", got, internalBody)
	}
}

func TestListResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	JSON(rec, http.StatusOK, NewListResponse([]string{"a", "b"}, 42))
	var body struct {
		Items []string `json:"items"`
		Total int      `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) != 2 || body.Total != 42 {
		t.Fatalf("unexpected body: %+v", body)
	}

	// nil items 必须是 []（不是 null），前端列表不需要为 nil 单独兜底。
	rec = httptest.NewRecorder()
	JSON(rec, http.StatusOK, NewListResponse[string](nil, -1))
	if got := rec.Body.String(); got != `{"items":[],"total":0}` {
		t.Fatalf("body = %s", got)
	}
}
