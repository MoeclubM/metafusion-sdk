package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealth(t *testing.T) {
	rec := httptest.NewRecorder()
	Health("metafusion-community")(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "live" || body["service"] != "metafusion-community" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func TestReady(t *testing.T) {
	var pinged bool
	rec := httptest.NewRecorder()
	Ready(Dependency{Name: "postgres", Ping: func(ctx context.Context) error {
		pinged = true
		return nil
	}})(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if !pinged {
		t.Fatal("ready must actually ping the dependency")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body struct {
		Status       string   `json:"status"`
		Dependencies []string `json:"dependencies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "ready" || len(body.Dependencies) != 1 || body.Dependencies[0] != "postgres" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestReadyFailsClosedWithoutLeakingDetails(t *testing.T) {
	rec := httptest.NewRecorder()
	Ready(Dependency{Name: "postgres", Ping: func(context.Context) error {
		return errors.New("dial tcp 10.0.0.5:5432: connection refused")
	}})(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if raw := rec.Body.String(); strings.Contains(raw, "10.0.0.5") {
		t.Fatalf("failure response must not leak dependency details: %s", raw)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "unavailable" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func TestReadyRegistersNameOnlyDependencies(t *testing.T) {
	rec := httptest.NewRecorder()
	Ready(Dependency{Name: "redis"})(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"dependencies":["redis"]`) {
		t.Fatalf("name-only dependency must be listed, got %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	Ready()(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"dependencies":[]`) {
		t.Fatalf("no dependencies must serialize as [], got %s", rec.Body.String())
	}
}
