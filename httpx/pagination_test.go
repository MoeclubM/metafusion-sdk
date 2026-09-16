package httpx

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestPaginationParse(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Pagination
		query  string
		limit  int
		offset int
		page   bool
	}{
		{"no params uses the default", Pagination{}, "", 50, 0, false},
		{"limit only", Default, "limit=10", 10, 0, false},
		{"limit at the cap", Default, "limit=100", 100, 0, false},
		{"limit above the cap falls back", Default, "limit=101", 50, 0, false},
		{"limit zero falls back", Default, "limit=0", 50, 0, false},
		{"limit negative falls back", Default, "limit=-3", 50, 0, false},
		{"limit non numeric falls back", Default, "limit=abc", 50, 0, false},
		{"offset only keeps the default limit", Default, "offset=20", 50, 20, false},
		{"limit with offset", Default, "limit=10&offset=20", 10, 20, false},
		{"negative offset converges to 0", Default, "offset=-5", 50, 0, false},
		{"page and page_size", Default, "page=2&page_size=30", 30, 30, true},
		{"page below 1 converges to 1", Default, "page=0&page_size=30", 30, 0, true},
		{"page_size above the cap uses the default", Default, "page=3&page_size=101", 50, 100, true},
		{"page_size non numeric uses the default", Default, "page=3&page_size=abc", 50, 100, true},
		{"page without page_size", Default, "page=2", 50, 50, true},
		{"limit wins over page", Default, "limit=5&page=9&page_size=40", 5, 0, false},
		{"invalid limit still selects the limit syntax", Default, "limit=abc&page=2", 50, 0, false},
		{"favorites-like config", Pagination{DefaultLimit: 20, MaxLimit: 100}, "limit=101", 20, 0, false},
		{"favorites-like page_size cap", Pagination{DefaultLimit: 20, MaxLimit: 100}, "page=2&page_size=101", 20, 20, true},
		{"tags cap", Tags, "limit=500", 500, 0, false},
		{"tags above the cap", Tags, "limit=501", 200, 0, false},
		{"tags default", Tags, "", 200, 0, false},
		{"max below default is normalized up", Pagination{DefaultLimit: 50, MaxLimit: 10}, "limit=20", 20, 0, false},
	}
	for _, tc := range cases {
		values, err := url.ParseQuery(tc.query)
		if err != nil {
			t.Fatalf("%s: parse query: %v", tc.name, err)
		}
		got := tc.cfg.Parse(values)
		if got.Limit != tc.limit || got.Offset != tc.offset || got.FromPage != tc.page {
			t.Errorf("%s: Parse(%q) = {Limit:%d Offset:%d FromPage:%v}, want {Limit:%d Offset:%d FromPage:%v}",
				tc.name, tc.query, got.Limit, got.Offset, got.FromPage, tc.limit, tc.offset, tc.page)
		}
	}
}

func TestPaginationParseRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/catalog/entities?limit=25&offset=50", nil)
	if got := Default.ParseRequest(req); got.Limit != 25 || got.Offset != 50 {
		t.Fatalf("ParseRequest = %+v", got)
	}
	// nil 请求不能 panic：中间件/lazily 构造的 handler 里可能出现。
	if got := Default.ParseRequest(nil); got.Limit != DefaultLimit || got.Offset != 0 {
		t.Fatalf("ParseRequest(nil) = %+v", got)
	}
}
