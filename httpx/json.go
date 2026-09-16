package httpx

import (
	"encoding/json"
	"net/http"
)

// marshalJSON 是内部共用的编码入口：错误体与列表体都从这里出，
// 免得两处各写一遍 Content-Type。
func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }

// JSON 写出一个 JSON 响应（含 Content-Type 与状态码）。
func JSON(w http.ResponseWriter, status int, v any) {
	body, err := marshalJSON(v)
	if err != nil {
		WriteCode(w, http.StatusInternalServerError, CodeInternal)
		return
	}
	writeBody(w, status, body)
}

// writeBody 统一写头写体：先写 Header 再写状态码，避免 Handler 里顺序写错
// 导致状态码被吞成 200。
func writeBody(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ListResponse 是列表响应的统一形状 {items,total}：分页参数决定 items 的范围，
// total 是**过滤条件下的全量条数**（不是本页条数），前端翻页依赖它。
type ListResponse[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

// NewListResponse 归一化 items 为 []（而不是 null），并把 total 兜底为 items 长度。
func NewListResponse[T any](items []T, total int) ListResponse[T] {
	if items == nil {
		items = []T{}
	}
	if total < 0 {
		total = len(items)
	}
	return ListResponse[T]{Items: items, Total: total}
}
