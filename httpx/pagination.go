package httpx

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// 通用分页口径：limit 默认 50、上限 100（目录侧 entities 与各子系统列表同口径）。
const (
	DefaultLimit = 50
	MaxLimit     = 100
	// TagsLimit / TagsMaxLimit 是受控词表一类的长列表口径（目录侧 /catalog/tags：默认 200、上限 500）。
	TagsLimit    = 200
	TagsMaxLimit = 500
)

// Pagination 是一个端点的分页口径。非法或越界的参数一律**静默收敛**为默认值，
// 不返回 400：与各服务现有行为一致——翻页参数抖动不该把整个列表打成错误。
type Pagination struct {
	DefaultLimit int
	MaxLimit     int
}

// Default 是通用口径；Tags 是长列表口径。
var (
	Default = Pagination{DefaultLimit: DefaultLimit, MaxLimit: MaxLimit}
	Tags    = Pagination{DefaultLimit: TagsLimit, MaxLimit: TagsMaxLimit}
)

// Params 是解析结果：统一的 Limit/Offset。total 由响应体承担（见 ListResponse）。
type Params struct {
	Limit  int
	Offset int
	// FromPage 表示这次是 page/page_size 写法解析出来的：排障与契约文档要用，
	// 也让"两套写法并存"这件事在代码里可见，而不是靠注释。
	FromPage bool
}

// Parse 解析查询串：limit/offset 优先，其次 page/page_size（page 从 1 开始），
// 两套都没有时用默认值。
//
//   - limit 缺失/非数字/<=0/>MaxLimit → DefaultLimit
//   - offset 缺失/非数字/<0 → 0（目录侧此前会把负数直接传给 SQL）
//   - page < 1 或非数字 → 1；page_size 缺失/非法/越界 → DefaultLimit
//   - 只要出现了 limit 或 offset 就按第一种写法解析（即使值非法也收敛为默认），
//     避免两套写法混用时算出双重默认的空翻页
func (p Pagination) Parse(q url.Values) Params {
	cfg := p.normalized()
	limitRaw := strings.TrimSpace(q.Get("limit"))
	offsetRaw := strings.TrimSpace(q.Get("offset"))
	if limitRaw != "" || offsetRaw != "" {
		limit, err := strconv.Atoi(limitRaw)
		if err != nil || limit <= 0 || limit > cfg.MaxLimit {
			limit = cfg.DefaultLimit
		}
		offset, err := strconv.Atoi(offsetRaw)
		if err != nil || offset < 0 {
			offset = 0
		}
		return Params{Limit: limit, Offset: offset}
	}
	pageRaw := strings.TrimSpace(q.Get("page"))
	sizeRaw := strings.TrimSpace(q.Get("page_size"))
	if pageRaw != "" || sizeRaw != "" {
		page, err := strconv.Atoi(pageRaw)
		if err != nil || page < 1 {
			page = 1
		}
		size, err := strconv.Atoi(sizeRaw)
		if err != nil || size < 1 || size > cfg.MaxLimit {
			size = cfg.DefaultLimit
		}
		return Params{Limit: size, Offset: (page - 1) * size, FromPage: true}
	}
	return Params{Limit: cfg.DefaultLimit}
}

// ParseRequest 是 Parse 的便捷入口（gi 侧与 net/http 侧都只有 *http.Request 可用）。
func (p Pagination) ParseRequest(r *http.Request) Params {
	if r == nil {
		return p.normalized().Parse(url.Values{})
	}
	return p.Parse(r.URL.Query())
}

func (p Pagination) normalized() Pagination {
	cfg := p
	if cfg.DefaultLimit <= 0 {
		cfg.DefaultLimit = DefaultLimit
	}
	if cfg.MaxLimit <= 0 || cfg.MaxLimit < cfg.DefaultLimit {
		cfg.MaxLimit = cfg.DefaultLimit
	}
	return cfg
}
