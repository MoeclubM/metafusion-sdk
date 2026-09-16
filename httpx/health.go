package httpx

import (
	"context"
	"net/http"
	"time"
)

// ReadyTimeout 是 /ready 探测依赖的超时：探针必须 2 秒内出结论，
// 不能因为数据库慢就把探针拖成"上游看起来活着"。
const ReadyTimeout = 2 * time.Second

// Dependency 是一项 /ready 依赖。Name 会出现在响应体的 dependencies 里，
// 让运维一眼看出该找谁；Ping 为 nil 表示只登记名字不探测。
type Dependency struct {
	Name string
	Ping func(ctx context.Context) error
}

// Health 返回 /health：只表示进程存活（不做任何 IO），不代表数据库或上游可用。
// 账号 / 互动 / 存储的现有实现就是这个形状；目录侧目前只有 /healthz，切换时补齐 /health。
func Health(service string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		JSON(w, http.StatusOK, map[string]any{"status": "live", "service": service})
	}
}

// Ready 返回 /ready：全部依赖通过才 200，任一失败或超时 503。
// 失败响应**不透出**底层错误原文——连接串、库名这类信息不该进响应体，
// 失败原因由调用方自己记日志。
func Ready(deps ...Dependency) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), ReadyTimeout)
		defer cancel()
		names := make([]string, 0, len(deps))
		for _, dep := range deps {
			if dep.Name != "" {
				names = append(names, dep.Name)
			}
			if dep.Ping == nil {
				continue
			}
			if err := dep.Ping(ctx); err != nil {
				JSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable"})
				return
			}
		}
		JSON(w, http.StatusOK, map[string]any{"status": "ready", "dependencies": names})
	}
}
