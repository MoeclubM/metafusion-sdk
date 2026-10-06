// Package httpx 是各服务共享的 HTTP 约定：统一错误体与状态码映射、分页参数解析、
// /health 与 /ready、服务标记头与 request-id 中间件。
//
// 只依赖 net/http：SDK 给的是 net/http 级原语，各服务自己决定怎么接——
// gin 侧用 ErrorStatus(err) 取 (状态码, 机器码) 后 c.JSON，身份用
// auth.PrincipalFromContext(c.Request.Context()) 取。
package httpx

import (
	"errors"
	"net/http"
)

// emptyErrorBody 是编码失败时的兜底响应体：此时不能再走一次编码路径。
var emptyErrorBody = []byte("{\"error\":\"internal_error\"}")

// 跨服务的协议级错误码：同一语义在任何一个服务上都必须给出同一个码与状态码。
// 服务私有的业务码（invalid_term、hash_mismatch 之类）不进这里，它们只属于各自的 handler。
const (
	CodeAuthenticationRequired = "authentication_required"
	CodeForbidden              = "forbidden"
	CodeInvalidPayload         = "invalid_payload"
	CodeNotFound               = "not_found"
	CodeInvalidID              = "invalid_id"
	CodeConstraintViolation    = "constraint_violation"
	CodeVersionConflict        = "version_conflict"
	CodeRateLimited            = "rate_limited"
	CodeInternal               = "internal_error"
)

// statusByCode 是规范机器码到状态码的唯一映射。
var statusByCode = map[string]int{
	CodeAuthenticationRequired: http.StatusUnauthorized,
	CodeForbidden:              http.StatusForbidden,
	CodeInvalidPayload:         http.StatusBadRequest,
	CodeInvalidID:              http.StatusBadRequest,
	CodeConstraintViolation:    http.StatusBadRequest,
	CodeNotFound:               http.StatusNotFound,
	CodeVersionConflict:        http.StatusConflict,
	CodeRateLimited:            http.StatusTooManyRequests,
	CodeInternal:               http.StatusInternalServerError,
}

// StatusFor 返回机器码对应的状态码。未知码按 400——与目录侧 respond 的默认分支一致：
// 没登记过的码属于调用方漏登记，静默升级成 5xx 会把"参数错"报成"服务错"。
func StatusFor(code string) int {
	if status, ok := statusByCode[code]; ok {
		return status
	}
	return http.StatusBadRequest
}

// Error 是可在 handler 之间传递的错误：机器码 + 状态码（0 表示由码推导）。
// 它的 Error() 就是机器码本身，排障时日志里出现的即客户端收到的即同一个字符串。
type Error struct {
	Code   string
	Status int
}

// New 按码构造错误，状态码由 StatusFor 推导。
func New(code string) *Error { return &Error{Code: code} }

// NewStatus 构造带显式状态码的错误（码不在映射表里时用）。
func NewStatus(status int, code string) *Error {
	return &Error{Code: code, Status: status}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

// ErrorStatus 取 (状态码, 机器码) 供 handler 组装响应；
// 非 *Error 的错误统一 500 internal_error——内部错误不透出原文。
func ErrorStatus(err error) (int, string) {
	if err == nil {
		return http.StatusOK, ""
	}
	// e != nil 必须显式判：error 接口里装着 (*Error)(nil) 时 errors.As 也会成功，
	// 此时读 e.Code 就是空指针崩溃。
	var e *Error
	if errors.As(err, &e) && e != nil && e.Code != "" {
		if e.Status > 0 {
			return e.Status, e.Code
		}
		return StatusFor(e.Code), e.Code
	}
	return http.StatusInternalServerError, CodeInternal
}

// WriteError 按错误的类型写出统一错误体。
func WriteError(w http.ResponseWriter, err error) {
	status, code := ErrorStatus(err)
	WriteCode(w, status, code)
}

// WriteCode 写出 {"error":"机器码"}；调用方须使用规范机器码。
func WriteCode(w http.ResponseWriter, status int, code string) {
	body, err := marshalJSON(map[string]string{"error": code})
	if err != nil {
		status, body = http.StatusInternalServerError, emptyErrorBody
	}
	writeBody(w, status, body)
}
