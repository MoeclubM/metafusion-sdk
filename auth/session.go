package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// SessionClient 是账号服务 /api/auth/me 的兜底解析实现：把调用者原样带来的
// Bearer 与 mf_session cookie 转给账号服务，由它验签或查会话表后返回身份。
//
// 只在 JWT 验签失败时使用（存量不透明会话令牌的过渡期）；账号服务是唯一身份来源，
// 这里刻意不指向目录服务。
type SessionClient struct {
	base string
	http *http.Client
}

// NewSessionClient 构造兜底 client；baseURL 为空时 Resolve 恒为 false（等于不启用兜底）。
func NewSessionClient(baseURL string, timeout time.Duration) *SessionClient {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	return &SessionClient{
		base: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		http: &http.Client{Timeout: timeout},
	}
}

// Resolve 返回兜底解析出的身份；false 表示无凭据、上游不可达或身份不成立。
func (c *SessionClient) Resolve(ctx context.Context, bearer, cookie string) (*Principal, bool) {
	if c == nil || c.base == "" || (bearer == "" && cookie == "") {
		return nil, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/auth/me", nil)
	if err != nil {
		return nil, false
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	// 账号服务 /api/auth/me 的形状：id 是用户 UUID，权限组随响应下发；
	// 缺字段（旧账号服务）时为空，判定层据此退回各自的角色兜底。
	var user struct {
		ID          string   `json:"id"`
		Username    string   `json:"username"`
		Role        string   `json:"role"`
		Groups      []string `json:"groups"`
		Permissions []string `json:"permissions"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&user); err != nil || user.ID == "" {
		return nil, false
	}
	return &Principal{
		ID: user.ID, Username: user.Username, Role: user.Role,
		Groups: user.Groups, Permissions: user.Permissions,
	}, true
}
