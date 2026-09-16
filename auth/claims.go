// Package auth 是访问令牌的**验签侧**协议：Claims 结构、RS256 验签（静态公钥或 JWKS）、
// 存量不透明会话令牌的兜底解析，以及把身份放进 context 的 net/http 原语。
//
// 只做协议，不做业务：这里没有签发路径（私钥只属于账号服务）、没有权限判定规则
// （各服务自己决定谁能改什么）、没有数据库访问。判定只认令牌里的 permissions 码，
// 角色兜底属于各服务的历史兼容逻辑，见 README「明确不进 SDK」。
package auth

import (
	"encoding/json"
	"errors"
)

// Claims 是访问令牌的载荷，字段名与账号服务的签发侧逐字一致——两边都只读令牌、
// 谁也不查对方的库，唯一要对齐的就是这些 json 名。
type Claims struct {
	Subject  string `json:"sub"`
	Username string `json:"preferred_username"`
	Email    string `json:"email,omitempty"`
	Role     string `json:"role"`
	// Groups 是组码（展示与审计用）；Permissions 是展开后的权限码集合——授权只看它。
	Groups      []string `json:"groups,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Issuer      string   `json:"iss"`
	Audience    Audience `json:"aud"`
	IssuedAt    int64    `json:"iat"`
	Expires     int64    `json:"exp"`
	// JTI 只做审计与排障：撤销由账号服务的会话表承担，验签侧不查任何库。
	JTI string `json:"jti"`
}

// Audience 兼容 aud 的两种合法形态：单字符串（自有平台）与数组（OIDC 的 id_token 等）。
type Audience []string

// UnmarshalJSON 接受 "metafusion" 与 ["metafusion", ...] 两种写法。
func (a *Audience) UnmarshalJSON(raw []byte) error {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = Audience(many)
	return nil
}

// Has 报告受众集合里是否包含某个 audience（配置为空时调用方不做校验）。
func (a Audience) Has(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}

// Principal 是验签后的调用者身份，与各服务现有 Principal 同形，便于直接替换。
type Principal struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	// Groups 与 Permissions 是账号服务的权限组投影，字段名与签发侧逐字一致
	// （令牌 claims 与 /api/auth/me 都叫 groups / permissions）。
	Groups      []string `json:"groups"`
	Permissions []string `json:"permissions"`
}

// Principal 把已验签的载荷还原为身份（不查库）。
func (c *Claims) Principal() *Principal {
	if c == nil {
		return nil
	}
	return &Principal{
		ID: c.Subject, Username: c.Username, Role: c.Role,
		Groups: c.Groups, Permissions: c.Permissions,
	}
}
