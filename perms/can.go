package perms

import "regexp"

// codeRe 是权限码格式：* 或 服务.资源.动作（最多四段）。
// 与账号服务校验新码的规则一致——下游可以自定义码，格式合法即可。
var codeRe = regexp.MustCompile("^[*]$|^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){1,3}$")

// ValidCode 校验权限码格式（账号服务登记自定义码、管理台输入时用）。
func ValidCode(code string) bool { return codeRe.MatchString(code) }

// Can 报告权限集合是否放行某码：集合里含 Wildcard 即全权；否则必须是码本身。
//
// 与目录侧 User.Can 的"令牌带 permissions 时一律以码为准"一致；**空集合一律不放行**。
// 老令牌没有 permissions 时的角色兜底是各服务的历史兼容逻辑，故意不进 SDK：
// 容忍它就会把"角色兜底"变成绕过权限组的后门（见 README「明确不进 SDK」）。
func Can(granted []string, code string) bool {
	if code == "" {
		return false
	}
	for _, g := range granted {
		if g == Wildcard || g == code {
			return true
		}
	}
	return false
}

// CanAny 报告权限集合是否放行其中任意一个码（"任一即可"的路由闸门）。
func CanAny(granted []string, codes ...string) bool {
	for _, code := range codes {
		if Can(granted, code) {
			return true
		}
	}
	return false
}
