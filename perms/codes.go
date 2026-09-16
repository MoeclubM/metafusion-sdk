// Package perms 是权限码的单一来源：码名必须与账号服务 PermissionCatalog 下发的
// permissions 逐字一致，各服务不再各自手抄一份常量表。
//
// 这里只有"码"和"是否放行"的协议语义，没有判定规则：哪个端点要哪个码、
// 实体级复核、老令牌的角色兜底，都留在各自服务里（见 README「明确不进 SDK」）。
package perms

// Wildcard 是账号服务 admin 组下发的「全部权限」码：命中即为全权。
const Wildcard = "*"

// 目录服务声明的权限码（与 backend/internal/catalog/permission.go 的常量逐字一致）。
const (
	CatalogEntityEdit        = "catalog.entity.edit"
	CatalogRelationEdit      = "catalog.relation.edit"
	CatalogDefinitionsManage = "catalog.definitions.manage"
	CatalogLifecycleManage   = "catalog.lifecycle.manage"
	CatalogImportSubmit      = "catalog.import.submit"
	CatalogShelvesManage     = "catalog.shelves.manage"
)

// 账号服务声明的权限码（与 metafusion-auth 的 PermissionCatalog 逐字一致）。
const (
	AuthUsersManage    = "auth.users.manage"
	AuthGroupsManage   = "auth.groups.manage"
	AuthInvitesManage  = "auth.invites.manage"
	AuthSettingsManage = "auth.settings.manage"
	AuthOAuthManage    = "auth.oauth.manage"
)

// 互动服务声明的权限码。
const (
	CommunityPostCreate   = "community.post.create"
	CommunityPostModerate = "community.post.moderate"
	CommunityTopicPin     = "community.topic.pin"
	CommunityBoardManage  = "community.board.manage"
)

// 存储服务声明的权限码。
const (
	StorageAssetUpload   = "storage.asset.upload"
	StorageAssetModerate = "storage.asset.moderate"
)

// CatalogCodes 返回目录服务声明的全部码（角色兜底只认本服务的码，
// 不会因为角色是 admin 就放行别的子系统的码）。
func CatalogCodes() []string {
	return []string{CatalogEntityEdit, CatalogRelationEdit, CatalogDefinitionsManage, CatalogLifecycleManage, CatalogImportSubmit, CatalogShelvesManage}
}

// AuthCodes 返回账号服务声明的全部码。
func AuthCodes() []string {
	return []string{AuthUsersManage, AuthGroupsManage, AuthInvitesManage, AuthSettingsManage, AuthOAuthManage}
}

// CommunityCodes 返回互动服务声明的全部码。
func CommunityCodes() []string {
	return []string{CommunityPostCreate, CommunityPostModerate, CommunityTopicPin, CommunityBoardManage}
}

// StorageCodes 返回存储服务声明的全部码。
func StorageCodes() []string {
	return []string{StorageAssetUpload, StorageAssetModerate}
}

// AllCodes 返回全部已声明的码（不含 Wildcard）：账号服务的权限清单、
// 管理台下拉与"某个码是否还有人认"的自检都用它，避免再手抄一遍。
func AllCodes() []string {
	out := make([]string, 0, 17)
	out = append(out, AuthCodes()...)
	out = append(out, CatalogCodes()...)
	out = append(out, CommunityCodes()...)
	out = append(out, StorageCodes()...)
	return out
}
