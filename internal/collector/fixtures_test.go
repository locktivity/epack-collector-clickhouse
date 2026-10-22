package collector

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/locktivity/epack/componentsdk/collectortest"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

// The kit's organization, service, and credentials. record_test.go gives a
// recording the same organization ID and host, so the suite's checks read
// recordings and hand-built scenarios alike.
const (
	kitOrgID      = "8c1f2a4e-5b6d-4e7f-9a0b-1c2d3e4f5a6b"
	kitHost       = "kit0service1.us-east-1.aws.clickhouse.cloud"
	kitKeyID      = "kitKeyId0123456789AB"
	kitKeySecret  = "kit-key-secret-0123456789abcdefghij"
	kitDBPassword = "kit-db-password-0123456789"

	kitAPI = "https://api.clickhouse.cloud/v1/organizations/" + kitOrgID
	kitDB  = "https://" + kitHost + ":8443/?wait_end_of_query=1"
)

func kitConfig() map[string]any {
	return map[string]any{
		"organization_id": kitOrgID,
		"services":        []any{map[string]any{"host": kitHost}},
		"level":           "internal",
	}
}

func kitSecrets() map[string]string {
	return map[string]string{keyIDEnv: kitKeyID, keySecretEnv: kitKeySecret, dbPasswordEnv: kitDBPassword}
}

// apiBody wraps result in the Cloud API's envelope.
func apiBody(result string) string {
	return `{"status": 200, "requestId": "0b6f7c1e-3a2d-4c5b-8e9f-102132435465", "result": ` + result + `}`
}

// apiError is a Cloud API error body.
func apiError(status int, message string) string {
	return fmt.Sprintf(`{"status": %d, "error": %q, "requestId": "0b6f7c1e-3a2d-4c5b-8e9f-102132435466"}`, status, message)
}

// sqlBody is a FORMAT JSON result holding rows, each a JSON object.
func sqlBody(rows ...string) string {
	return `{"meta": [], "data": [` + strings.Join(rows, ",\n") + fmt.Sprintf(`], "rows": %d, "statistics": {"elapsed": 0.001, "rows_read": %d, "bytes_read": 512}}`, len(rows), len(rows))
}

// sqlError is a failed query's answer: ClickHouse's message in the body and
// its exception code in a header.
func sqlError(op string, status, code int, message string) collectortest.Response {
	return collectortest.Response{
		Operation: op,
		Method:    http.MethodPost,
		URL:       kitDB,
		Status:    status,
		Header:    http.Header{"X-Clickhouse-Exception-Code": []string{fmt.Sprint(code)}, "Content-Type": []string{"text/plain; charset=UTF-8"}},
		Body:      message,
	}
}

func sql(op, body string) collectortest.Response {
	return collectortest.Response{Operation: op, Method: http.MethodPost, URL: kitDB, Body: body}
}

const (
	kitOrgBody = `{"id": "` + kitOrgID + `", "name": "Kit Org", "createdAt": "2026-10-21T13:58:12.000Z", "privateEndpoints": [], "enableCoreDumps": false}`

	kitMembersBody = `[
		{"userId": "4d1e2f30-0000-4000-8000-000000000001", "name": "Owner", "email": "kit+ch-owner@example.com", "role": "admin", "joinedAt": "2026-10-21T13:58:12Z",
		 "assignedRoles": [{"roleId": "r-admin", "roleName": "Admin", "roleType": "system"}]},
		{"userId": "4d1e2f30-0000-4000-8000-000000000002", "name": "Reader", "email": "Kit+ch-reader@example.com", "role": "developer", "joinedAt": "2026-10-21T14:10:00Z",
		 "assignedRoles": [{"roleId": "r-member", "roleName": "Member", "roleType": "system"}, {"roleId": "r-service-reader", "roleName": "Service reader", "roleType": "system"}]},
		{"userId": "4d1e2f30-0000-4000-8000-000000000003", "name": "Auditor", "email": "kit+ch-auditor@example.com", "role": "developer", "joinedAt": "2026-10-21T14:11:00Z",
		 "assignedRoles": [{"roleId": "r-member", "roleName": "Member", "roleType": "system"}, {"roleId": "r-auditor", "roleName": "sandbox-auditor", "roleType": "custom"}]},
		{"userId": "4d1e2f30-0000-4000-8000-000000000004", "name": "Billing", "email": "kit+ch-billing@example.com", "role": "developer", "joinedAt": "2026-10-21T14:12:00Z",
		 "assignedRoles": [{"roleId": "r-billing", "roleName": "Billing", "roleType": "system"}]}
	]`

	kitInvitationsBody = `[
		{"id": "5e2f3a40-0000-4000-8000-000000000001", "email": "kit+ch-pending@example.com", "role": "developer", "createdAt": "2026-10-21T15:00:00Z", "expireAt": "2026-10-28T15:00:00Z",
		 "assignedRoles": [{"roleId": "r-member", "roleName": "Member", "roleType": "system"}]},
		{"id": "5e2f3a40-0000-4000-8000-000000000002", "email": "kit+ch-lapsed@example.com", "role": "developer", "createdAt": "2026-09-01T15:00:00Z", "expireAt": "2026-09-08T15:00:00Z",
		 "assignedRoles": [{"roleId": "r-member", "roleName": "Member", "roleType": "system"}]}
	]`

	kitKeysPage1 = `[
		{"id": "6f3a4b50-0000-4000-8000-000000000001", "name": "sandbox-admin", "state": "enabled", "roles": ["admin"], "keySuffix": "AbCd", "createdAt": "2026-10-21T14:00:00Z", "expireAt": "2027-10-21T14:00:00Z", "usedAt": "2026-10-22T09:59:00Z",
		 "assignedRoles": [{"roleId": "r-admin", "roleName": "Admin", "roleType": "system"}], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]},
		{"id": "6f3a4b50-0000-4000-8000-000000000002", "name": "epack-collector", "state": "enabled", "roles": [], "keySuffix": "EfGh", "createdAt": "2026-10-21T14:30:00Z", "usedAt": "2026-10-22T10:00:00Z",
		 "assignedRoles": [{"roleId": "r-collector", "roleName": "epack-collector", "roleType": "custom"}], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]},
		{"id": "6f3a4b50-0000-4000-8000-000000000003", "name": "sandbox-auditor", "state": "enabled", "roles": [], "keySuffix": "IjKl", "createdAt": "2026-10-21T14:30:01Z", "expireAt": null,
		 "assignedRoles": [{"roleId": "r-auditor", "roleName": "sandbox-auditor", "roleType": "custom"}], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]}
	]`

	kitKeysPage2 = `[
		{"id": "6f3a4b50-0000-4000-8000-000000000004", "name": "sandbox-disabled", "state": "disabled", "roles": [], "keySuffix": "MnOp", "createdAt": "2026-10-21T14:30:02Z", "expireAt": "",
		 "assignedRoles": [], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]},
		{"id": "6f3a4b50-0000-4000-8000-000000000005", "name": "sandbox-expiring", "state": "enabled", "roles": [], "keySuffix": "QrSt", "createdAt": "2026-10-21T14:30:03Z", "expireAt": "2030-01-01T00:00:00Z",
		 "assignedRoles": [], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]},
		{"id": "6f3a4b50-0000-4000-8000-000000000006", "name": "sandbox-ip-limited", "state": "enabled", "roles": [], "keySuffix": "UvWx", "createdAt": "2026-10-21T14:30:04Z",
		 "assignedRoles": [], "ipAccessList": [{"source": "203.0.113.0/24", "description": "Documentation range"}]}
	]`

	kitRolesBody = `[
		{"id": "r-admin", "tenantId": "organization/` + kitOrgID + `", "ownerId": "organization/` + kitOrgID + `", "name": "Admin", "type": "system",
		 "actors": ["user/4d1e2f30-0000-4000-8000-000000000001", "apiKey/6f3a4b50-0000-4000-8000-000000000001"],
		 "policies": [{"id": "p1", "roleId": "r-admin", "allowDeny": "ALLOW", "permissions": ["control-plane:organization:manage"], "resources": ["organization/` + kitOrgID + `"]}]},
		{"id": "r-collector", "name": "epack-collector", "type": "custom", "actors": ["apiKey/6f3a4b50-0000-4000-8000-000000000002"],
		 "policies": [{"id": "p2", "roleId": "r-collector", "allowDeny": "ALLOW", "permissions": ["control-plane:organization:view", "control-plane:organization:view-api-keys"], "resources": ["organization/` + kitOrgID + `"]}]},
		{"id": "r-auditor", "name": "sandbox-auditor", "type": "custom", "actors": ["user/4d1e2f30-0000-4000-8000-000000000003", "apiKey/6f3a4b50-0000-4000-8000-000000000003"],
		 "policies": [
			{"id": "p3", "roleId": "r-auditor", "allowDeny": "ALLOW", "permissions": ["control-plane:organization:view"], "resources": ["organization/` + kitOrgID + `"]},
			{"id": "p4", "roleId": "r-auditor", "allowDeny": "ALLOW", "permissions": ["control-plane:service:view"], "resources": ["instance/*"]}
		 ]},
		{"id": "r-member", "name": "Member", "type": "system", "actors": ["user/4d1e2f30-0000-4000-8000-000000000002", "user/4d1e2f30-0000-4000-8000-000000000003"], "policies": []}
	]`
)

// kitUsers mirrors the sandbox's database users (seed/seed.sql), with two of
// ClickHouse Cloud's own.
var kitUsers = []string{
	`{"name": "analyst", "storage": "replicated", "auth_types": ["sha256_password"], "valid_until": ["1970-01-01T00:00:00Z"], "second_factors": [""], "host_ip": ["::/0"], "host_names": [], "host_names_regexp": [], "host_names_like": []}`,
	`{"name": "default", "storage": "replicated", "auth_types": ["sha256_password"], "valid_until": ["1970-01-01T00:00:00Z"], "second_factors": [""], "host_ip": ["::/0"], "host_names": [], "host_names_regexp": [], "host_names_like": []}`,
	`{"name": "deploy_bot", "storage": "replicated", "auth_types": ["ssh_key"], "valid_until": ["1970-01-01T00:00:00Z"], "second_factors": [""], "host_ip": ["::/0"], "host_names": [], "host_names_regexp": [], "host_names_like": []}`,
	`{"name": "epack_collector", "storage": "replicated", "auth_types": ["sha256_password"], "valid_until": ["1970-01-01T00:00:00Z"], "second_factors": [""], "host_ip": ["::/0"], "host_names": [], "host_names_regexp": [], "host_names_like": []}`,
	`{"name": "legacy_app", "storage": "replicated", "auth_types": ["sha256_password", "ssh_key"], "valid_until": ["1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"], "second_factors": ["", ""], "host_ip": ["::/0"], "host_names": [], "host_names_regexp": [], "host_names_like": []}`,
	`{"name": "monitoring-internal", "storage": "users_xml", "auth_types": ["ssl_certificate"], "valid_until": ["1970-01-01T00:00:00Z"], "second_factors": [""], "host_ip": [], "host_names": ["localhost"], "host_names_regexp": [], "host_names_like": []}`,
	`{"name": "office_only", "storage": "replicated", "auth_types": ["sha256_password"], "valid_until": ["1970-01-01T00:00:00Z"], "second_factors": [""], "host_ip": ["10.0.0.0/8"], "host_names": [], "host_names_regexp": [], "host_names_like": []}`,
	`{"name": "operator-internal", "storage": "users_xml", "auth_types": ["no_password"], "valid_until": ["1970-01-01T00:00:00Z"], "second_factors": [""], "host_ip": ["10.0.0.0/8"], "host_names": [], "host_names_regexp": [], "host_names_like": []}`,
	`{"name": "ops_admin", "storage": "replicated", "auth_types": ["sha256_password"], "valid_until": ["2030-01-01T00:00:00Z"], "second_factors": [""], "host_ip": ["::/0"], "host_names": [], "host_names_regexp": [], "host_names_like": []}`,
	`{"name": "otp_user", "storage": "replicated", "auth_types": ["plaintext_password", "no_password"], "valid_until": ["1970-01-01T00:00:00Z", "2026-11-01T00:00:00Z"], "second_factors": ["one_time_password", ""], "host_ip": [], "host_names": ["localhost"], "host_names_regexp": ["^app[0-9]+\\.internal$"], "host_names_like": ["%.corp"]}`,
	`{"name": "sql-console", "storage": "replicated", "auth_types": ["jwt"], "valid_until": ["1970-01-01T00:00:00Z"], "second_factors": [""], "host_ip": ["::/0"], "host_names": [], "host_names_regexp": [], "host_names_like": []}`,
}

var kitRoles = []string{
	`{"name": "access_reader", "storage": "replicated"}`,
	`{"name": "app_reader", "storage": "replicated"}`,
	`{"name": "clickpipes_system", "storage": "replicated"}`,
	`{"name": "default_role", "storage": "replicated"}`,
	`{"name": "sql_console_admin", "storage": "replicated"}`,
	`{"name": "sql_console_read_only", "storage": "replicated"}`,
	`{"name": "user_admin", "storage": "replicated"}`,
}

var kitRoleGrants = []string{
	`{"user_name": "analyst", "role_name": null, "granted_role_name": "app_reader", "granted_role_is_default": 1, "with_admin_option": 0, "user_storage": "replicated"}`,
	`{"user_name": "default", "role_name": null, "granted_role_name": "default_role", "granted_role_is_default": 1, "with_admin_option": 1, "user_storage": "replicated"}`,
	`{"user_name": "epack_collector", "role_name": null, "granted_role_name": "access_reader", "granted_role_is_default": 1, "with_admin_option": 0, "user_storage": "replicated"}`,
	`{"user_name": "office_only", "role_name": null, "granted_role_name": "app_reader", "granted_role_is_default": 1, "with_admin_option": 0, "user_storage": "replicated"}`,
	`{"user_name": "operator-internal", "role_name": null, "granted_role_name": "default_role", "granted_role_is_default": 1, "with_admin_option": 0, "user_storage": "users_xml"}`,
	`{"user_name": "ops_admin", "role_name": null, "granted_role_name": "user_admin", "granted_role_is_default": 1, "with_admin_option": 1, "user_storage": "replicated"}`,
	`{"user_name": null, "role_name": "sql_console_admin", "granted_role_name": "default_role", "granted_role_is_default": 0, "with_admin_option": 0, "user_storage": ""}`,
}

var kitGrants = []string{
	`{"user_name": "legacy_app", "role_name": null, "access_type": "SELECT", "database": "app", "table": "events", "column": null, "is_partial_revoke": 0, "grant_option": 1, "user_storage": "replicated"}`,
	`{"user_name": "monitoring-internal", "role_name": null, "access_type": "SELECT", "database": "system", "table": null, "column": null, "is_partial_revoke": 0, "grant_option": 0, "user_storage": "users_xml"}`,
	`{"user_name": null, "role_name": "access_reader", "access_type": "SHOW USERS", "database": null, "table": null, "column": null, "is_partial_revoke": 0, "grant_option": 0, "user_storage": ""}`,
	`{"user_name": null, "role_name": "access_reader", "access_type": "SELECT", "database": "system", "table": "grants", "column": null, "is_partial_revoke": 0, "grant_option": 0, "user_storage": ""}`,
	`{"user_name": null, "role_name": "app_reader", "access_type": "SELECT", "database": "app", "table": null, "column": null, "is_partial_revoke": 0, "grant_option": 0, "user_storage": ""}`,
	`{"user_name": null, "role_name": "default_role", "access_type": "ALL", "database": null, "table": null, "column": null, "is_partial_revoke": 0, "grant_option": 1, "user_storage": ""}`,
	`{"user_name": null, "role_name": "default_role", "access_type": "CREATE USER", "database": null, "table": null, "column": null, "is_partial_revoke": 1, "grant_option": 0, "user_storage": ""}`,
	`{"user_name": null, "role_name": "user_admin", "access_type": "CREATE USER", "database": null, "table": null, "column": null, "is_partial_revoke": 0, "grant_option": 0, "user_storage": ""}`,
}

var kitProfiles = []string{
	`{"name": "default", "storage": "users_xml", "apply_to_all": 0, "apply_to_list": [], "apply_to_except": []}`,
	`{"name": "ro_profile", "storage": "replicated", "apply_to_all": 0, "apply_to_list": ["app_reader"], "apply_to_except": []}`,
	`{"name": "everyone_but_ops", "storage": "replicated", "apply_to_all": 1, "apply_to_list": [], "apply_to_except": ["ops_admin"]}`,
}

var kitProfileElements = []string{
	`{"profile_name": "default", "user_name": null, "role_name": null, "setting_name": "readonly", "value": null, "min": null, "max": null, "writability": "CONST", "inherit_profile": null, "profile_storage": "users_xml", "user_storage": ""}`,
	`{"profile_name": "ro_profile", "user_name": null, "role_name": null, "setting_name": "readonly", "value": "1", "min": null, "max": null, "writability": null, "inherit_profile": null, "profile_storage": "replicated", "user_storage": ""}`,
	`{"profile_name": "everyone_but_ops", "user_name": null, "role_name": null, "setting_name": "max_execution_time", "value": "60", "min": null, "max": "600", "writability": "WRITABLE", "inherit_profile": null, "profile_storage": "replicated", "user_storage": ""}`,
	`{"profile_name": null, "user_name": "default", "role_name": null, "setting_name": null, "value": null, "min": null, "max": null, "writability": null, "inherit_profile": "default", "profile_storage": "", "user_storage": "replicated"}`,
	`{"profile_name": null, "user_name": "epack_collector", "role_name": null, "setting_name": "readonly", "value": "1", "min": null, "max": null, "writability": null, "inherit_profile": null, "profile_storage": "", "user_storage": "replicated"}`,
	`{"profile_name": null, "user_name": null, "role_name": "sql_console_read_only", "setting_name": "readonly", "value": "2", "min": null, "max": null, "writability": null, "inherit_profile": null, "profile_storage": "", "user_storage": ""}`,
}

var kitQuotas = []string{
	`{"name": "default", "storage": "users_xml", "keys": ["user_name"], "durations": [3600], "apply_to_all": 0, "apply_to_list": ["default"], "apply_to_except": []}`,
	`{"name": "reader_quota", "storage": "replicated", "keys": [], "durations": [3600], "apply_to_all": 0, "apply_to_list": ["app_reader"], "apply_to_except": []}`,
}

var kitQuotaLimits = []string{
	`{"quota_name": "default", "duration": 3600, "is_randomized_interval": 0, "max_queries": null, "max_errors": null, "max_execution_time": null, "max_failed_sequential_authentications": null, "quota_storage": "users_xml"}`,
	`{"quota_name": "reader_quota", "duration": 3600, "is_randomized_interval": 0, "max_queries": "1000", "max_errors": null, "max_execution_time": 3.5, "max_failed_sequential_authentications": "5", "quota_storage": "replicated"}`,
}

var kitRowPolicies = []string{
	`{"name": "tenant_a ON app.events", "short_name": "tenant_a", "database": "app", "table": "events", "storage": "replicated", "is_restrictive": 0, "apply_to_all": 0, "apply_to_list": ["app_reader"], "apply_to_except": []}`,
}

// kitConsole answers the Cloud API calls of a clean run. roles answers the
// console roles call.
func kitConsole(roles collectortest.Response) []collectortest.Response {
	next := `"limit": 3, "totalCount": 6, `
	return []collectortest.Response{
		{URL: kitAPI, Body: apiBody(kitOrgBody)},
		{URL: kitAPI + "/members", Body: apiBody(kitMembersBody)},
		{URL: kitAPI + "/invitations", Body: apiBody(kitInvitationsBody)},
		{URL: kitAPI + "/keys?", Body: `{"status": 200, "requestId": "0b6f7c1e-3a2d-4c5b-8e9f-102132435467", ` + next + `"nextCursor": "c2", "result": ` + kitKeysPage1 + `}`},
		{URL: kitAPI + "/keys?cursor=c2", Body: `{"status": 200, "requestId": "0b6f7c1e-3a2d-4c5b-8e9f-102132435468", ` + next + `"nextCursor": null, "result": ` + kitKeysPage2 + `}`},
		roles,
	}
}

func kitRolesAllowed() collectortest.Response {
	return collectortest.Response{URL: kitAPI + "/roles", Body: apiBody(kitRolesBody)}
}

// kitRolesRefused is the answer the collector's own key gets, since it lacks
// control-plane:organization:manage.
func kitRolesRefused() collectortest.Response {
	return collectortest.Response{URL: kitAPI + "/roles", Status: http.StatusForbidden, Body: apiError(403, "FORBIDDEN")}
}

// kitDatabase answers every query of a clean run.
func kitDatabase() []collectortest.Response {
	return []collectortest.Response{
		sql(clickhouse.OpGetVersion, sqlBody(`{"version": "26.8.1.2045"}`)),
		sql(clickhouse.OpListUsers, sqlBody(kitUsers...)),
		sql(clickhouse.OpListDatabaseRoles, sqlBody(kitRoles...)),
		sql(clickhouse.OpListRoleGrants, sqlBody(kitRoleGrants...)),
		sql(clickhouse.OpListGrants, sqlBody(kitGrants...)),
		sql(clickhouse.OpListSettingsProfiles, sqlBody(kitProfiles...)),
		sql(clickhouse.OpListSettingsProfileElements, sqlBody(kitProfileElements...)),
		sql(clickhouse.OpListQuotas, sqlBody(kitQuotas...)),
		sql(clickhouse.OpListQuotaLimits, sqlBody(kitQuotaLimits...)),
		sql(clickhouse.OpListRowPolicies, sqlBody(kitRowPolicies...)),
	}
}

// kitClean is an organization like the sandbox's, written by hand, read
// with a key that can also read the console roles: four members, one
// pending invitation and one expired, six API keys over two pages, and one
// service with the sandbox's database users and roles and two of ClickHouse
// Cloud's own users.
func kitClean() collectortest.Scenario {
	return collectortest.Scenario{
		Name:      "clean",
		Responses: append(kitConsole(kitRolesAllowed()), kitDatabase()...),
		Expect: map[string]map[string]any{
			artifactPath: {
				"/organization/id":                                            kitOrgID,
				"/organization/created_at":                                    "2026-10-21T13:58:12Z",
				"/organization/sso_enabled":                                   nil,
				"/members/total_count":                                        4,
				"/members/admin_count":                                        1,
				"/members/mfa_enabled_count":                                  nil,
				"/members/inventory/0/email":                                  "kit+ch-auditor@example.com",
				"/members/inventory/0/roles/1":                                map[string]any{"name": "sandbox-auditor", "type": "custom"},
				"/members/inventory/3/email":                                  "kit+ch-reader@example.com",
				"/invitations/pending_count":                                  1,
				"/invitations/expired_count":                                  1,
				"/invitations/inventory/0/expired":                            true,
				"/api_keys/total_count":                                       6,
				"/api_keys/enabled_count":                                     5,
				"/api_keys/admin_count":                                       1,
				"/api_keys/never_expires_count":                               4,
				"/api_keys/any_address_count":                                 5,
				"/api_keys/never_used_count":                                  4,
				"/api_keys/inventory/1/last_used_at":                          "2026-10-22T09:59:00Z",
				"/api_keys/inventory/3/expires_at":                            nil,
				"/api_keys/inventory/5/ip_access_list":                        []any{"203.0.113.0/24"},
				"/console_roles/total_count":                                  4,
				"/console_roles/custom_count":                                 2,
				"/console_roles/inventory/0/name":                             "Admin",
				"/console_roles/inventory/0/api_key_count":                    1,
				"/services/0/host":                                            kitHost,
				"/services/0/user":                                            defaultDatabaseUser,
				"/services/0/version":                                         "26.8.1.2045",
				"/services/0/users/customer_count":                            9,
				"/services/0/users/cloud_managed_count":                       2,
				"/services/0/users/no_password_count":                         1,
				"/services/0/users/plaintext_password_count":                  1,
				"/services/0/users/any_host_count":                            7,
				"/services/0/users/inventory/6/name":                          "ops_admin",
				"/services/0/users/inventory/6/auth_methods/0/valid_until":    "2030-01-01T00:00:00Z",
				"/services/0/users/inventory/7/auth_methods/0/second_factor":  "one_time_password",
				"/services/0/users/cloud_managed/1/name":                      "operator-internal",
				"/services/0/roles/customer_count":                            3,
				"/services/0/roles/cloud_managed_count":                       4,
				"/services/0/role_grants/customer_count":                      5,
				"/services/0/role_grants/cloud_managed_count":                 2,
				"/services/0/role_grants/with_admin_option_count":             2,
				"/services/0/role_grants/inventory/4/with_admin_option":       true,
				"/services/0/role_grants/cloud_managed/0/user_name":           "operator-internal",
				"/services/0/grants/customer_count":                           5,
				"/services/0/grants/cloud_managed_count":                      3,
				"/services/0/grants/grant_option_count":                       1,
				"/services/0/settings_profiles/customer_count":                2,
				"/services/0/settings_profiles/cloud_managed_count":           1,
				"/services/0/settings_profile_elements/customer_count":        4,
				"/services/0/settings_profile_elements/cloud_managed_count":   2,
				"/services/0/quotas/customer_count":                           1,
				"/services/0/quota_limits/cloud_managed/0/quota_name":         "default",
				"/services/0/settings_profile_elements/inventory/3/user_name": "epack_collector",
				"/services/0/quota_limits/inventory/0/limits":                 map[string]any{"queries": 1000, "execution_time": 3.5, "failed_sequential_authentications": 5},
				"/services/0/row_policies/inventory/0/short_name":             "tenant_a",
			},
		},
	}
}
