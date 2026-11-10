package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

// kitNow is the time the hand-built scenarios run at, a day after the
// sandbox was made.
var kitNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// kitResultPath is where the kit's runs write their collector result.
const kitResultPath = "artifacts/clickhouse.collector-result.json"

// kitSteps are a run's steps in order. A run with no services makes only
// the first four.
var kitSteps = []string{"sign_in", "members", "api_keys", "console_roles", "databases"}

// kitServiceParts are the parts of a service a failed first query leaves
// out, in the order their gaps are recorded.
var kitServiceParts = append([]string{"version"}, serviceParts...)

// TestCollectorKit runs the collector against the scenarios below and any
// recorded from the sandbox, then injects faults into each operation's
// calls and checks the output against the schema, every collection level,
// and the credential and sensitivity rules.
func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  kitConfig(),
		Secrets: kitSecrets(),
		Clock:   kitNow,
		Scenarios: append([]collectortest.Scenario{
			kitClean(),
			kitLeastPrivilegeKey(),
			kitEmptyOrganization(),
			kitTrustLevel(),
			kitStaleKeys(),
			kitNoUsableKeys(),
			kitKeyWithoutCreationTime(),
			kitCollectAccessOnly(),
			kitCollectDetailsOnly(),
			{
				Name:      "no services configured",
				Config:    map[string]any{"services": nil},
				Responses: kitConsole(kitRolesRefused()),
				Expect: map[string]map[string]any{
					artifactPath:  {"/services": []any{}},
					kitResultPath: {"/steps/3/name": "console_roles", "/steps/4": collectortest.Absent},
				},
			},
			kitDatabasePasswordRejected(),
			kitMissingShowUsers(),
			kitSourceAndPrefixGrants(),
			kitOlderServerGrants(),
			kitSQLConsoleRoles(),
			kitNoRolesListed(),
			kitExpiredNoPassword(),
			kitAPIKeysFail("API keys call fails with a server error", http.StatusInternalServerError, apiError(500, "INTERNAL_SERVER_ERROR"), map[string]any{
				"code": "vendor_error", "missing_permission": collectortest.Absent, "warning": collectortest.Absent,
			}),
			kitAPIKeysFail("API keys call refused", http.StatusForbidden, apiError(403, "FORBIDDEN"), map[string]any{
				"code": "permission_denied", "missing_permission": clickhouse.PermissionViewAPIKeys,
				"warning": "Give the API key's role control-plane:organization:view-api-keys to list API keys.",
			}),
			{
				Name:          "API key refused from the runner's address",
				ExpectFailure: componentsdk.CodePermissionDenied,
				Responses:     []collectortest.Response{{URL: kitAPI, Status: http.StatusForbidden, Body: apiError(403, "FORBIDDEN: IP address not allowed")}},
			},
			{
				Name:          "API key rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses:     []collectortest.Response{{URL: kitAPI, Status: http.StatusUnauthorized, Body: apiError(401, "Unauthorized")}},
			},
		}, kitRecordings(t, "clickhouse")...),
		// The sign-in is the only call whose failure may fail the run.
		Required: []string{clickhouse.OpGetOrganization},
		Semantics: []collectortest.Semantic{
			{
				Operation:     clickhouse.OpGetOrganization,
				Fault:         "404",
				Meaning:       "no organization has the configured ID",
				ExpectFailure: componentsdk.CodeConfigInvalid,
			},
		},
		Operations: []string{
			clickhouse.OpGetOrganization,
			clickhouse.OpListMembers,
			clickhouse.OpListInvitations,
			clickhouse.OpListKeys,
			clickhouse.OpListRoles,
			clickhouse.OpGetVersion,
			clickhouse.OpListUsers,
			clickhouse.OpListDatabaseRoles,
			clickhouse.OpListRoleGrants,
			clickhouse.OpListGrants,
			clickhouse.OpListSettingsProfiles,
			clickhouse.OpListSettingsProfileElements,
			clickhouse.OpListQuotas,
			clickhouse.OpListQuotaLimits,
			clickhouse.OpListRowPolicies,
		},
		// The sign-in's response holds only strings the collector reads,
		// which the sensitivity check leaves as they are.
		Insensitive: []string{clickhouse.OpGetOrganization},
		// Every gap a fault leaves names the faulted call, since the clients
		// build their errors with componentsdk.ResponseError.
		GapOperations: true,
	})
}

// kitLeastPrivilegeKey is a read-only key, with control-plane:organization:view
// and view-api-keys only. The Cloud API lists no members to it and refuses
// it the console roles, so both are left out with permission_denied gaps
// naming control-plane:organization:manage.
func kitLeastPrivilegeKey() collectortest.Scenario {
	result := kitStepPins()
	access := kitAccessGaps("/admins", "/members")
	details := len(access)
	kitGap(result, details, map[string]any{
		"pointer": "/console_roles", "status": "not_collected",
		"code": "permission_denied", "owner": "customer", "vendor_code": "FORBIDDEN",
		"operation": clickhouse.OpListRoles, "call": 6,
		"missing_permission": clickhouse.PermissionManageOrganization,
		"warning":            "Reading console role definitions needs control-plane:organization:manage, which can also change the organization.",
		"detail":             "the ClickHouse Cloud API returned status 403: FORBIDDEN",
	})
	membersHidden := map[string]any{
		"status": "not_collected", "code": "permission_denied", "owner": "customer",
		"operation": clickhouse.OpListMembers, "call": 2,
		"missing_permission": clickhouse.PermissionManageOrganization,
		"warning":            "ClickHouse Cloud's API reference says control-plane:organization:view is enough to list members (https://clickhouse.com/docs/products/cloud/api-reference/user-management/list-organization-members). In practice the API returns an empty list unless the key's role also has control-plane:organization:manage, which can also change the organization. This looks like a bug in ClickHouse Cloud.",
		"detail":             "clickhouse.members.list: the API returned no members, and an organization always has at least one",
	}
	kitGap(result, details+1, membersHidden)
	kitGap(result, details+1, map[string]any{"pointer": "/members", "path": artifactPath})
	kitGap(result, details+2, map[string]any{"pointer": "/organization/sso_enabled", "code": "unsupported", "owner": "nobody"})
	result[fmt.Sprintf("/gaps/%d", details+3)] = collectortest.Absent
	// The access-posture file's members and admins come from the same list,
	// so they carry the same gap.
	for _, section := range []string{"/admins", "/members"} {
		kitGap(result, slices.Index(access, section), membersHidden)
		kitGap(result, slices.Index(access, section), map[string]any{"pointer": section, "path": accessPath})
	}
	result["/signed_in_as"] = map[string]any{"provider": "clickhouse", "kind": "api_key", "tenant_id": kitOrgID, "auth_method": "api_token"}
	responses := kitConsole(kitRolesRefused())
	responses[1] = collectortest.Response{URL: kitAPI + "/members", Body: apiBody(`[]`)}
	return collectortest.Scenario{
		Name:      "read-only key",
		Responses: append(responses, kitDatabase()...),
		Expect: map[string]map[string]any{
			artifactPath: {
				"/members":                 collectortest.Absent,
				"/console_roles":           collectortest.Absent,
				"/invitations/total_count": 2,
				"/api_keys/total_count":    6,
			},
			accessPath: {
				"/members":                      collectortest.Absent,
				"/admins":                       collectortest.Absent,
				"/credentials/credential_count": 5,
			},
			kitResultPath: result,
		},
	}
}

// kitEmptyOrganization has only its owner and the owner's key, and a
// service with only what ClickHouse Cloud creates.
func kitEmptyOrganization() collectortest.Scenario {
	owner := `[{"userId": "4d1e2f30-0000-4000-8000-000000000001", "name": "Owner", "email": "kit+ch-owner@example.com", "joinedAt": "2026-10-21T13:58:12Z", "assignedRoles": [{"roleId": "r-admin", "roleName": "Admin", "roleType": "system"}]}]`
	key := `[{"id": "6f3a4b50-0000-4000-8000-000000000001", "name": "admin", "state": "enabled", "createdAt": "2026-10-21T14:00:00Z", "assignedRoles": [{"roleId": "r-admin", "roleName": "Admin", "roleType": "system"}], "ipAccessList": []}]`
	empty := map[string]any{}
	for _, part := range []string{"settings_profiles", "settings_profile_elements", "quotas", "quota_limits", "row_policies"} {
		empty["/services/0/"+part] = map[string]any{"customer_count": 0, "cloud_managed_count": 0, "inventory": []any{}, "cloud_managed": []any{}}
	}
	empty["/services/0/role_grants"] = map[string]any{"customer_count": 0, "cloud_managed_count": 0, "with_admin_option_count": 0, "inventory": []any{}, "cloud_managed": []any{}}
	empty["/services/0/grants"] = map[string]any{"customer_count": 0, "cloud_managed_count": 0, "grant_option_count": 0, "inventory": []any{}, "cloud_managed": []any{}}
	empty["/members/total_count"] = 1
	empty["/invitations"] = map[string]any{"total_count": 0, "pending_count": 0, "expired_count": 0, "inventory": []any{}}
	empty["/api_keys/any_address_count"] = 0
	empty["/api_keys/inventory/0/ip_access_list"] = []any{}
	empty["/services/0/users/customer_count"] = 0
	empty["/services/0/users/inventory"] = []any{}
	empty["/services/0/roles/customer_count"] = 0
	empty["/services/0/roles/inventory"] = []any{}
	access := map[string]any{
		"/members": map[string]any{"members_present": true, "member_count": 1},
		"/admins":  map[string]any{"admins_present": true, "admin_count": 1, "admin_share_pct": 100},
		"/credentials": map[string]any{
			"credentials_present": true, "credential_count": 1,
			"never_expiring_credential_count": 1, "never_expiring_pct": 100,
			"unused_credential_count": 1, "unused_pct": 100,
			"unrestricted_credential_count": 0, "unrestricted_pct": 0,
			"write_access_credential_count": 1, "write_access_pct": 100,
			"rotation_overdue_credential_count": 0, "rotation_overdue_pct": 0,
		},
	}
	return collectortest.Scenario{
		Name: "empty organization",
		Responses: []collectortest.Response{
			{URL: kitAPI, Body: apiBody(kitOrgBody)},
			{URL: kitAPI + "/members", Body: apiBody(owner)},
			{URL: kitAPI + "/invitations", Body: apiBody(`[]`)},
			{URL: kitAPI + "/keys?", Body: `{"status": 200, "limit": 250, "totalCount": 1, "nextCursor": null, "result": ` + key + `}`},
			kitRolesRefused(),
			sql(clickhouse.OpGetVersion, sqlBody(`{"version": "26.8.1.2045"}`)),
			sql(clickhouse.OpListUsers, sqlBody(kitUsers[5])),
			sql(clickhouse.OpListDatabaseRoles, sqlBody(kitRoles[2:6]...)),
			sql(clickhouse.OpListRoleGrants, sqlBody()),
			sql(clickhouse.OpListGrants, sqlBody()),
			sql(clickhouse.OpListSettingsProfiles, sqlBody()),
			sql(clickhouse.OpListSettingsProfileElements, sqlBody()),
			sql(clickhouse.OpListQuotas, sqlBody()),
			sql(clickhouse.OpListQuotaLimits, sqlBody()),
			sql(clickhouse.OpListRowPolicies, sqlBody()),
		},
		Expect: map[string]map[string]any{artifactPath: empty, accessPath: access},
	}
}

// kitDatabasePasswordRejected is a service that rejects the collector's
// database password. ClickHouse answers with a 403, as it does for a missing
// grant, and only the exception code tells them apart.
func kitDatabasePasswordRejected() collectortest.Scenario {
	rejected := sqlError(clickhouse.OpGetVersion, http.StatusForbidden, 516,
		"Code: 516. DB::Exception: epack_collector: Authentication failed: password is incorrect, or there is no user with such name. (AUTHENTICATION_FAILED) (version 26.8.1.2045 (official build))\n")
	// The result lists gaps by path and then pointer. The service's come
	// after the access-posture file's and the two the console leaves.
	parts := slices.Sorted(slices.Values(kitServiceParts))
	first := len(kitAccessGaps()) + 2
	detailed, result := map[string]any{}, map[string]any{}
	for i, part := range parts {
		detailed["/services/0/"+part] = collectortest.Absent
		kitGap(result, first+i, map[string]any{
			"pointer":     "/services/0/" + part,
			"code":        "auth_failed",
			"vendor_code": "AUTHENTICATION_FAILED",
			"operation":   clickhouse.OpGetVersion,
			"warning":     "The service rejected the password for epack_collector. Check CLICKHOUSE_DB_PASSWORD and the user in services.",
		})
	}
	result[fmt.Sprintf("/gaps/%d", first+len(parts))] = collectortest.Absent
	return collectortest.Scenario{
		Name:      "database password rejected",
		Responses: append(kitConsole(kitRolesAllowed()), rejected),
		Expect:    map[string]map[string]any{artifactPath: detailed, kitResultPath: result},
	}
}

// kitMissingShowUsers is a database user that lacks SHOW USERS, so the
// service's users are left out and everything else is read.
func kitMissingShowUsers() collectortest.Scenario {
	denied := sqlError(clickhouse.OpListUsers, http.StatusForbidden, 497,
		"Code: 497. DB::Exception: epack_collector: Not enough privileges. To execute this query, it's necessary to have the grant SHOW USERS ON *.*. (ACCESS_DENIED) (version 26.8.1.2045 (official build))\n")
	return collectortest.Scenario{
		Name:      "database user lacks SHOW USERS",
		Responses: append(append(kitConsole(kitRolesAllowed()), denied), kitDatabase()...),
		Expect: map[string]map[string]any{
			artifactPath: {"/services/0/users": collectortest.Absent, "/services/0/roles/customer_count": 3},
			kitResultPath: kitGapPins(len(kitAccessGaps())+2, map[string]any{
				"pointer":     "/services/0/users",
				"code":        "permission_denied",
				"vendor_code": "ACCESS_DENIED",
				"operation":   clickhouse.OpListUsers,
				"warning":     "Grant SHOW USERS to epack_collector. docs/configuration.md lists every grant the collector needs.",
			}),
		},
	}
}

// kitAnswered is a clean run in which each query named in bodies gets that
// body for its answer.
func kitAnswered(bodies map[string]string) []collectortest.Response {
	database := kitDatabase()
	for i, r := range database {
		if body, ok := bodies[r.Operation]; ok {
			database[i] = sql(r.Operation, body)
		}
	}
	return append(kitConsole(kitRolesAllowed()), database...)
}

// kitSourceAndPrefixGrants has grants that differ only in their source, or
// in whether their database name is a prefix.
func kitSourceAndPrefixGrants() collectortest.Scenario {
	grant := func(access, database, source string, wildcard int) string {
		return fmt.Sprintf(`{"user_name": null, "role_name": "app_reader", "access_type": %q, "database": %s, "table": null, "column": null, "is_partial_revoke": 0, "grant_option": 0, "access_object": %q, "is_wildcard": %d, "user_storage": ""}`,
			access, database, source, wildcard)
	}
	return collectortest.Scenario{
		Name: "grants on sources and database name prefixes",
		Responses: kitAnswered(map[string]string{clickhouse.OpListGrants: sqlBody(
			grant("READ", "null", "S3", 0),
			grant("READ", "null", "URL", 0),
			grant("SELECT", `"sales"`, "", 0),
			grant("SELECT", `"sales"`, "", 1),
		)}),
		Expect: map[string]map[string]any{artifactPath: {
			"/services/0/grants/customer_count":            4,
			"/services/0/grants/inventory/0/access_object": "S3",
			"/services/0/grants/inventory/1/access_object": "URL",
			"/services/0/grants/inventory/2/is_wildcard":   false,
			"/services/0/grants/inventory/3/is_wildcard":   true,
		}},
	}
}

// kitOlderServerGrants is a service on ClickHouse 25.3, whose system.grants
// has neither access_object nor is_wildcard.
func kitOlderServerGrants() collectortest.Scenario {
	return collectortest.Scenario{
		Name: "grants from a server older than 25.8",
		Responses: kitAnswered(map[string]string{
			clickhouse.OpGetVersion: sqlBody(`{"version": "25.3.1.1"}`),
			clickhouse.OpListGrants: sqlBody(`{"user_name": null, "role_name": "app_reader", "access_type": "SELECT", "database": "app", "table": null, "column": null, "is_partial_revoke": 0, "grant_option": 0, "user_storage": ""}`),
		}),
		Expect: map[string]map[string]any{artifactPath: {
			"/services/0/grants/customer_count":            1,
			"/services/0/grants/inventory/0/access_object": nil,
			"/services/0/grants/inventory/0/is_wildcard":   nil,
		}},
	}
}

// kitSQLConsoleRoles has the Service Reader and Service Admin system roles
// as the sandbox recording holds them. Their policies differ only in
// tags.roleV2.
func kitSQLConsoleRoles() collectortest.Scenario {
	roles := `[
		{"id": "r-service-reader", "name": "Service Reader", "type": "system", "actors": [],
		 "policies": [{"id": "p1", "allowDeny": "ALLOW", "permissions": ["sql-console:database:access"], "resources": ["instance/*"], "tags": {"roleV2": "sql-console-readonly"}}]},
		{"id": "r-service-admin", "name": "Service Admin", "type": "system", "actors": [],
		 "policies": [{"id": "p2", "allowDeny": "ALLOW", "permissions": ["sql-console:database:access"], "resources": ["instance/*"], "tags": {"roleV2": "sql-console-admin"}}]},
		{"id": "r-member", "name": "Member", "type": "system", "actors": [],
		 "policies": [{"id": "p3", "allowDeny": "ALLOW", "permissions": ["control-plane:organization:view"], "resources": ["organization/` + kitOrgID + `"], "tags": {}}]}
	]`
	return collectortest.Scenario{
		Name:      "SQL console roles",
		Responses: append(kitConsole(collectortest.Response{URL: kitAPI + "/roles", Body: apiBody(roles)}), kitDatabase()...),
		Expect: map[string]map[string]any{artifactPath: {
			"/console_roles/inventory/0/name":                    "Member",
			"/console_roles/inventory/0/policies/0/tags":         map[string]any{"role_v2": nil, "grants": nil},
			"/console_roles/inventory/1/name":                    "Service Admin",
			"/console_roles/inventory/1/policies/0/tags/role_v2": "sql-console-admin",
			"/console_roles/inventory/2/name":                    "Service Reader",
			"/console_roles/inventory/2/policies/0/tags/role_v2": "sql-console-readonly",
		}},
	}
}

// kitNoRolesListed answers the roles call with an empty list. Every
// organization has the system roles, so the roles are left out with a
// permission_denied gap, as the members are when none are listed.
func kitNoRolesListed() collectortest.Scenario {
	result := map[string]any{}
	kitGap(result, len(kitAccessGaps()), map[string]any{
		"pointer": "/console_roles", "code": "permission_denied", "operation": clickhouse.OpListRoles,
		"missing_permission": clickhouse.PermissionManageOrganization,
		"warning":            "Reading console role definitions needs control-plane:organization:manage, which can also change the organization.",
		"detail":             "clickhouse.roles.list: the API returned no roles, and an organization always has its system roles",
	})
	return collectortest.Scenario{
		Name:      "roles call lists no roles",
		Responses: append(kitConsole(collectortest.Response{URL: kitAPI + "/roles", Body: apiBody(`[]`)}), kitDatabase()...),
		Expect:    map[string]map[string]any{artifactPath: {"/console_roles": collectortest.Absent}, kitResultPath: result},
	}
}

// kitExpiredNoPassword has otp_user's no_password method expire before the
// run, so no customer user can sign in with no password. The no_password
// method of operator-internal, one of ClickHouse Cloud's own users, never
// expires.
func kitExpiredNoPassword() collectortest.Scenario {
	users := slices.Clone(kitUsers)
	for i, u := range users {
		if strings.Contains(u, `"name": "otp_user"`) {
			users[i] = strings.Replace(u, `"2026-11-01T00:00:00Z"`, `"2026-10-01T00:00:00Z"`, 1)
		}
	}
	return collectortest.Scenario{
		Name:      "no_password method expired",
		Responses: kitAnswered(map[string]string{clickhouse.OpListUsers: sqlBody(users...)}),
		Expect: map[string]map[string]any{artifactPath: {
			"/services/0/users/no_password_count":                      0,
			"/services/0/users/inventory/7/name":                       "otp_user",
			"/services/0/users/inventory/7/no_password":                false,
			"/services/0/users/inventory/7/auth_methods/1/valid_until": "2026-10-01T00:00:00Z",
			"/services/0/users/cloud_managed/1/name":                   "operator-internal",
			"/services/0/users/cloud_managed/1/no_password":            true,
		}},
	}
}

// kitAPIKeysFail answers the keys call with status and body. gap pins the
// fields of the gap at /api_keys, which the access-posture file's
// credentials carry too.
func kitAPIKeysFail(name string, status int, body string, gap map[string]any) collectortest.Scenario {
	responses := kitConsole(kitRolesAllowed())
	responses = append(responses[:3:3], collectortest.Response{URL: kitAPI + "/keys?", Status: status, Body: body}, responses[5])
	access := kitAccessGaps("/credentials")
	result := map[string]any{}
	kitGap(result, len(access), gap)
	kitGap(result, len(access), map[string]any{"pointer": "/api_keys", "path": artifactPath})
	kitGap(result, slices.Index(access, "/credentials"), gap)
	kitGap(result, slices.Index(access, "/credentials"), map[string]any{"pointer": "/credentials", "path": accessPath})
	return collectortest.Scenario{
		Name:      name,
		Responses: append(responses, kitDatabase()...),
		Expect: map[string]map[string]any{
			artifactPath:  {"/api_keys": collectortest.Absent},
			accessPath:    {"/credentials": collectortest.Absent, "/members/member_count": 4},
			kitResultPath: result,
		},
	}
}

// kitAccessGaps returns the pointers of the access-posture file's gaps in a
// run at the audit level or above, in the order the result lists them,
// which is before the detailed artifact's. left adds the sections a failed
// list leaves out.
func kitAccessGaps(left ...string) []string {
	pointers := slices.Clone(left)
	for _, u := range accessLeftOut {
		pointers = append(pointers, u.pointer)
	}
	slices.Sort(pointers)
	return pointers
}

// kitGap pins fields of the result's gap at index.
func kitGap(pins map[string]any, index int, fields map[string]any) {
	for field, value := range fields {
		pins[fmt.Sprintf("/gaps/%d/%s", index, field)] = value
	}
}

// kitGapPins pins fields of the result's gap at index, and that it is the
// last gap.
func kitGapPins(index int, fields map[string]any) map[string]any {
	pins := map[string]any{fmt.Sprintf("/gaps/%d", index+1): collectortest.Absent}
	kitGap(pins, index, fields)
	return pins
}

// kitStepPins pins a run's five steps in order, and that there are no more.
func kitStepPins() map[string]any {
	pins := map[string]any{}
	for i, name := range kitSteps {
		pins[fmt.Sprintf("/steps/%d/name", i)] = name
	}
	pins[fmt.Sprintf("/steps/%d", len(kitSteps))] = collectortest.Absent
	return pins
}

// kitRecordings loads the scenarios TestRecord in record_test.go records
// from sandboxes, and logs each one not recorded yet.
func kitRecordings(t *testing.T, names ...string) []collectortest.Scenario {
	t.Helper()
	var out []collectortest.Scenario
	for _, name := range names {
		path := filepath.Join("testdata", "recordings", name+".json")
		sc, err := collectortest.LoadScenario(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			t.Logf("no recording at %s yet", path)
		case err != nil:
			t.Fatal(err)
		default:
			out = append(out, sc)
		}
	}
	return out
}

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	without := func(name string) map[string]string {
		secrets := kitSecrets()
		delete(secrets, name)
		return secrets
	}
	cases := map[string]struct {
		config  map[string]any
		secrets map[string]string
	}{
		"no organization ID":          {map[string]any{"level": "internal"}, kitSecrets()},
		"organization ID not a UUID":  {map[string]any{"organization_id": "my-org"}, kitSecrets()},
		"no key ID":                   {kitConfig(), without(keyIDEnv)},
		"no key secret":               {kitConfig(), without(keySecretEnv)},
		"no database password":        {kitConfig(), without(dbPasswordEnv)},
		"service host with a scheme":  {map[string]any{"organization_id": kitOrgID, "services": []any{map[string]any{"host": "https://" + kitHost}}}, kitSecrets()},
		"service without a host":      {map[string]any{"organization_id": kitOrgID, "services": []any{map[string]any{"user": "reader"}}}, kitSecrets()},
		"services not a list":         {map[string]any{"organization_id": kitOrgID, "services": kitHost}, kitSecrets()},
		"service listed twice":        {map[string]any{"organization_id": kitOrgID, "services": []any{map[string]any{"host": kitHost}, map[string]any{"host": kitHost}}}, kitSecrets()},
		"service with an unknown key": {map[string]any{"organization_id": kitOrgID, "services": []any{map[string]any{"host": kitHost, "password": "x"}}}, kitSecrets()},
		"service with an empty user":  {map[string]any{"organization_id": kitOrgID, "services": []any{map[string]any{"host": kitHost, "user": " "}}}, kitSecrets()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
				Config:  tc.config,
				Secrets: tc.secrets,
			})
			if res.ExitCode != 2 || res.Failure == nil || res.Failure.Code != componentsdk.CodeConfigInvalid {
				t.Errorf("exit %d, failure %+v; want exit 2 with config_invalid", res.ExitCode, res.Failure)
			}
		})
	}
}

// A trust run writes neither the organization's ID nor a service's host in
// any artifact, even for a service it could not reach. An audit run still
// writes both.
func TestATrustRunWritesNoIDsOrHosts(t *testing.T) {
	const unreachable = "kit0service2.us-east-1.aws.clickhouse.cloud"
	for _, a := range runAtLevel(t, componentsdk.LevelTrust, unreachable).Artifacts {
		for _, id := range []string{kitOrgID, kitHost, unreachable} {
			if strings.Contains(string(a.Data), id) {
				t.Errorf("the trust run wrote %s in %s", id, a.Path)
			}
		}
	}
	for _, a := range runAtLevel(t, componentsdk.LevelAudit, unreachable).Artifacts {
		if a.Path != artifactPath {
			continue
		}
		var out Output
		if err := json.Unmarshal(a.Data, &out); err != nil {
			t.Fatal(err)
		}
		if out.Organization.ID != kitOrgID {
			t.Errorf("the audit run wrote organization ID %q, want %q", out.Organization.ID, kitOrgID)
		}
		var hosts []string
		for _, svc := range out.Services {
			hosts = append(hosts, svc.Host)
		}
		if want := []string{kitHost, unreachable}; !slices.Equal(hosts, want) {
			t.Errorf("the audit run wrote hosts %q, want %q", hosts, want)
		}
		return
	}
	t.Fatalf("the audit run wrote no %s", artifactPath)
}

// The run declares the organization it signed in to and the services the
// config lists. A service it could not reach leaves the services
// incomplete. Only the audit level counts them.
func TestRunDeclaresTheOrganizationAndServices(t *testing.T) {
	const unreachable = "kit0service2.us-east-1.aws.clickhouse.cloud"
	one, two, complete, incomplete := 1, 2, true, false
	targets := func(count, services *int, servicesComplete *bool) []componentsdk.ResultTarget {
		return []componentsdk.ResultTarget{
			{
				Kind: componentsdk.TargetOrganization, ChosenBy: componentsdk.ChosenByConfig, ConfigKey: "organization_id",
				At: &componentsdk.Location{Path: artifactPath, Pointer: "/organization"}, Name: []string{"/name"},
				Count: count, Complete: &complete,
			},
			{
				Kind: componentsdk.TargetService, ChosenBy: componentsdk.ChosenByConfig, ConfigKey: "services",
				At: &componentsdk.Location{Path: artifactPath, Pointer: "/services"}, Name: []string{"/host"},
				Count: services, Complete: servicesComplete,
			},
		}
	}
	cases := []struct {
		name string
		res  componentsdk.InProcessResult
		want []componentsdk.ResultTarget
	}{
		{"audit", runAtLevel(t, componentsdk.LevelAudit), targets(&one, &one, &complete)},
		{"audit, a service unreachable", runAtLevel(t, componentsdk.LevelAudit, unreachable), targets(&one, &two, &incomplete)},
		{"trust, a service unreachable", runAtLevel(t, componentsdk.LevelTrust, unreachable), targets(nil, nil, &incomplete)},
	}
	for _, tc := range cases {
		if !reflect.DeepEqual(tc.res.Result.Targets, tc.want) {
			got, _ := json.Marshal(tc.res.Result.Targets)
			want, _ := json.Marshal(tc.want)
			t.Errorf("%s: targets = %s, want %s", tc.name, got, want)
		}
		for _, f := range tc.res.Result.Checks {
			t.Errorf("%s: check finding %+v", tc.name, f)
		}
	}
}

// runAtLevel runs the clean organization at level, with a further service
// at each host in unreachable, which nothing answers.
func runAtLevel(t *testing.T, level componentsdk.Level, unreachable ...string) componentsdk.InProcessResult {
	t.Helper()
	replay, err := collectortest.NewReplay(collectortest.Scenario{Name: t.Name(), Responses: append(kitConsole(kitRolesAllowed()), kitDatabase()...)})
	if err != nil {
		t.Fatal(err)
	}
	config := kitConfig()
	config["level"] = string(level)
	services := []any{map[string]any{"host": kitHost}}
	for _, host := range unreachable {
		services = append(services, map[string]any{"host": host})
	}
	config["services"] = services
	res := componentsdk.RunInProcess(Spec("test", "collectortest"), Run, componentsdk.InProcessOptions{
		Config:    config,
		Secrets:   kitSecrets(),
		Transport: replay,
		Clock:     func() time.Time { return kitNow },
		Sleep:     func(context.Context, time.Duration) error { return nil },
	})
	if res.ExitCode != 0 {
		t.Fatalf("the %s run exited %d: %+v", level, res.ExitCode, res.Failure)
	}
	return res
}

// kitTrustLevel is the clean organization at the trust level. The
// organization's ID and the service's host are left out. The
// access-posture file has its present flags and percentages and none of its
// counts. Only its trust-level values get an unsupported or not_read gap,
// and neither makes the run partial.
func kitTrustLevel() collectortest.Scenario {
	var trustGaps []string
	for _, v := range accessLeftOut {
		if !v.audit {
			trustGaps = append(trustGaps, v.pointer)
		}
	}
	slices.Sort(trustGaps)
	result := kitGapPins(len(trustGaps)+1, map[string]any{"pointer": "/organization/sso_enabled", "code": "unsupported"})
	kitGap(result, len(trustGaps), map[string]any{"pointer": "/members/mfa_enabled_count", "code": "unsupported"})
	kitGap(result, 0, map[string]any{"pointer": "/admins/local_admin_mfa_coverage_pct", "code": "unsupported", "owner": "nobody"})
	kitGap(result, slices.Index(trustGaps, "/members/inactive_pct"), map[string]any{
		"pointer": "/members/inactive_pct", "code": "not_read", "owner": "publisher",
	})
	result["/outcome/status"] = "collected"
	return collectortest.Scenario{
		Name:      "trust level",
		Config:    map[string]any{"level": "trust"},
		Responses: append(kitConsole(kitRolesAllowed()), kitDatabase()...),
		Expect: map[string]map[string]any{
			artifactPath: {
				"/organization/id":   collectortest.Absent,
				"/organization/name": "Kit Org",
				"/services/0/host":   collectortest.Absent,
				"/services/0/user":   defaultDatabaseUser,
			},
			accessPath: {
				"/members":     map[string]any{"members_present": true},
				"/admins":      map[string]any{"admins_present": true, "admin_share_pct": 25},
				"/credentials": map[string]any{"credentials_present": true, "never_expiring_pct": 60, "unused_pct": 60, "unrestricted_pct": 20, "write_access_pct": 20, "rotation_overdue_pct": 0},
			},
			kitResultPath: result,
		},
	}
}

// kitStaleKeys has keys created or last used more than 90 days before the
// run. Its expired key and its disabled key cannot be used, so they are left
// out of the credentials.
func kitStaleKeys() collectortest.Scenario {
	keys := `[
		{"id": "7a4b5c60-0000-4000-8000-000000000001", "name": "old-admin", "state": "enabled", "createdAt": "2026-01-05T09:00:00Z", "usedAt": "2026-06-01T08:00:00Z",
		 "assignedRoles": [{"roleId": "r-admin", "roleName": "Admin", "roleType": "system"}], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]},
		{"id": "7a4b5c60-0000-4000-8000-000000000002", "name": "recent", "state": "enabled", "createdAt": "2026-10-01T09:00:00Z", "usedAt": "2026-10-20T08:00:00Z", "expireAt": "2027-01-01T00:00:00Z",
		 "assignedRoles": [{"roleId": "r-collector", "roleName": "epack-collector", "roleType": "custom"}], "ipAccessList": [{"source": "203.0.113.0/24", "description": "Office"}]},
		{"id": "7a4b5c60-0000-4000-8000-000000000003", "name": "unused-new", "state": "enabled", "createdAt": "2026-07-25T09:00:00Z", "expireAt": "2026-12-01T00:00:00Z",
		 "assignedRoles": [], "ipAccessList": [{"source": "203.0.113.0/24", "description": "Office"}]},
		{"id": "7a4b5c60-0000-4000-8000-000000000004", "name": "expired", "state": "enabled", "createdAt": "2026-01-05T09:00:00Z", "expireAt": "2026-10-01T00:00:00Z",
		 "assignedRoles": [{"roleId": "r-admin", "roleName": "Admin", "roleType": "system"}], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]},
		{"id": "7a4b5c60-0000-4000-8000-000000000005", "name": "disabled-old", "state": "disabled", "createdAt": "2025-01-05T09:00:00Z",
		 "assignedRoles": [{"roleId": "r-admin", "roleName": "Admin", "roleType": "system"}], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]}
	]`
	return collectortest.Scenario{
		Name:      "API keys past their dates",
		Responses: append(kitKeysAnswered(keys), kitDatabase()...),
		Expect: map[string]map[string]any{
			artifactPath: {"/api_keys/total_count": 5, "/api_keys/never_expires_count": 2},
			accessPath: {"/credentials": map[string]any{
				"credentials_present": true, "credential_count": 3,
				"never_expiring_credential_count": 1, "never_expiring_pct": 34,
				"unused_credential_count": 2, "unused_pct": 67,
				"unrestricted_credential_count": 1, "unrestricted_pct": 34,
				"write_access_credential_count": 1, "write_access_pct": 34,
				"rotation_overdue_credential_count": 1, "rotation_overdue_pct": 34,
			}},
		},
	}
}

// kitNoUsableKeys lists only a disabled key, so the access-posture file has
// no credentials. Its percentages are null and its counts are 0.
func kitNoUsableKeys() collectortest.Scenario {
	keys := `[{"id": "7a4b5c60-0000-4000-8000-000000000006", "name": "disabled", "state": "disabled", "createdAt": "2026-10-21T14:30:02Z",
		"assignedRoles": [], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]}]`
	return collectortest.Scenario{
		Name:      "no API key enabled",
		Responses: append(kitKeysAnswered(keys), kitDatabase()...),
		Expect: map[string]map[string]any{
			artifactPath: {"/api_keys/total_count": 1, "/api_keys/enabled_count": 0},
			accessPath: {"/credentials": map[string]any{
				"credentials_present": false, "credential_count": 0,
				"never_expiring_credential_count": 0, "never_expiring_pct": nil,
				"unused_credential_count": 0, "unused_pct": nil,
				"unrestricted_credential_count": 0, "unrestricted_pct": nil,
				"write_access_credential_count": 0, "write_access_pct": nil,
				"rotation_overdue_credential_count": 0, "rotation_overdue_pct": nil,
			}},
		},
	}
}

// kitKeyWithoutCreationTime lists a key with no createdAt, so the keys
// overdue for rotation cannot be counted. That count and its percentage are
// left out with a partial gap, and the other credential values are written.
func kitKeyWithoutCreationTime() collectortest.Scenario {
	keys := `[
		{"id": "7a4b5c60-0000-4000-8000-000000000007", "name": "no-created-at", "state": "enabled", "usedAt": "2026-10-20T08:00:00Z",
		 "assignedRoles": [], "ipAccessList": [{"source": "0.0.0.0/0", "description": "Anywhere"}]},
		{"id": "7a4b5c60-0000-4000-8000-000000000008", "name": "with-created-at", "state": "enabled", "createdAt": "2026-10-01T09:00:00Z",
		 "assignedRoles": [], "ipAccessList": [{"source": "203.0.113.0/24", "description": "Office"}]}
	]`
	access := kitAccessGaps("/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_pct")
	result := map[string]any{}
	for _, pointer := range []string{"/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_pct"} {
		kitGap(result, slices.Index(access, pointer), map[string]any{
			"pointer": pointer, "status": "partial", "code": "invalid_response", "unmeasured": 1,
			"detail": "clickhouse.keys.list: 1 of the listed keys have no createdAt, or one that is not an RFC 3339 time",
		})
	}
	return collectortest.Scenario{
		Name:      "API key without a creation time",
		Responses: append(kitKeysAnswered(keys), kitDatabase()...),
		Expect: map[string]map[string]any{
			accessPath: {
				"/credentials/credential_count":                  2,
				"/credentials/unused_credential_count":           1,
				"/credentials/rotation_overdue_credential_count": collectortest.Absent,
				"/credentials/rotation_overdue_pct":              collectortest.Absent,
			},
			kitResultPath: result,
		},
	}
}

// kitCollectAccessOnly has the collect config key list only the
// access-posture file. The run reads only the members and the API keys,
// which the file needs.
func kitCollectAccessOnly() collectortest.Scenario {
	console := kitConsole(kitRolesAllowed())
	result := map[string]any{
		"/steps/0/name":     "sign_in",
		"/steps/1/name":     "members",
		"/steps/2/name":     "api_keys",
		"/steps/3":          collectortest.Absent,
		"/collect/listed":   []any{"access-posture"},
		"/collect/left_out": []any{"details"},
	}
	kitGap(result, len(kitAccessGaps()), map[string]any{"path": artifactPath, "code": "not_shared"})
	result[fmt.Sprintf("/gaps/%d", len(kitAccessGaps())+1)] = collectortest.Absent
	return collectortest.Scenario{
		Name:      "collect lists only access-posture",
		Config:    map[string]any{"collect": []any{"access-posture"}},
		Responses: []collectortest.Response{console[0], console[1], console[3], console[4]},
		Expect: map[string]map[string]any{
			accessPath:    {"/members/member_count": 4, "/credentials/credential_count": 5},
			kitResultPath: result,
		},
	}
}

// kitCollectDetailsOnly has the collect config key list only the detailed
// artifact, so the run writes no access-posture file and records none of
// its gaps.
func kitCollectDetailsOnly() collectortest.Scenario {
	result := kitStepPins()
	kitGap(result, 0, map[string]any{"schema": accessSchema, "code": "not_shared"})
	kitGap(result, 1, map[string]any{"pointer": "/members/mfa_enabled_count", "code": "unsupported"})
	kitGap(result, 2, map[string]any{"pointer": "/organization/sso_enabled", "code": "unsupported"})
	result["/gaps/3"] = collectortest.Absent
	result["/collect/left_out"] = []any{"access-posture"}
	return collectortest.Scenario{
		Name:      "collect lists only details",
		Config:    map[string]any{"collect": []any{"details"}},
		Responses: append(kitConsole(kitRolesAllowed()), kitDatabase()...),
		Expect: map[string]map[string]any{
			artifactPath:  {"/members/total_count": 4, "/api_keys/total_count": 6},
			kitResultPath: result,
		},
	}
}

// kitKeysAnswered is a clean run whose keys call answers with keys, a list
// of API keys on one page.
func kitKeysAnswered(keys string) []collectortest.Response {
	console := kitConsole(kitRolesAllowed())
	page := collectortest.Response{URL: kitAPI + "/keys?", Body: `{"status": 200, "requestId": "0b6f7c1e-3a2d-4c5b-8e9f-102132435469", "limit": 250, "nextCursor": null, "result": ` + keys + `}`}
	return append(console[:3:3], page, console[5])
}
