package collector

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"slices"
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
	for field, value := range map[string]any{
		"pointer": "/console_roles", "status": "not_collected",
		"code": "permission_denied", "owner": "customer", "vendor_code": "FORBIDDEN",
		"operation": clickhouse.OpListRoles, "call": 6,
		"missing_permission": clickhouse.PermissionManageOrganization,
		"warning":            "Reading console role definitions needs control-plane:organization:manage, which can also change the organization.",
		"detail":             "the ClickHouse Cloud API returned status 403: FORBIDDEN",
	} {
		result["/gaps/0/"+field] = value
	}
	for field, value := range map[string]any{
		"pointer": "/members", "status": "not_collected",
		"code": "permission_denied", "owner": "customer",
		"operation": clickhouse.OpListMembers, "call": 2,
		"missing_permission": clickhouse.PermissionManageOrganization,
		"warning":            "ClickHouse Cloud's API reference says control-plane:organization:view is enough to list members (https://clickhouse.com/docs/products/cloud/api-reference/user-management/list-organization-members). In practice the API returns an empty list unless the key's role also has control-plane:organization:manage, which can also change the organization. This looks like a bug in ClickHouse Cloud.",
		"detail":             "clickhouse.members.list: the API returned no members, and an organization always has at least one",
	} {
		result["/gaps/1/"+field] = value
	}
	result["/gaps/2/pointer"] = "/organization/sso_enabled"
	result["/gaps/2/code"] = "not_licensed"
	result["/gaps/2/owner"] = "nobody"
	result["/gaps/3"] = collectortest.Absent
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
		Expect: map[string]map[string]any{artifactPath: empty},
	}
}

// kitDatabasePasswordRejected is a service that rejects the collector's
// database password. ClickHouse answers with a 403, as it does for a missing
// grant, and only the exception code tells them apart.
func kitDatabasePasswordRejected() collectortest.Scenario {
	rejected := sqlError(clickhouse.OpGetVersion, http.StatusForbidden, 516,
		"Code: 516. DB::Exception: epack_collector: Authentication failed: password is incorrect, or there is no user with such name. (AUTHENTICATION_FAILED) (version 26.8.1.2045 (official build))\n")
	// The result sorts gaps by pointer, after the two the console leaves.
	parts := slices.Sorted(slices.Values(kitServiceParts))
	detailed, result := map[string]any{}, map[string]any{}
	for i, part := range parts {
		detailed["/services/0/"+part] = collectortest.Absent
		result[fmt.Sprintf("/gaps/%d/pointer", i+2)] = "/services/0/" + part
		result[fmt.Sprintf("/gaps/%d/code", i+2)] = "auth_failed"
		result[fmt.Sprintf("/gaps/%d/vendor_code", i+2)] = "AUTHENTICATION_FAILED"
		result[fmt.Sprintf("/gaps/%d/operation", i+2)] = clickhouse.OpGetVersion
		result[fmt.Sprintf("/gaps/%d/warning", i+2)] = "The service rejected the password for epack_collector. Check CLICKHOUSE_DB_PASSWORD and the user in services."
	}
	result[fmt.Sprintf("/gaps/%d", len(parts)+2)] = collectortest.Absent
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
			kitResultPath: {
				"/gaps/2/pointer":     "/services/0/users",
				"/gaps/2/code":        "permission_denied",
				"/gaps/2/vendor_code": "ACCESS_DENIED",
				"/gaps/2/operation":   clickhouse.OpListUsers,
				"/gaps/2/warning":     "Grant SHOW USERS to epack_collector. docs/configuration.md lists every grant the collector needs.",
				"/gaps/3":             collectortest.Absent,
			},
		},
	}
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
