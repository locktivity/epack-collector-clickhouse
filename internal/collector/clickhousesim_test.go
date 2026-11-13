package collector

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

// simRosterPath is the clickhouse sandbox's roster in v1 form, which
// cmd/derive in epack-collector-sandboxes converts from
// sandboxes/clickhouse/roster.json and the refresh workflow commits here.
const simRosterPath = "testdata/simulator/clickhouse.roster.json"

func simBase(t testing.TB) *roster.Roster {
	t.Helper()
	r, err := roster.Load(simRosterPath)
	if err != nil {
		t.Fatal(err)
	}
	reals, err := r.Realizations()
	if err != nil {
		t.Fatal(err)
	}
	return reals[0].Roster
}

// simSystemRoles are ClickHouse Cloud's own console roles. Every other role
// is a custom one.
var simSystemRoles = []string{"Admin", "Member", "Billing", "Service Reader", "Service Admin", "Developer"}

// simRole is a console role as the roles call lists it. A role whose term
// class is admin or super_admin allows managing the organization, as the
// system Admin role does, and any other only viewing it.
func simRole(r *roster.Roster, name string, actors []string) map[string]any {
	kind := "custom"
	if slices.Contains(simSystemRoles, name) {
		kind = "system"
	}
	permission := "control-plane:organization:view"
	if class := r.Terms.Roles[name]; class == roster.RoleAdmin || class == roster.RoleSuperAdmin {
		permission = "control-plane:organization:manage"
	}
	id := simulate.UUID("role", name)
	return map[string]any{
		"id": id, "tenantId": "organization/" + kitOrgID, "ownerId": "organization/" + kitOrgID, "name": name, "type": kind, "actors": actors,
		"createdAt": "2026-10-21T13:58:12Z", "updatedAt": "2026-10-21T13:58:12Z",
		"policies": []any{map[string]any{
			"id": simulate.UUID("policy", name), "tenantId": "organization/" + kitOrgID, "roleId": id, "allowDeny": "ALLOW",
			"permissions": []string{permission}, "resources": []string{"organization/" + kitOrgID}, "tags": map[string]any{},
		}},
	}
}

func simRoleRef(r *roster.Roster, name string) map[string]any {
	role := simRole(r, name, nil)
	return map[string]any{"roleId": role["id"], "roleName": name, "roleType": role["type"]}
}

func simTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// newClickHouseSim answers every call a run makes for r, at now. The
// members are the roster's enabled people, each signing in with the email
// its tag makes. The API keys are the workspace's credentials, holding the
// console role their permissions name, or none for no_roles. The database
// answers are the recording's: they fill the details artifact alone, and
// the kit's database fixtures don't keep ClickHouse's shapes.
func newClickHouseSim(r *roster.Roster, now time.Time, rec *simulate.Recorded) []collectortest.Response {
	actors := map[string][]string{}
	var members []any
	for _, a := range r.Accounts {
		if !a.Enabled {
			continue
		}
		var tag string
		simulate.Extra(a.Extra, "tag", &tag)
		id := simulate.UUID("user", a.Key)
		role := "developer"
		refs := []any{}
		for _, name := range a.Roles {
			refs = append(refs, simRoleRef(r, name))
			actors[name] = append(actors[name], "user/"+id)
			if name == "Admin" {
				role = "admin"
			}
		}
		members = append(members, map[string]any{
			"userId": id, "name": a.Key, "email": "kit+" + tag + "@example.com", "role": role,
			"joinedAt": simTime(now.AddDate(0, 0, -30)), "assignedRoles": refs,
		})
	}

	var invitations []any
	var pending map[string]struct {
		Tag   string   `json:"tag"`
		Roles []string `json:"roles"`
	}
	simulate.Extra(r.Workspace.Extra, "invitations", &pending)
	for key, inv := range pending {
		refs := []any{}
		for _, name := range inv.Roles {
			refs = append(refs, simRoleRef(r, name))
		}
		invitations = append(invitations, map[string]any{
			"id": simulate.UUID("invitation", key), "email": "kit+" + inv.Tag + "@example.com", "role": "developer",
			"createdAt": simTime(now.AddDate(0, 0, -1)), "expireAt": simTime(now.AddDate(0, 0, 6)), "assignedRoles": refs,
		})
	}

	var keys []any
	for _, m := range r.Workspace.Credentials {
		var name string
		simulate.Extra(m.Extra, "name", &name)
		id := simulate.UUID("key", m.Key)
		state := "enabled"
		if !m.Active {
			state = "disabled"
		}
		refs := []any{}
		if m.Permissions != "no_roles" {
			refs = append(refs, simRoleRef(r, m.Permissions))
			actors[m.Permissions] = append(actors[m.Permissions], "apiKey/"+id)
		}
		sources := []any{}
		for _, s := range m.AllowedSources {
			sources = append(sources, map[string]any{"source": s, "description": s})
		}
		created := 30
		if m.CreatedDaysAgo != nil {
			created = *m.CreatedDaysAgo
		}
		key := map[string]any{
			"id": id, "name": cmpOr(name, m.Key), "state": state, "roles": []any{}, "keySuffix": "XXXX",
			"createdAt": simTime(now.AddDate(0, 0, -created)), "assignedRoles": refs, "ipAccessList": sources,
		}
		if m.ExpiresInDays != nil {
			key["expireAt"] = simTime(now.AddDate(0, 0, *m.ExpiresInDays))
		}
		if m.LastUsedDaysAgo != nil {
			key["usedAt"] = simTime(now.AddDate(0, 0, -*m.LastUsedDaysAgo))
		}
		keys = append(keys, key)
	}

	var roles []any
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range actors {
			if !yield(name) {
				return
			}
		}
	}) {
		roles = append(roles, simRole(r, name, actors[name]))
	}

	org := map[string]any{
		"id": kitOrgID, "name": r.Workspace.Name, "createdAt": simTime(now.AddDate(0, 0, -30)), "privateEndpoints": []any{}, "enableCoreDumps": true,
		"capabilities": map[string]any{"snapshots": false},
	}
	out := []collectortest.Response{
		{Operation: clickhouse.OpGetOrganization, URL: kitAPI, Body: apiBody(simulate.JSON(org))},
		{Operation: clickhouse.OpListMembers, URL: kitAPI + "/members", Body: apiBody(simulate.JSON(simNonNil(members)))},
		{Operation: clickhouse.OpListInvitations, URL: kitAPI + "/invitations", Body: apiBody(simulate.JSON(simNonNil(invitations)))},
		{Operation: clickhouse.OpListKeys, URL: kitAPI + "/keys?", Body: fmt.Sprintf(`{"status": 200, "requestId": %q, "limit": 250, "totalCount": %d, "nextCursor": null, "result": %s}`,
			simulate.UUID("request", "keys"), len(keys), simulate.JSON(simNonNil(keys)))},
		{Operation: clickhouse.OpListRoles, URL: kitAPI + "/roles", Body: apiBody(simulate.JSON(simNonNil(roles)))},
	}
	for _, op := range []string{
		clickhouse.OpGetVersion, clickhouse.OpListUsers, clickhouse.OpListDatabaseRoles, clickhouse.OpListRoleGrants, clickhouse.OpListGrants,
		clickhouse.OpListSettingsProfiles, clickhouse.OpListSettingsProfileElements, clickhouse.OpListQuotas, clickhouse.OpListQuotaLimits, clickhouse.OpListRowPolicies,
	} {
		out = append(out, sql(op, simulate.JSON(rec.Body(op))))
	}
	return out
}

func simNonNil(items []any) []any {
	if items == nil {
		return []any{}
	}
	return items
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// simConfig reads the organization and its one service at the audit level,
// as the sandbox does.
func simConfig() map[string]any {
	config := kitConfig()
	config["level"] = "audit"
	return config
}

// simHarness runs the collector against the simulated organization and
// checks each answer's shape against the sandbox's recording.
func simHarness(t testing.TB, standing simulate.Differences) simulate.Harness {
	rec, err := simulate.LoadRecorded("testdata/recordings/clickhouse.json")
	if err != nil {
		t.Fatal(err)
	}
	return simulate.Harness{
		Simulate: func(r *roster.Roster, _ int) []collectortest.Response { return newClickHouseSim(r, kitNow, rec) },
		Collect: func(t *testing.T, responses []collectortest.Response) componentsdk.InProcessResult {
			return simulate.InProcess(t, Spec("test", "simulator"), Run, componentsdk.InProcessOptions{
				Config: simConfig(), Secrets: kitSecrets(), Clock: func() time.Time { return kitNow },
			}, responses)
		},
		Artifacts:  []simulate.Artifact{{Schema: roster.AccessPosture, Path: accessPath}},
		Standing:   standing,
		Recorded:   rec,
		Unrecorded: simUnrecorded,
		Coverage:   true,
		Uncompared: simUncompared,
	}
}
