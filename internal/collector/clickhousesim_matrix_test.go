package collector

import (
	"slices"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/roster"
	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated matrix varies the sandbox's auditor and the auditor's API
// key along the axes below. Each one-at-a-time row changes one setting, so a
// difference it shows belongs to that setting and is listed in
// simMatrixAlone. The pairwise rows put every two settings together at
// least once, and a difference none of a row's settings shows alone must be
// listed in simMatrixTogether.

// simMatrixBase is the sandbox with every key made 30 days ago, so the
// rotation values are derived too.
func simMatrixBase(t testing.TB) *roster.Roster {
	t.Helper()
	r := simBase(t)
	for i := range r.Workspace.Credentials {
		r.Workspace.Credentials[i].CreatedDaysAgo = new(30)
	}
	r.Terms.Roles["org-manager"] = roster.RoleAdmin
	r.Terms.WorkspaceCredentialPermissions["org-manager"] = roster.PermissionsWrite
	return r
}

func onAuditorKey(change func(*roster.MachineCredential)) func(*roster.Roster) {
	return func(r *roster.Roster) {
		i := slices.IndexFunc(r.Workspace.Credentials, func(m roster.MachineCredential) bool { return m.Key == "auditor" })
		change(&r.Workspace.Credentials[i])
	}
}

func onAuditor(change func(*roster.Account)) func(*roster.Roster) {
	return simulate.OnAccount("auditor", change)
}

func simMatrixAxes() []roster.Axis {
	return []roster.Axis{
		{Name: "member_role", Values: []roster.Value{
			{Name: "custom_viewer"},
			{Name: "admin", Change: onAuditor(func(a *roster.Account) { a.Roles = []string{"Admin"} })},
			{Name: "custom_manager", Change: onAuditor(func(a *roster.Account) { a.Roles = []string{"Member", "org-manager"} })},
			{Name: "billing", Change: onAuditor(func(a *roster.Account) { a.Roles = []string{"Billing"} })},
		}},
		{Name: "key_role", Values: []roster.Value{
			{Name: "custom_viewer"},
			{Name: "admin", Change: onAuditorKey(func(m *roster.MachineCredential) { m.Permissions = "Admin" })},
			{Name: "custom_manager", Change: onAuditorKey(func(m *roster.MachineCredential) { m.Permissions = "org-manager" })},
			{Name: "none", Change: onAuditorKey(func(m *roster.MachineCredential) { m.Permissions = "no_roles" })},
		}},
		{Name: "key_network", Values: []roster.Value{
			{Name: "anywhere"},
			{Name: "limited", Change: onAuditorKey(func(m *roster.MachineCredential) { m.AllowedSources = []string{"203.0.113.0/24"} })},
		}},
		{Name: "key_expiry", Values: []roster.Value{
			{Name: "never"},
			{Name: "in_30_days", Change: onAuditorKey(func(m *roster.MachineCredential) { m.ExpiresInDays = new(30) })},
			{Name: "disabled", Change: onAuditorKey(func(m *roster.MachineCredential) { m.Active = false })},
		}},
		{Name: "key_use", Values: []roster.Value{
			{Name: "never"},
			{Name: "yesterday", Change: onAuditorKey(func(m *roster.MachineCredential) { m.LastUsedDaysAgo = new(1) })},
			{Name: "100_days_ago", Change: onAuditorKey(func(m *roster.MachineCredential) { m.LastUsedDaysAgo = new(100) })},
		}},
		{Name: "key_age", Values: []roster.Value{
			{Name: "30_days"},
			{Name: "100_days", Change: onAuditorKey(func(m *roster.MachineCredential) { m.CreatedDaysAgo = new(100) })},
		}},
	}
}

// simMatrixAlone lists, by axis=value, the differences a setting shows on
// its own.
var simMatrixAlone = map[string]simulate.Differences{}

func TestSimulatedMatrix(t *testing.T) {
	simHarness(t, simStanding).Matrix(t, simMatrixBase(t), simMatrixAxes(), simMatrixAlone, nil)
}
