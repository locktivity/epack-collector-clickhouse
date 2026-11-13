package collector

import (
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest/simulate"
)

// The simulated organizations are rosters the simulator answers for, each
// with the values roster.Derive computes from it. A value the collector
// reports otherwise is listed with a verdict and a note that says where in
// the collector's code it was checked, so a new difference fails, and so
// does a listed one that goes away.

// simStanding are the differences every organization shows. The collector
// leaves out what the Cloud API has no field for, and the members' activity,
// which it doesn't read (accessLeftOut in access.go).
var simStanding = simulate.Same(simulate.Gap, "accessLeftOut in access.go: the Cloud API has no field for it, so the collector leaves it out with an unsupported gap.",
	"/sign_in/sso_configured", "/sign_in/sso_required", "/sign_in/mfa_required", "/sign_in/scim_enabled",
	"/members/external_members_present", "/members/external_member_count",
	"/members/sso_member_count", "/members/sso_coverage_pct", "/members/local_members_present", "/members/local_member_count",
	"/members/local_mfa_member_count", "/members/local_mfa_coverage_pct",
	"/admins/local_admins_present", "/admins/local_admin_count", "/admins/local_mfa_admin_count", "/admins/local_admin_mfa_coverage_pct",
	"/root/root_account_count", "/root/root_accounts_present", "/root/root_mfa_account_count", "/root/root_mfa_coverage_pct", "/root/root_access_keys_present",
	"/connected_apps/app_count", "/connected_apps/apps_present",
).With(simulate.Same(simulate.Gap, "accessLeftOut in access.go: member sign-ins are user_login events in the activities list, which the collector doesn't read, so it leaves these out with a not_read gap.",
	"/members/inactive_member_count", "/members/inactive_pct"))

var simUncompared = map[string]string{
	"/credentials/rotation_overdue_credential_count": simKeyAge,
	"/credentials/rotation_overdue_pct":              simKeyAge,
}

// simKeyAge says why the sandbox roster gives no rotation values.
const simKeyAge = "The sandbox roster leaves out when each API key was made, since the keys age each day, so Derive gives no rotation values for it. The matrix's keys give it."

var simUnrecorded = map[string]string{}

func simScenarios(t testing.TB) []simulate.Scenario {
	return []simulate.Scenario{{Name: "sandbox", Roster: simBase(t)}}
}

func TestSimulatedOrganizations(t *testing.T) {
	simHarness(t, simStanding).Tenants(t, simScenarios(t))
}
