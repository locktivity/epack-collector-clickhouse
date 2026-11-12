package collector

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

func TestAccessPathIsTheSDKPath(t *testing.T) {
	if got := componentsdk.ArtifactPath("clickhouse", accessSchema); got != accessPath {
		t.Errorf("accessPath is %s, want %s", accessPath, got)
	}
	if got := componentsdk.ArtifactPath("clickhouse", ""); got != artifactPath {
		t.Errorf("artifactPath is %s, want %s", artifactPath, got)
	}
}

// accessJSON returns the access-posture file as the run writes it.
func accessJSON(t *testing.T, posture *AccessPosture) map[string]any {
	t.Helper()
	raw, err := json.Marshal(posture)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func stringPtr(s string) *string { return &s }

func TestAccessAdminsAreAdminRoleMembers(t *testing.T) {
	members := []Member{{Email: "a@example.com", Admin: true}, {Email: "b@example.com"}, {Email: "c@example.com"}}
	m, a := accessMembers(gapLog{rec: &componentsdk.Recorder{}}, members, nil, nil, true)
	if !m.MembersPresent || *m.MemberCount != 3 {
		t.Errorf("members %+v, want 3 present", m)
	}
	if !*a.AdminsPresent || *a.AdminCount != 1 || *a.AdminSharePct.Value != 34 {
		t.Errorf("admins %+v, want 1 admin at 34%%, rounded up", a)
	}

	m, a = accessMembers(gapLog{rec: &componentsdk.Recorder{}}, []Member{{Email: "a@example.com"}}, nil, nil, false)
	if m.MemberCount != nil || a.AdminCount != nil {
		t.Errorf("counts below audit: members %+v, admins %+v", m, a)
	}
	if *a.AdminsPresent || *a.AdminSharePct.Value != 0 {
		t.Errorf("admins %+v, want none at 0%%", a)
	}
}

// policyRole is a role with one policy that allows or denies permission on
// resource.
func policyRole(id, allowDeny, permission, resource string) clickhouse.Role {
	return clickhouse.Role{ID: id, Name: id, Type: "custom", Policies: []clickhouse.Policy{
		{AllowDeny: allowDeny, Permissions: []string{permission}, Resources: []string{resource}},
	}}
}

// A member without the system Admin role is an admin when a role they hold
// allows changing who has access to the organization, or changing or
// deleting every service. Viewing, billing, or managing one service is not
// enough, and a DENY policy takes an allowed permission away.
func TestAccessAdminsFromRolePolicies(t *testing.T) {
	roles := []clickhouse.Role{
		policyRole("r-org-manage", "ALLOW", "control-plane:organization:manage", "organization/8c1f2a4e"),
		policyRole("r-service-delete", "ALLOW", "control-plane:service:delete", "instance/*"),
		policyRole("r-postgres-manage", "ALLOW", "control-plane:postgres-service:manage", "postgres/*"),
		policyRole("r-one-service", "ALLOW", "control-plane:service:manage", "instance/0b9e"),
		policyRole("r-view", "ALLOW", "control-plane:service:view", "instance/*"),
		policyRole("r-billing", "ALLOW", "control-plane:organization:manage-billing", "organization/8c1f2a4e"),
		policyRole("r-deny-delete", "DENY", "control-plane:service:delete", "instance/*"),
	}
	cases := map[string]struct {
		roleIDs []string
		admin   bool
	}{
		"organization manage":        {[]string{"r-org-manage"}, true},
		"delete every service":       {[]string{"r-service-delete"}, true},
		"manage every Postgres":      {[]string{"r-postgres-manage"}, true},
		"manage one service":         {[]string{"r-one-service"}, false},
		"view every service":         {[]string{"r-view"}, false},
		"billing":                    {[]string{"r-billing"}, false},
		"delete denied by a role":    {[]string{"r-service-delete", "r-deny-delete"}, false},
		"a role the list leaves out": {[]string{"r-unknown"}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := &componentsdk.Recorder{}
			_, a := accessMembers(gapLog{rec: rec}, []Member{{Email: "a@example.com", roleIDs: tc.roleIDs}}, roles, nil, true)
			if want := count(tc.admin); *a.AdminCount != want || *a.AdminsPresent != tc.admin {
				t.Errorf("admins %+v, want admin %t", a, tc.admin)
			}
			if gaps := rec.Gaps(); len(gaps) != 0 {
				t.Errorf("gaps %+v, want none", gaps)
			}
		})
	}
}

// When the roles can't be read, whether a member without the system Admin
// role is an admin is unknown. The admin count and share are left out with
// a partial gap, and a member with the system Admin role still makes
// admins_present true.
func TestAccessAdminsWithoutRoles(t *testing.T) {
	refused := componentsdk.CodeError(componentsdk.CodePermissionDenied, clickhouse.ErrRolesHidden)
	members := []Member{{Email: "a@example.com", Admin: true}, {Email: "b@example.com"}, {Email: "c@example.com"}}
	rec := &componentsdk.Recorder{}
	_, a := accessMembers(gapLog{rec: rec}, members, nil, refused, true)
	if a.AdminsPresent == nil || !*a.AdminsPresent || a.AdminCount != nil || a.AdminSharePct.Read {
		t.Errorf("admins %+v, want admins_present alone", a)
	}
	gaps := rec.Gaps()
	pointers := []string{}
	for _, g := range gaps {
		pointers = append(pointers, g.Pointer)
		if g.Status != componentsdk.GapPartial || g.Unmeasured != 2 || g.Code != componentsdk.CodePermissionDenied {
			t.Errorf("gap %+v, want partial permission_denied with 2 unmeasured", g)
		}
	}
	slices.Sort(pointers)
	if want := []string{"/admins/admin_count", "/admins/admin_share_pct"}; !slices.Equal(pointers, want) {
		t.Errorf("gaps on %v, want %v", pointers, want)
	}
}

func TestAccessCredentialsCountUsableKeys(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	keys := []APIKey{
		// Never expires, used long ago, open to any address, Admin, old.
		{Name: "old-admin", State: "enabled", Admin: true, NeverExpires: true, AnyAddress: true,
			CreatedAt: stringPtr("2026-01-05T09:00:00Z"), LastUsedAt: stringPtr("2026-06-01T08:00:00Z")},
		// Expires later, used recently, limited to an address range, new.
		{Name: "recent", State: "enabled", ExpiresAt: stringPtr("2027-01-01T00:00:00Z"),
			CreatedAt: stringPtr("2026-10-01T09:00:00Z"), LastUsedAt: stringPtr("2026-10-20T08:00:00Z")},
		// Never used, created just inside 90 days.
		{Name: "unused-new", State: "enabled", ExpiresAt: stringPtr("2026-12-01T00:00:00Z"), NeverUsed: true,
			CreatedAt: stringPtr("2026-07-25T09:00:00Z")},
		// An expired key that is still enabled, and a disabled key. Neither
		// can be used.
		{Name: "expired", State: "enabled", Admin: true, AnyAddress: true, ExpiresAt: stringPtr("2026-10-01T00:00:00Z"),
			CreatedAt: stringPtr("2026-01-05T09:00:00Z")},
		{Name: "disabled", State: "disabled", Admin: true, NeverExpires: true, AnyAddress: true, NeverUsed: true,
			CreatedAt: stringPtr("2025-01-05T09:00:00Z")},
	}
	rec := &componentsdk.Recorder{}
	got := accessCredentials(gapLog{rec: rec}, keys, now, true)
	want := map[string]int{
		"credential_count":                  3,
		"never_expiring_credential_count":   1,
		"unused_credential_count":           2,
		"unrestricted_credential_count":     1,
		"write_access_credential_count":     1,
		"rotation_overdue_credential_count": 1,
		"never_expiring_pct":                34,
		"unused_pct":                        67,
		"unrestricted_pct":                  34,
		"write_access_pct":                  34,
		"rotation_overdue_pct":              34,
	}
	doc := accessJSON(t, &AccessPosture{Credentials: got})["credentials"].(map[string]any)
	for field, n := range want {
		if doc[field] != float64(n) {
			t.Errorf("%s is %v, want %d", field, doc[field], n)
		}
	}
	if doc["credentials_present"] != true {
		t.Errorf("credentials_present is %v, want true", doc["credentials_present"])
	}
	if gaps := rec.Gaps(); len(gaps) != 0 {
		t.Errorf("gaps %+v, want none", gaps)
	}
}

func TestAccessCredentialsUnrestrictedNeedsAdminFromAnyAddress(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	created := stringPtr("2026-10-01T09:00:00Z")
	keys := []APIKey{
		{Name: "admin-anywhere", State: "enabled", Admin: true, AnyAddress: true, NeverExpires: true, NeverUsed: true, CreatedAt: created},
		// Open to any address, with a role short of Admin.
		{Name: "reader-anywhere", State: "enabled", AnyAddress: true, NeverExpires: true, NeverUsed: true, CreatedAt: created},
		// Admin, limited to an address range.
		{Name: "admin-office", State: "enabled", Admin: true, NeverExpires: true, NeverUsed: true, CreatedAt: created},
		{Name: "reader-office", State: "enabled", NeverExpires: true, NeverUsed: true, CreatedAt: created},
	}
	got := accessCredentials(gapLog{rec: &componentsdk.Recorder{}}, keys, now, true)
	if *got.UnrestrictedCredentialCount != 1 || *got.UnrestrictedPct.Value != 25 {
		t.Errorf("unrestricted %d at %d%%, want 1 at 25%%", *got.UnrestrictedCredentialCount, *got.UnrestrictedPct.Value)
	}
	if *got.WriteAccessCredentialCount != 2 {
		t.Errorf("write_access_credential_count is %d, want 2", *got.WriteAccessCredentialCount)
	}
}

func TestAccessCredentialsNoUsableKeys(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for name, keys := range map[string][]APIKey{
		"no keys":       {},
		"disabled only": {{Name: "off", State: "disabled", NeverExpires: true, CreatedAt: stringPtr("2026-10-01T00:00:00Z")}},
	} {
		t.Run(name, func(t *testing.T) {
			doc := accessJSON(t, &AccessPosture{Credentials: accessCredentials(gapLog{rec: &componentsdk.Recorder{}}, keys, now, true)})
			creds := doc["credentials"].(map[string]any)
			if creds["credentials_present"] != false || creds["credential_count"] != float64(0) {
				t.Errorf("credentials %v, want none present and a count of 0", creds)
			}
			for _, field := range []string{"never_expiring_pct", "unused_pct", "unrestricted_pct", "write_access_pct", "rotation_overdue_pct"} {
				if v, ok := creds[field]; !ok || v != nil {
					t.Errorf("%s is %v (written %v), want null", field, v, ok)
				}
			}
		})
	}
}

func TestAccessCredentialsBelowAuditHaveNoCounts(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	keys := []APIKey{{Name: "k", State: "enabled", NeverExpires: true, NeverUsed: true, CreatedAt: stringPtr("2026-10-01T00:00:00Z")}}
	doc := accessJSON(t, &AccessPosture{Credentials: accessCredentials(gapLog{rec: &componentsdk.Recorder{}}, keys, now, false)})
	creds := doc["credentials"].(map[string]any)
	for field := range creds {
		if len(field) > 6 && field[len(field)-6:] == "_count" {
			t.Errorf("%s is written below the audit level", field)
		}
	}
	if creds["never_expiring_pct"] != float64(100) || creds["unused_pct"] != float64(100) {
		t.Errorf("credentials %v, want never_expiring_pct and unused_pct of 100", creds)
	}
}

func TestAccessCredentialsUnreadableTimes(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	keys := []APIKey{
		{Name: "no-created", State: "enabled", LastUsedAt: stringPtr("not a time")},
		{Name: "ok", State: "enabled", NeverUsed: true, CreatedAt: stringPtr("2026-10-01T00:00:00Z")},
	}
	rec := &componentsdk.Recorder{}
	doc := accessJSON(t, &AccessPosture{Credentials: accessCredentials(gapLog{rec: rec}, keys, now, true)})
	creds := doc["credentials"].(map[string]any)
	for _, field := range []string{"unused_credential_count", "unused_pct", "rotation_overdue_credential_count", "rotation_overdue_pct"} {
		if v, ok := creds[field]; ok {
			t.Errorf("%s is %v, want it left out", field, v)
		}
	}
	if creds["credential_count"] != float64(2) {
		t.Errorf("credential_count is %v, want 2", creds["credential_count"])
	}
	var pointers []string
	for _, g := range rec.Gaps() {
		if g.Status != componentsdk.GapPartial || g.Code != componentsdk.CodeInvalidResponse || g.Unmeasured != 1 {
			t.Errorf("gap %+v, want a partial invalid_response gap with 1 unmeasured", g)
		}
		pointers = append(pointers, g.Pointer)
	}
	slices.Sort(pointers)
	want := []string{
		"/credentials/rotation_overdue_credential_count", "/credentials/rotation_overdue_pct",
		"/credentials/unused_credential_count", "/credentials/unused_pct",
	}
	if !slices.Equal(pointers, want) {
		t.Errorf("gaps at %v, want %v", pointers, want)
	}
}

func TestAccessPostureValuesLeftOut(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	members := []Member{{Email: "a@example.com", Admin: true}}
	for _, level := range []componentsdk.Level{componentsdk.LevelTrust, componentsdk.LevelAudit} {
		rec := &componentsdk.Recorder{}
		doc := accessJSON(t, accessPosture(gapLog{rec: rec}, level, now, members, nil, nil, []APIKey{}))
		for _, section := range []string{"sign_in", "root", "connected_apps", "scopes"} {
			if _, ok := doc[section]; ok {
				t.Errorf("%s: %s is written", level, section)
			}
		}
		gaps := map[string]componentsdk.Gap{}
		for _, g := range rec.Gaps() {
			gaps[g.Pointer] = g
		}
		// The App access checks read these. ClickHouse Cloud reports none
		// of them.
		for _, pointer := range []string{
			"/sign_in/sso_required", "/sign_in/mfa_required",
			"/admins/local_admins_present", "/admins/local_admin_mfa_coverage_pct",
		} {
			if g, ok := gaps[pointer]; !ok || g.Code != componentsdk.CodeUnsupported || g.Path != accessPath {
				t.Errorf("%s: %s has gap %+v, want unsupported", level, pointer, g)
			}
		}
		// ClickHouse Cloud reports sign-ins in its activities list, which
		// the collector does not read.
		if g := gaps["/members/inactive_pct"]; g.Code != componentsdk.CodeNotRead || g.Owner != componentsdk.OwnerPublisher ||
			!strings.Contains(g.Detail, clickhouse.PermissionViewActivities) {
			t.Errorf("%s: inactive_pct has gap %+v, want not_read naming %s", level, g, clickhouse.PermissionViewActivities)
		}
		g, counted := gaps["/members/inactive_member_count"]
		if counted != level.AtLeast(componentsdk.LevelAudit) || (counted && g.Code != componentsdk.CodeNotRead) {
			t.Errorf("%s: inactive_member_count has gap %+v, recorded %v", level, g, counted)
		}
		if doc["provider"] != "clickhouse" || doc["system_type"] != "database" {
			t.Errorf("%s: provider %v, system_type %v", level, doc["provider"], doc["system_type"])
		}
	}
}

func TestAccessPostureLeavesOutUnreadLists(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	doc := accessJSON(t, accessPosture(gapLog{rec: &componentsdk.Recorder{}}, componentsdk.LevelAudit, now, nil, nil, nil, nil))
	for _, section := range []string{"members", "admins", "credentials"} {
		if _, ok := doc[section]; ok {
			t.Errorf("%s is written although its list was not read", section)
		}
	}
}
