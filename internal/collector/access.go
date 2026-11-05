package collector

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

// The access-posture file's schema ID and path, the one
// componentsdk.ArtifactPath gives. The path is a constant, since epack sdk
// map finds the code behind an artifact only from a constant path.
const (
	accessSchema = "evidencepack/access-posture@v1"
	accessPath   = "artifacts/clickhouse.access-posture.json"
)

// accessSchemaVersion is the version of the access-posture schema the file
// follows.
const accessSchemaVersion = "1.0.0"

// staleAfter is how long ago a key's last use or creation must be for the
// key to count as unused or overdue for rotation.
const staleAfter = 90 * 24 * time.Hour

// AccessPosture is the evidencepack/access-posture@v1 file for the
// organization's console. A section whose list could not be read is left
// out, with the gap of the detailed value it comes from. Values ClickHouse
// Cloud does not report are left out with an unsupported gap. Values it
// reports through a call the collector does not make are left out with a
// not_read gap. The counts are written from the audit level, as the schema
// marks them, and the present flags and percentages at every level.
type AccessPosture struct {
	SchemaVersion string             `json:"schema_version"`
	CollectedAt   string             `json:"collected_at"`
	Provider      string             `json:"provider"`
	SystemType    string             `json:"system_type"`
	Members       *AccessMembers     `json:"members,omitempty"`
	Admins        *AccessAdmins      `json:"admins,omitempty"`
	Credentials   *AccessCredentials `json:"credentials,omitempty"`
}

// AccessMembers holds the console members.
type AccessMembers struct {
	MembersPresent bool `json:"members_present"`
	MemberCount    *int `json:"member_count,omitempty"`
}

// AccessAdmins holds the members who hold the system Admin role.
type AccessAdmins struct {
	AdminsPresent bool `json:"admins_present"`
	AdminCount    *int `json:"admin_count,omitempty"`
	AdminSharePct pct  `json:"admin_share_pct,omitzero"`
}

// AccessCredentials holds the API keys that are enabled and have not
// expired.
type AccessCredentials struct {
	CredentialsPresent             bool `json:"credentials_present"`
	CredentialCount                *int `json:"credential_count,omitempty"`
	NeverExpiringCredentialCount   *int `json:"never_expiring_credential_count,omitempty"`
	NeverExpiringPct               pct  `json:"never_expiring_pct,omitzero"`
	UnusedCredentialCount          *int `json:"unused_credential_count,omitempty"`
	UnusedPct                      pct  `json:"unused_pct,omitzero"`
	UnrestrictedCredentialCount    *int `json:"unrestricted_credential_count,omitempty"`
	UnrestrictedPct                pct  `json:"unrestricted_pct,omitzero"`
	WriteAccessCredentialCount     *int `json:"write_access_credential_count,omitempty"`
	WriteAccessPct                 pct  `json:"write_access_pct,omitzero"`
	RotationOverdueCredentialCount *int `json:"rotation_overdue_credential_count,omitempty"`
	RotationOverduePct             pct  `json:"rotation_overdue_pct,omitzero"`
}

// pct is a percentage in the access-posture file. It is left out when Read
// is false. Otherwise it is written as Value, which is nil over an empty
// population.
type pct struct {
	Value *int
	Read  bool
}

// IsZero reports whether the percentage was not read, for omitzero.
func (p pct) IsZero() bool { return !p.Read }

// MarshalJSON writes the value, or null.
func (p pct) MarshalJSON() ([]byte, error) { return json.Marshal(p.Value) }

func percent(count, total int, rounding componentsdk.Rounding) pct {
	return pct{Value: componentsdk.Percent(count, total, rounding), Read: true}
}

// The details of the access-posture file's gaps. An unsupported detail
// names what ClickHouse Cloud does not report. The not_read detail names the
// call that reports the value.
const (
	noSSOField      = "The Cloud API has no field for SAML SSO."
	noSSORequired   = "The Cloud API has no field for whether members must sign in with SAML SSO."
	noMFARequired   = "The Cloud API has no field for an MFA requirement."
	noSCIMField     = "The Cloud API has no field for SCIM provisioning."
	noExternalField = "The Cloud API's member list has no field that marks a member from outside the organization."
	noSignInMethod  = "The Cloud API's member list has no field for how a member signs in."
	noMemberMFA     = "The Cloud API's member list has no field for how a member signs in or for their MFA."
	noRootAccount   = "A ClickHouse Cloud organization has no built-in root account."
	noConnectedApps = "The Cloud API has no list of third-party apps with access to the organization."

	signInsNotRead = "The Cloud API's activities list reports member sign-ins as user_login events, which this collector does not read. " +
		"Reading it needs " + clickhouse.PermissionViewActivities + "."
)

// accessLeftOut lists the values left out of the access-posture file, with
// the gap code and the reason. The audit ones are audit-level counts, whose
// gaps are recorded only from the audit level.
var accessLeftOut = []struct {
	pointer string
	code    componentsdk.Code
	reason  string
	audit   bool
}{
	{"/sign_in/sso_configured", componentsdk.CodeUnsupported, noSSOField, false},
	{"/sign_in/sso_required", componentsdk.CodeUnsupported, noSSORequired, false},
	{"/sign_in/mfa_required", componentsdk.CodeUnsupported, noMFARequired, false},
	{"/sign_in/scim_enabled", componentsdk.CodeUnsupported, noSCIMField, false},
	{"/members/external_members_present", componentsdk.CodeUnsupported, noExternalField, false},
	{"/members/external_member_count", componentsdk.CodeUnsupported, noExternalField, true},
	{"/members/sso_member_count", componentsdk.CodeUnsupported, noSignInMethod, true},
	{"/members/sso_coverage_pct", componentsdk.CodeUnsupported, noSignInMethod, false},
	{"/members/local_members_present", componentsdk.CodeUnsupported, noSignInMethod, false},
	{"/members/local_member_count", componentsdk.CodeUnsupported, noSignInMethod, true},
	{"/members/local_mfa_member_count", componentsdk.CodeUnsupported, noMemberMFA, true},
	{"/members/local_mfa_coverage_pct", componentsdk.CodeUnsupported, noMemberMFA, false},
	{"/members/inactive_member_count", componentsdk.CodeNotRead, signInsNotRead, true},
	{"/members/inactive_pct", componentsdk.CodeNotRead, signInsNotRead, false},
	{"/admins/local_admins_present", componentsdk.CodeUnsupported, noSignInMethod, false},
	{"/admins/local_admin_count", componentsdk.CodeUnsupported, noSignInMethod, true},
	{"/admins/local_mfa_admin_count", componentsdk.CodeUnsupported, noMemberMFA, true},
	{"/admins/local_admin_mfa_coverage_pct", componentsdk.CodeUnsupported, noMemberMFA, false},
	{"/root", componentsdk.CodeUnsupported, noRootAccount, false},
	{"/connected_apps", componentsdk.CodeUnsupported, noConnectedApps, false},
}

// accessPosture builds the access-posture file from the member and API key
// rows. members is nil when the member list could not be read, and keys is
// nil when the key list could not be read. Each section left out then gets
// the gap of the detailed list it comes from.
func accessPosture(gaps gapLog, level componentsdk.Level, now time.Time, members []Member, keys []APIKey) *AccessPosture {
	audit := level.AtLeast(componentsdk.LevelAudit)
	out := &AccessPosture{
		SchemaVersion: accessSchemaVersion,
		CollectedAt:   now.Format(time.RFC3339),
		Provider:      "clickhouse",
		SystemType:    "database",
	}
	gaps.mirror("/members", "/members")
	gaps.mirror("/members", "/admins")
	gaps.mirror("/api_keys", "/credentials")
	if members != nil {
		out.Members, out.Admins = accessMembers(members, audit)
	}
	if keys != nil {
		out.Credentials = accessCredentials(gaps, keys, now, audit)
	}
	for _, v := range accessLeftOut {
		if v.audit && !audit {
			continue
		}
		gaps.leftOut(v.pointer, v.code, v.reason)
	}
	return out
}

// accessMembers counts the members, and the admins among them, which are
// the members who hold the system Admin role.
func accessMembers(members []Member, audit bool) (*AccessMembers, *AccessAdmins) {
	admins := 0
	for _, m := range members {
		admins += count(m.Admin)
	}
	total := len(members)
	m := &AccessMembers{MembersPresent: total > 0}
	a := &AccessAdmins{AdminsPresent: admins > 0, AdminSharePct: percent(admins, total, componentsdk.RoundUp)}
	if audit {
		m.MemberCount = &total
		a.AdminCount = &admins
	}
	return m, a
}

// accessCredentials counts the API keys that can be used, the enabled keys
// whose expiry has not passed at now. A key last used or created more than
// 90 days before now counts as unused or overdue for rotation. A key is
// unrestricted when it holds the system Admin role and can be used from any
// address. A key with another role, or with an IP access list that leaves
// out some addresses, is restricted. When a key's time cannot be read, that
// count and its percentage are left out with a partial gap.
func accessCredentials(gaps gapLog, keys []APIKey, now time.Time, audit bool) *AccessCredentials {
	cutoff := now.Add(-staleAfter)
	var total, neverExpiring, unused, unrestricted, writeAccess, overdue int
	var unusedUnread, overdueUnread int
	for _, k := range keys {
		if k.State != "enabled" || (k.ExpiresAt != nil && passed(*k.ExpiresAt, now)) {
			continue
		}
		total++
		neverExpiring += count(k.NeverExpires)
		unrestricted += count(k.AnyAddress && k.Admin)
		writeAccess += count(k.Admin)
		if k.LastUsedAt == nil {
			unused++
		} else if before, ok := earlier(*k.LastUsedAt, cutoff); !ok {
			unusedUnread++
		} else {
			unused += count(before)
		}
		if k.CreatedAt == nil {
			overdueUnread++
		} else if before, ok := earlier(*k.CreatedAt, cutoff); !ok {
			overdueUnread++
		} else {
			overdue += count(before)
		}
	}
	out := &AccessCredentials{
		CredentialsPresent: total > 0,
		NeverExpiringPct:   percent(neverExpiring, total, componentsdk.RoundUp),
		UnrestrictedPct:    percent(unrestricted, total, componentsdk.RoundUp),
		WriteAccessPct:     percent(writeAccess, total, componentsdk.RoundUp),
	}
	if audit {
		out.CredentialCount = &total
		out.NeverExpiringCredentialCount = &neverExpiring
		out.UnrestrictedCredentialCount = &unrestricted
		out.WriteAccessCredentialCount = &writeAccess
	}
	if unusedUnread == 0 {
		out.UnusedPct = percent(unused, total, componentsdk.RoundUp)
		if audit {
			out.UnusedCredentialCount = &unused
		}
	} else {
		keyTimeGap(gaps, audit, "/credentials/unused", unusedUnread, "usedAt")
	}
	if overdueUnread == 0 {
		out.RotationOverduePct = percent(overdue, total, componentsdk.RoundUp)
		if audit {
			out.RotationOverdueCredentialCount = &overdue
		}
	} else {
		keyTimeGap(gaps, audit, "/credentials/rotation_overdue", overdueUnread, "createdAt")
	}
	return out
}

// keyTimeGap leaves out the count at prefix+"_credential_count" and the
// percentage at prefix+"_pct", since unread of the keys have no readable
// field.
func keyTimeGap(gaps gapLog, audit bool, prefix string, unread int, field string) {
	gaps.rec.Helper()
	err := componentsdk.CodeError(componentsdk.CodeInvalidResponse,
		fmt.Errorf("%s: %d of the listed keys have no %s, or one that is not an RFC 3339 time", clickhouse.OpListKeys, unread, field))
	if audit {
		gaps.partial(prefix+"_credential_count", unread, err)
	}
	gaps.partial(prefix+"_pct", unread, err)
}

// earlier reports whether the RFC 3339 time at is before cutoff. ok is false
// when at cannot be read.
func earlier(at string, cutoff time.Time) (before, ok bool) {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return false, false
	}
	return t.Before(cutoff), true
}
