package collector

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

// membersHiddenWarning explains an empty member list, which looks like a bug
// in ClickHouse Cloud.
var membersHiddenWarning = "ClickHouse Cloud's API reference says " + clickhouse.PermissionViewOrganization +
	" is enough to list members (" + clickhouse.MembersDocs + "). In practice the API returns an empty list unless the key's role also has " +
	clickhouse.PermissionManageOrganization + ", which can also change the organization. This looks like a bug in ClickHouse Cloud."

// anyAddress is the IP access list entry that admits every IPv4 address.
const anyAddress = "0.0.0.0/0"

// readMembers lists the organization's members. Their rows, sorted by
// email, appear in the artifact from the audit level. It also returns every
// row at every level, for the access-posture file, or nil when the list
// could not be read.
func readMembers(ctx componentsdk.CollectorContext, cloud *clickhouse.Cloud, gaps gapLog) (*Members, []Member) {
	members, err := cloud.ListMembers(ctx.Context())
	if err != nil {
		warning := manageWarning(err, "members")
		if errors.Is(err, clickhouse.ErrMembersHidden) {
			warning = componentsdk.Warning(membersHiddenWarning)
		}
		gaps.notCollected(err, "/members", hiddenListPermission(err, clickhouse.ErrMembersHidden), warning)
		return nil, nil
	}
	rows := make([]Member, len(members))
	out := &Members{TotalCount: len(members)}
	for i, m := range members {
		roles := roleRefs(m.AssignedRoles)
		rows[i] = Member{Email: strings.ToLower(m.Email), Roles: roles, Admin: holdsAdmin(roles), JoinedAt: timestamp(m.JoinedAt)}
		for _, r := range m.AssignedRoles {
			rows[i].roleIDs = append(rows[i].roleIDs, r.RoleID)
		}
		if rows[i].Admin {
			out.AdminCount++
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Email < rows[j].Email })
	gaps.noAPI("/members/mfa_enabled_count", "ClickHouse Cloud has no API that reports whether a member signs in with MFA.")
	if atAudit(ctx) {
		out.Inventory = rows
	}
	return out, rows
}

// readInvitations lists the invitations that have not been accepted. One
// whose expiry has passed at now counts as expired, the rest as pending.
func readInvitations(ctx componentsdk.CollectorContext, cloud *clickhouse.Cloud, gaps gapLog, now time.Time) *Invitations {
	invitations, err := cloud.ListInvitations(ctx.Context())
	if err != nil {
		gaps.notCollected(err, "/invitations")
		return nil
	}
	rows := make([]Invitation, len(invitations))
	out := &Invitations{TotalCount: len(invitations)}
	for i, inv := range invitations {
		expiresAt := *timestamp(inv.ExpireAt)
		rows[i] = Invitation{
			Email:     strings.ToLower(inv.Email),
			Roles:     roleRefs(inv.AssignedRoles),
			CreatedAt: timestamp(inv.CreatedAt),
			ExpiresAt: expiresAt,
			Expired:   passed(expiresAt, now),
		}
		if rows[i].Expired {
			out.ExpiredCount++
		} else {
			out.PendingCount++
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Email < rows[j].Email })
	if atAudit(ctx) {
		out.Inventory = rows
	}
	return out
}

// readAPIKeys lists the organization's API keys. Their rows, sorted by name,
// appear in the artifact from the audit level. It also returns every row at
// every level, for the access-posture file, or nil when the list could not
// be read.
func readAPIKeys(ctx componentsdk.CollectorContext, cloud *clickhouse.Cloud, gaps gapLog) (*APIKeys, []APIKey) {
	keys, err := cloud.ListKeys(ctx.Context())
	if err != nil {
		var warning componentsdk.AdviceOption
		if componentsdk.Classify(err) == componentsdk.CodePermissionDenied {
			warning = componentsdk.Warning("Give the API key's role " + clickhouse.PermissionViewAPIKeys + " to list API keys.")
		}
		gaps.notCollected(err, "/api_keys", warning)
		return nil, nil
	}
	out := &APIKeys{TotalCount: len(keys), Inventory: make([]APIKey, len(keys))}
	for i, k := range keys {
		roles := roleRefs(k.AssignedRoles)
		row := APIKey{
			Name:         k.Name,
			State:        k.State,
			Roles:        roles,
			Admin:        holdsAdmin(roles),
			CreatedAt:    timestamp(k.CreatedAt),
			IPAccessList: make([]string, len(k.IPAccessList)),
		}
		if k.ExpireAt != nil {
			row.ExpiresAt = timestamp(*k.ExpireAt)
		}
		row.NeverExpires = row.ExpiresAt == nil
		for j, entry := range k.IPAccessList {
			row.IPAccessList[j] = entry.Source
			if entry.Source == anyAddress {
				row.AnyAddress = true
			}
		}
		if k.UsedAt != nil {
			row.LastUsedAt = timestamp(*k.UsedAt)
		}
		for _, r := range k.AssignedRoles {
			row.roleIDs = append(row.roleIDs, r.RoleID)
		}
		row.NeverUsed = row.LastUsedAt == nil
		out.Inventory[i] = row
		out.EnabledCount += count(row.State == "enabled")
		out.AdminCount += count(row.Admin)
		out.NeverExpiresCount += count(row.NeverExpires)
		out.AnyAddressCount += count(row.AnyAddress)
		out.NeverUsedCount += count(row.NeverUsed)
	}
	sort.SliceStable(out.Inventory, func(i, j int) bool { return out.Inventory[i].Name < out.Inventory[j].Name })
	rows := out.Inventory
	if !atAudit(ctx) {
		out.Inventory = nil
	}
	return out, rows
}

// consoleRoles writes the console roles, listed with err, and what they
// grant. The Cloud API serves them only to a key with
// control-plane:organization:manage, which can also change the
// organization, so a read-only key is refused and the roles are left out
// with a gap.
func consoleRoles(ctx componentsdk.CollectorContext, roles []clickhouse.Role, err error, gaps gapLog) *ConsoleRoles {
	if err != nil {
		gaps.notCollected(err, "/console_roles", hiddenListPermission(err, clickhouse.ErrRolesHidden), manageWarning(err, "console role definitions"))
		return nil
	}
	out := &ConsoleRoles{TotalCount: len(roles), Inventory: make([]ConsoleRole, len(roles))}
	for i, r := range roles {
		row := ConsoleRole{Name: r.Name, Type: r.Type, Policies: make([]ConsolePolicy, len(r.Policies))}
		for _, actor := range r.Actors {
			switch {
			case strings.HasPrefix(actor, "user/"):
				row.MemberCount++
			case strings.HasPrefix(actor, "apiKey/"):
				row.APIKeyCount++
			}
		}
		for j, p := range r.Policies {
			row.Policies[j] = ConsolePolicy{
				AllowDeny:   p.AllowDeny,
				Permissions: nonNil(p.Permissions),
				Resources:   nonNil(p.Resources),
				Tags:        ConsolePolicyTags{RoleV2: p.Tags.RoleV2, Grants: p.Tags.Grants},
			}
		}
		out.Inventory[i] = row
		out.CustomCount += count(r.Type == "custom")
	}
	sort.SliceStable(out.Inventory, func(i, j int) bool { return out.Inventory[i].Name < out.Inventory[j].Name })
	if !atAudit(ctx) {
		out.Inventory = nil
	}
	return out
}

// manageWarning tells the operator that reading what names needs
// control-plane:organization:manage when err is a permission_denied
// failure, and adds nothing otherwise.
func manageWarning(err error, what string) componentsdk.AdviceOption {
	if componentsdk.Classify(err) != componentsdk.CodePermissionDenied {
		return componentsdk.AdviceOption{}
	}
	return componentsdk.Warning(fmt.Sprintf("Reading %s needs %s, which can also change the organization.", what, clickhouse.PermissionManageOrganization))
}

// hiddenListPermission names control-plane:organization:manage on the gap
// when err is hidden. hidden is the error for a list the API answered empty
// with status 200, which a key without that permission gets. A gap takes
// its operation's permission only from a refused call, so this one needs it
// named here.
func hiddenListPermission(err, hidden error) componentsdk.AdviceOption {
	if !errors.Is(err, hidden) {
		return componentsdk.AdviceOption{}
	}
	return componentsdk.MissingPermission(clickhouse.PermissionManageOrganization)
}

func roleRefs(assigned []clickhouse.AssignedRole) []RoleRef {
	refs := make([]RoleRef, len(assigned))
	for i, r := range assigned {
		refs[i] = RoleRef{Name: r.RoleName, Type: r.RoleType}
	}
	sort.SliceStable(refs, func(i, j int) bool { return refs[i].Name < refs[j].Name })
	return refs
}

func holdsAdmin(roles []RoleRef) bool {
	for _, r := range roles {
		if r.Type == "system" && r.Name == clickhouse.AdminRole {
			return true
		}
	}
	return false
}

// passed reports whether the RFC 3339 time at has passed at now. A time it
// cannot read counts as not passed.
func passed(at string, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, at)
	return err == nil && !t.After(now)
}

func atAudit(ctx componentsdk.CollectorContext) bool {
	return ctx.Level().AtLeast(componentsdk.LevelAudit)
}

func count(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}
