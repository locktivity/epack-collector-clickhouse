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

// adminRole is the system role with every permission in the organization.
const adminRole = "Admin"

// anyAddress is the IP access list entry that admits every IPv4 address.
const anyAddress = "0.0.0.0/0"

// readMembers lists the organization's members. Their rows, sorted by
// email, appear from the audit level.
func readMembers(ctx componentsdk.CollectorContext, cloud *clickhouse.Cloud, gaps gapLog) *Members {
	members, err := cloud.ListMembers(ctx.Context())
	if err != nil {
		warning := manageWarning(err, "members")
		if errors.Is(err, clickhouse.ErrMembersHidden) {
			warning = componentsdk.Warning(membersHiddenWarning)
		}
		gaps.notCollected(err, "/members", componentsdk.MissingPermission(clickhouse.PermissionManageOrganization), warning)
		return nil
	}
	rows := make([]Member, len(members))
	out := &Members{TotalCount: len(members)}
	for i, m := range members {
		roles := roleRefs(m.AssignedRoles)
		rows[i] = Member{Email: strings.ToLower(m.Email), Roles: roles, Admin: holdsAdmin(roles), JoinedAt: timestamp(m.JoinedAt)}
		if rows[i].Admin {
			out.AdminCount++
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Email < rows[j].Email })
	gaps.noAPI("/members/mfa_enabled_count", "ClickHouse Cloud has no API that reports whether a member signs in with MFA.")
	if atAudit(ctx) {
		out.Inventory = rows
	}
	return out
}

// readInvitations lists the invitations that have not been accepted. One
// whose expiry has passed at now counts as expired, the rest as pending.
func readInvitations(ctx componentsdk.CollectorContext, cloud *clickhouse.Cloud, gaps gapLog, now time.Time) *Invitations {
	invitations, err := cloud.ListInvitations(ctx.Context())
	if err != nil {
		gaps.notCollected(err, "/invitations", componentsdk.MissingPermission(clickhouse.PermissionViewOrganization))
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
// appear from the audit level.
func readAPIKeys(ctx componentsdk.CollectorContext, cloud *clickhouse.Cloud, gaps gapLog) *APIKeys {
	keys, err := cloud.ListKeys(ctx.Context())
	if err != nil {
		gaps.notCollected(err, "/api_keys", componentsdk.MissingPermission(clickhouse.PermissionViewAPIKeys),
			componentsdk.Warning("Give the API key's role "+clickhouse.PermissionViewAPIKeys+" to list API keys."))
		return nil
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
		row.NeverUsed = row.LastUsedAt == nil
		out.Inventory[i] = row
		out.EnabledCount += count(row.State == "enabled")
		out.AdminCount += count(row.Admin)
		out.NeverExpiresCount += count(row.NeverExpires)
		out.AnyAddressCount += count(row.AnyAddress)
		out.NeverUsedCount += count(row.NeverUsed)
	}
	sort.SliceStable(out.Inventory, func(i, j int) bool { return out.Inventory[i].Name < out.Inventory[j].Name })
	if !atAudit(ctx) {
		out.Inventory = nil
	}
	return out
}

// readConsoleRoles lists the console roles and what they grant. The Cloud
// API serves them only to a key with control-plane:organization:manage,
// which can also change the organization, so a read-only key is refused and
// the roles are left out with a gap.
func readConsoleRoles(ctx componentsdk.CollectorContext, cloud *clickhouse.Cloud, gaps gapLog) *ConsoleRoles {
	roles, err := cloud.ListRoles(ctx.Context())
	if err != nil {
		gaps.notCollected(err, "/console_roles", componentsdk.MissingPermission(clickhouse.PermissionManageOrganization), manageWarning(err, "console role definitions"))
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
			row.Policies[j] = ConsolePolicy{AllowDeny: p.AllowDeny, Permissions: nonNil(p.Permissions), Resources: nonNil(p.Resources)}
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
func manageWarning(err error, what string) componentsdk.GapOption {
	if componentsdk.Classify(err) != componentsdk.CodePermissionDenied {
		return componentsdk.GapOption{}
	}
	return componentsdk.Warning(fmt.Sprintf("Reading %s needs %s, which can also change the organization.", what, clickhouse.PermissionManageOrganization))
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
		if r.Type == "system" && r.Name == adminRole {
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
