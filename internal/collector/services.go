package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

// cloudManagedStorage is where ClickHouse Cloud keeps its own database
// users, apart from the default and sql-console users it also creates.
const cloudManagedStorage = "users_xml"

// cloudManagedRoles are the roles ClickHouse Cloud creates in every service.
// They are stored like the customer's roles, so only their names mark them.
var cloudManagedRoles = []string{"clickpipes_system", "default_role", "sql_console_admin", "sql_console_read_only"}

// noExpiry is how the users query writes a sign-in method that never
// expires: ClickHouse stores it as 0, the Unix epoch.
const noExpiry = "1970-01-01T00:00:00Z"

// serviceParts are the parts of a service read after its first query.
var serviceParts = []string{
	"users", "roles", "role_grants", "grants", "settings_profiles",
	"settings_profile_elements", "quotas", "quota_limits", "row_policies",
}

// readService reads one service's access settings as cfg.User. The first
// query also wakes a service that has gone idle. When it fails, every part
// is left out with its error, since the rest would fail the same way.
func readService(ctx componentsdk.CollectorContext, db *clickhouse.Database, gaps gapLog, index int, cfg ServiceConfig) Service {
	svc := Service{Host: cfg.Host, User: cfg.User}
	base := fmt.Sprintf("/services/%d/", index)

	wakeCtx, cancel := context.WithTimeout(ctx.Context(), wakeBudget)
	version, err := db.Version(wakeCtx)
	cancel()
	if err != nil {
		warning := componentsdk.Warning(reachWarning(err, cfg.User))
		gaps.notCollected(err, base+"version", warning)
		for _, part := range serviceParts {
			gaps.notCollected(err, base+part, warning)
		}
		return svc
	}
	svc.Version = version

	c, audit := ctx.Context(), atAudit(ctx)
	if users, err := db.Users(c); err != nil {
		gaps.notCollected(err, base+"users", grantWarning(err, cfg.User, "SHOW USERS"))
	} else {
		svc.Users = databaseUsers(users, audit)
	}
	if roles, err := db.Roles(c); err != nil {
		gaps.notCollected(err, base+"roles", grantWarning(err, cfg.User, "SHOW ROLES"))
	} else {
		svc.Roles = databaseRoles(roles, audit)
	}
	if grants, err := db.RoleGrants(c); err != nil {
		gaps.notCollected(err, base+"role_grants", grantWarning(err, cfg.User, "SELECT ON system.role_grants"))
	} else {
		svc.RoleGrants = roleGrants(grants, audit)
	}
	if grants, err := db.Grants(c); err != nil {
		gaps.notCollected(err, base+"grants", grantWarning(err, cfg.User, "SELECT ON system.grants"))
	} else {
		svc.Grants = privilegeGrants(grants, audit)
	}
	if profiles, err := db.SettingsProfiles(c); err != nil {
		gaps.notCollected(err, base+"settings_profiles", grantWarning(err, cfg.User, "SHOW SETTINGS PROFILES"))
	} else {
		svc.SettingsProfiles = settingsProfiles(profiles, audit)
	}
	if elements, err := db.SettingsProfileElements(c); err != nil {
		gaps.notCollected(err, base+"settings_profile_elements", grantWarning(err, cfg.User, "SELECT ON system.settings_profile_elements"))
	} else {
		svc.SettingsProfileElements = settingsProfileElements(elements, audit)
	}
	if quotas, err := db.Quotas(c); err != nil {
		gaps.notCollected(err, base+"quotas", grantWarning(err, cfg.User, "SHOW QUOTAS"))
	} else {
		svc.Quotas = quotaList(quotas, audit)
	}
	if limits, err := db.QuotaLimits(c); err != nil {
		gaps.notCollected(err, base+"quota_limits", grantWarning(err, cfg.User, "SELECT ON system.quota_limits"))
	} else {
		svc.QuotaLimits = quotaLimits(limits, audit)
	}
	if policies, err := db.RowPolicies(c); err != nil {
		gaps.notCollected(err, base+"row_policies", grantWarning(err, cfg.User, "SHOW ROW POLICIES"))
	} else {
		svc.RowPolicies = rowPolicies(policies, audit)
	}
	return svc
}

// reachWarning says what to check when a service's first query fails.
func reachWarning(err error, user string) string {
	var dbErr *clickhouse.DatabaseError
	var dnsErr *net.DNSError
	switch code := componentsdk.Classify(err); {
	case code == componentsdk.CodeAuthFailed:
		return fmt.Sprintf("The service rejected the password for %s. Check %s and the user in services.", user, dbPasswordEnv)
	case code == componentsdk.CodePermissionDenied:
		return fmt.Sprintf("The service refused %s. The user's HOST setting must allow this runner's address.", user)
	case code == componentsdk.CodeTimeout:
		return fmt.Sprintf("The service did not answer within %d minutes. A service that has gone idle can take a minute or more to start.", int(wakeBudget.Minutes()))
	case errors.As(err, &dnsErr):
		return "The service's host could not be found. Check the host in services."
	case code == componentsdk.CodeVendorError && !errors.As(err, &dbErr):
		return "The service closed the connection before it answered. ClickHouse Cloud does this when the runner's address is not on the service's IP access list."
	}
	return "The service could not be read."
}

// grantWarning tells the operator which grant user lacks when err is a
// permission_denied failure, and adds nothing otherwise.
func grantWarning(err error, user, grant string) componentsdk.GapOption {
	if componentsdk.Classify(err) != componentsdk.CodePermissionDenied {
		return componentsdk.GapOption{}
	}
	return componentsdk.Warning(fmt.Sprintf("Grant %s to %s. docs/configuration.md lists every grant the collector needs.", grant, user))
}

func databaseUsers(users []clickhouse.User, audit bool) *DatabaseUsers {
	out := &DatabaseUsers{}
	customer, cloud := []DatabaseUser{}, []DatabaseUser{}
	for _, u := range users {
		row := DatabaseUser{
			Name:            u.Name,
			Storage:         u.Storage,
			AuthMethods:     make([]AuthMethod, len(u.AuthTypes)),
			HostIP:          u.HostIP,
			HostNames:       u.HostNames,
			HostNamesRegexp: u.HostNamesRegexp,
			HostNamesLike:   u.HostNamesLike,
			AnyHost:         slices.Contains(u.HostIP, "::/0") || slices.Contains(u.HostIP, anyAddress),
		}
		for i, authType := range u.AuthTypes {
			method := AuthMethod{Type: authType}
			if until := u.ValidUntil[i]; until != noExpiry {
				method.ValidUntil = &until
			}
			if factor := u.SecondFactors[i]; factor != "" {
				method.SecondFactor = &factor
			}
			row.AuthMethods[i] = method
			row.NoPassword = row.NoPassword || authType == "no_password"
			row.PlaintextPassword = row.PlaintextPassword || authType == "plaintext_password"
		}
		if u.Storage == cloudManagedStorage {
			cloud = append(cloud, row)
			out.CloudManagedCount++
			continue
		}
		customer = append(customer, row)
		out.CustomerCount++
		out.NoPasswordCount += count(row.NoPassword)
		out.PlaintextPasswordCount += count(row.PlaintextPassword)
		out.AnyHostCount += count(row.AnyHost)
	}
	if audit {
		out.Inventory, out.CloudManaged = customer, cloud
	}
	return out
}

func databaseRoles(roles []clickhouse.DatabaseRole, audit bool) *DatabaseRoles {
	out := &DatabaseRoles{}
	customer, cloud := []DatabaseRole{}, []DatabaseRole{}
	for _, r := range roles {
		row := DatabaseRole{Name: r.Name, Storage: r.Storage}
		if slices.Contains(cloudManagedRoles, r.Name) {
			cloud = append(cloud, row)
			out.CloudManagedCount++
			continue
		}
		customer = append(customer, row)
		out.CustomerCount++
	}
	if audit {
		out.Inventory, out.CloudManaged = customer, cloud
	}
	return out
}

// cloudGrantee reports whether a grant's grantee is ClickHouse Cloud's own:
// a user stored in users_xml, or one of the roles Cloud creates.
func cloudGrantee(role *string, userStorage string) bool {
	if role != nil {
		return slices.Contains(cloudManagedRoles, *role)
	}
	return userStorage == cloudManagedStorage
}

// split converts rows and puts each among the customer's or among ClickHouse
// Cloud's own, as cloud says.
func split[In, Out any](rows []In, cloud func(In) bool, convert func(In) Out) (customer, cloudManaged []Out) {
	customer, cloudManaged = []Out{}, []Out{}
	for _, row := range rows {
		if cloud(row) {
			cloudManaged = append(cloudManaged, convert(row))
		} else {
			customer = append(customer, convert(row))
		}
	}
	return customer, cloudManaged
}

func roleGrants(grants []clickhouse.RoleGrant, audit bool) *RoleGrants {
	customer, cloud := split(grants,
		func(g clickhouse.RoleGrant) bool { return cloudGrantee(g.RoleName, g.UserStorage) },
		func(g clickhouse.RoleGrant) RoleGrant {
			return RoleGrant{
				UserName:             g.UserName,
				RoleName:             g.RoleName,
				GrantedRoleName:      g.GrantedRoleName,
				GrantedRoleIsDefault: bool(g.GrantedRoleIsDefault),
				WithAdminOption:      bool(g.WithAdminOption),
			}
		})
	out := &RoleGrants{CustomerCount: len(customer), CloudManagedCount: len(cloud)}
	for _, g := range customer {
		out.WithAdminOptionCount += count(g.WithAdminOption)
	}
	if audit {
		out.Inventory, out.CloudManaged = customer, cloud
	}
	return out
}

func privilegeGrants(grants []clickhouse.Grant, audit bool) *Grants {
	customer, cloud := split(grants,
		func(g clickhouse.Grant) bool { return cloudGrantee(g.RoleName, g.UserStorage) },
		func(g clickhouse.Grant) Grant {
			return Grant{
				UserName:        g.UserName,
				RoleName:        g.RoleName,
				AccessType:      g.AccessType,
				Database:        g.Database,
				Table:           g.Table,
				Column:          g.Column,
				IsPartialRevoke: bool(g.IsPartialRevoke),
				GrantOption:     bool(g.GrantOption),
			}
		})
	out := &Grants{CustomerCount: len(customer), CloudManagedCount: len(cloud)}
	for _, g := range customer {
		out.GrantOptionCount += count(g.GrantOption)
	}
	if audit {
		out.Inventory, out.CloudManaged = customer, cloud
	}
	return out
}

func settingsProfiles(profiles []clickhouse.SettingsProfile, audit bool) *SettingsProfiles {
	customer, cloud := split(profiles,
		func(p clickhouse.SettingsProfile) bool { return p.Storage == cloudManagedStorage },
		func(p clickhouse.SettingsProfile) SettingsProfile {
			return SettingsProfile{
				Name:          p.Name,
				Storage:       p.Storage,
				ApplyToAll:    bool(p.ApplyToAll),
				ApplyToList:   p.ApplyToList,
				ApplyToExcept: p.ApplyToExcept,
			}
		})
	out := &SettingsProfiles{CustomerCount: len(customer), CloudManagedCount: len(cloud)}
	if audit {
		out.Inventory, out.CloudManaged = customer, cloud
	}
	return out
}

// settingsProfileElements puts each element with its owner: a profile and a
// user by where the server keeps them, and a role by its name.
func settingsProfileElements(elements []clickhouse.SettingsProfileElement, audit bool) *SettingsProfileElements {
	customer, cloud := split(elements,
		func(e clickhouse.SettingsProfileElement) bool {
			switch {
			case e.ProfileName != nil:
				return e.ProfileStorage == cloudManagedStorage
			case e.RoleName != nil:
				return slices.Contains(cloudManagedRoles, *e.RoleName)
			}
			return e.UserStorage == cloudManagedStorage
		},
		func(e clickhouse.SettingsProfileElement) SettingsProfileElement {
			return SettingsProfileElement{
				ProfileName:    e.ProfileName,
				UserName:       e.UserName,
				RoleName:       e.RoleName,
				SettingName:    e.SettingName,
				Value:          e.Value,
				Min:            e.Min,
				Max:            e.Max,
				Writability:    e.Writability,
				InheritProfile: e.InheritProfile,
			}
		})
	out := &SettingsProfileElements{CustomerCount: len(customer), CloudManagedCount: len(cloud)}
	if audit {
		out.Inventory, out.CloudManaged = customer, cloud
	}
	return out
}

func quotaList(quotas []clickhouse.Quota, audit bool) *Quotas {
	customer, cloud := split(quotas,
		func(q clickhouse.Quota) bool { return q.Storage == cloudManagedStorage },
		func(q clickhouse.Quota) Quota {
			return Quota{
				Name:          q.Name,
				Storage:       q.Storage,
				Keys:          q.Keys,
				Durations:     q.Durations,
				ApplyToAll:    bool(q.ApplyToAll),
				ApplyToList:   q.ApplyToList,
				ApplyToExcept: q.ApplyToExcept,
			}
		})
	out := &Quotas{CustomerCount: len(customer), CloudManagedCount: len(cloud)}
	if audit {
		out.Inventory, out.CloudManaged = customer, cloud
	}
	return out
}

func quotaLimits(limits []clickhouse.QuotaLimit, audit bool) *QuotaLimits {
	customer, cloud := split(limits,
		func(l clickhouse.QuotaLimit) bool { return l.QuotaStorage == cloudManagedStorage },
		func(l clickhouse.QuotaLimit) QuotaLimit {
			return QuotaLimit{
				QuotaName:            l.QuotaName,
				Duration:             l.Duration,
				IsRandomizedInterval: l.IsRandomizedInterval,
				Limits:               l.Limits,
			}
		})
	out := &QuotaLimits{CustomerCount: len(customer), CloudManagedCount: len(cloud)}
	if audit {
		out.Inventory, out.CloudManaged = customer, cloud
	}
	return out
}

func rowPolicies(policies []clickhouse.RowPolicy, audit bool) *RowPolicies {
	customer, cloud := split(policies,
		func(p clickhouse.RowPolicy) bool { return p.Storage == cloudManagedStorage },
		func(p clickhouse.RowPolicy) RowPolicy {
			return RowPolicy{
				Name:          p.Name,
				ShortName:     p.ShortName,
				Database:      p.Database,
				Table:         p.Table,
				Storage:       p.Storage,
				IsRestrictive: bool(p.IsRestrictive),
				ApplyToAll:    bool(p.ApplyToAll),
				ApplyToList:   p.ApplyToList,
				ApplyToExcept: p.ApplyToExcept,
			}
		})
	out := &RowPolicies{CustomerCount: len(customer), CloudManagedCount: len(cloud)}
	if audit {
		out.Inventory, out.CloudManaged = customer, cloud
	}
	return out
}
