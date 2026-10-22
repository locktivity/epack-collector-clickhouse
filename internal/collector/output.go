package collector

import "encoding/json"

// SchemaVersion is the version of docs/schema/v1.0.0.json, which describes
// Output. It stays 1.0.0 until the collector itself reaches v1.0.0.
const SchemaVersion = "1.0.0"

// Output is the artifact the collector emits at artifactPath. A part whose
// read failed is left out, with a gap in the collector result.
type Output struct {
	SchemaVersion    string        `json:"schema_version"`
	CollectedAt      string        `json:"collected_at"`
	CollectedAtLevel string        `json:"collected_at_level"`
	Organization     Organization  `json:"organization"`
	Members          *Members      `json:"members,omitempty"`
	Invitations      *Invitations  `json:"invitations,omitempty"`
	APIKeys          *APIKeys      `json:"api_keys,omitempty"`
	ConsoleRoles     *ConsoleRoles `json:"console_roles,omitempty"`
	Services         []Service     `json:"services"`
}

// Organization is the organization the collector signed in to.
type Organization struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	CreatedAt *string `json:"created_at"`
	// SSOEnabled is always null, with a gap: ClickHouse Cloud has no API
	// that reports SAML SSO.
	SSOEnabled *bool `json:"sso_enabled"`
}

// Members rolls up the organization's members.
type Members struct {
	TotalCount int `json:"total_count"`
	AdminCount int `json:"admin_count"`
	// MFAEnabledCount is always null, with a gap: ClickHouse Cloud has no
	// API that reports a member's MFA.
	MFAEnabledCount *int     `json:"mfa_enabled_count"`
	Inventory       []Member `json:"inventory,omitzero"`
}

// Member is one row of the members inventory.
type Member struct {
	Email    string    `json:"email"`
	Roles    []RoleRef `json:"roles"`
	Admin    bool      `json:"admin"`
	JoinedAt *string   `json:"joined_at"`
}

// RoleRef names a console role assigned to a member, an invitation, or an
// API key.
type RoleRef struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Invitations rolls up the invitations that have not been accepted.
type Invitations struct {
	TotalCount   int          `json:"total_count"`
	PendingCount int          `json:"pending_count"`
	ExpiredCount int          `json:"expired_count"`
	Inventory    []Invitation `json:"inventory,omitzero"`
}

// Invitation is one row of the invitations inventory.
type Invitation struct {
	Email     string    `json:"email"`
	Roles     []RoleRef `json:"roles"`
	CreatedAt *string   `json:"created_at"`
	ExpiresAt string    `json:"expires_at"`
	Expired   bool      `json:"expired"`
}

// APIKeys rolls up the organization's API keys.
type APIKeys struct {
	TotalCount        int      `json:"total_count"`
	EnabledCount      int      `json:"enabled_count"`
	AdminCount        int      `json:"admin_count"`
	NeverExpiresCount int      `json:"never_expires_count"`
	AnyAddressCount   int      `json:"any_address_count"`
	NeverUsedCount    int      `json:"never_used_count"`
	Inventory         []APIKey `json:"inventory,omitzero"`
}

// APIKey is one row of the API keys inventory.
type APIKey struct {
	Name         string    `json:"name"`
	State        string    `json:"state"`
	Roles        []RoleRef `json:"roles"`
	Admin        bool      `json:"admin"`
	CreatedAt    *string   `json:"created_at"`
	ExpiresAt    *string   `json:"expires_at"`
	NeverExpires bool      `json:"never_expires"`
	IPAccessList []string  `json:"ip_access_list"`
	AnyAddress   bool      `json:"any_address"`
	LastUsedAt   *string   `json:"last_used_at"`
	NeverUsed    bool      `json:"never_used"`
}

// ConsoleRoles rolls up the organization's console roles.
type ConsoleRoles struct {
	TotalCount  int           `json:"total_count"`
	CustomCount int           `json:"custom_count"`
	Inventory   []ConsoleRole `json:"inventory,omitzero"`
}

// ConsoleRole is one row of the console roles inventory.
type ConsoleRole struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	MemberCount int             `json:"member_count"`
	APIKeyCount int             `json:"api_key_count"`
	Policies    []ConsolePolicy `json:"policies"`
}

// ConsolePolicy is one policy of a console role.
type ConsolePolicy struct {
	AllowDeny   string   `json:"allow_deny"`
	Permissions []string `json:"permissions"`
	Resources   []string `json:"resources"`
}

// Service is what the collector read from one configured service. Every
// part but the host and the user is left out, with a gap, when the service
// could not be reached.
type Service struct {
	Host                    string                   `json:"host"`
	User                    string                   `json:"user"`
	Version                 string                   `json:"version,omitempty"`
	Users                   *DatabaseUsers           `json:"users,omitempty"`
	Roles                   *DatabaseRoles           `json:"roles,omitempty"`
	RoleGrants              *RoleGrants              `json:"role_grants,omitempty"`
	Grants                  *Grants                  `json:"grants,omitempty"`
	SettingsProfiles        *SettingsProfiles        `json:"settings_profiles,omitempty"`
	SettingsProfileElements *SettingsProfileElements `json:"settings_profile_elements,omitempty"`
	Quotas                  *Quotas                  `json:"quotas,omitempty"`
	QuotaLimits             *QuotaLimits             `json:"quota_limits,omitempty"`
	RowPolicies             *RowPolicies             `json:"row_policies,omitempty"`
}

// DatabaseUsers rolls up a service's database users. Inventory holds the
// customer's users and CloudManaged ClickHouse Cloud's own, the ones stored
// in users_xml.
type DatabaseUsers struct {
	CustomerCount          int            `json:"customer_count"`
	CloudManagedCount      int            `json:"cloud_managed_count"`
	NoPasswordCount        int            `json:"no_password_count"`
	PlaintextPasswordCount int            `json:"plaintext_password_count"`
	AnyHostCount           int            `json:"any_host_count"`
	Inventory              []DatabaseUser `json:"inventory,omitzero"`
	CloudManaged           []DatabaseUser `json:"cloud_managed,omitzero"`
}

// DatabaseUser is one database user.
type DatabaseUser struct {
	Name              string       `json:"name"`
	Storage           string       `json:"storage"`
	AuthMethods       []AuthMethod `json:"auth_methods"`
	NoPassword        bool         `json:"no_password"`
	PlaintextPassword bool         `json:"plaintext_password"`
	HostIP            []string     `json:"host_ip"`
	HostNames         []string     `json:"host_names"`
	HostNamesRegexp   []string     `json:"host_names_regexp"`
	HostNamesLike     []string     `json:"host_names_like"`
	AnyHost           bool         `json:"any_host"`
}

// AuthMethod is one way a database user can sign in.
type AuthMethod struct {
	Type         string  `json:"type"`
	ValidUntil   *string `json:"valid_until"`
	SecondFactor *string `json:"second_factor"`
}

// DatabaseRoles rolls up a service's database roles. Inventory holds the
// customer's roles and CloudManaged the roles ClickHouse Cloud creates in
// every service.
type DatabaseRoles struct {
	CustomerCount     int            `json:"customer_count"`
	CloudManagedCount int            `json:"cloud_managed_count"`
	Inventory         []DatabaseRole `json:"inventory,omitzero"`
	CloudManaged      []DatabaseRole `json:"cloud_managed,omitzero"`
}

// DatabaseRole is one database role.
type DatabaseRole struct {
	Name    string `json:"name"`
	Storage string `json:"storage"`
}

// RoleGrants lists the roles granted to users and to other roles. Inventory
// holds the grants to the customer's users and roles, and CloudManaged those
// to ClickHouse Cloud's own.
type RoleGrants struct {
	CustomerCount        int         `json:"customer_count"`
	CloudManagedCount    int         `json:"cloud_managed_count"`
	WithAdminOptionCount int         `json:"with_admin_option_count"`
	Inventory            []RoleGrant `json:"inventory,omitzero"`
	CloudManaged         []RoleGrant `json:"cloud_managed,omitzero"`
}

// RoleGrant is a row of system.role_grants.
type RoleGrant struct {
	UserName             *string `json:"user_name"`
	RoleName             *string `json:"role_name"`
	GrantedRoleName      string  `json:"granted_role_name"`
	GrantedRoleIsDefault bool    `json:"granted_role_is_default"`
	WithAdminOption      bool    `json:"with_admin_option"`
}

// Grants lists the privileges granted to users and roles. Inventory holds
// those of the customer's users and roles, and CloudManaged those of
// ClickHouse Cloud's own.
type Grants struct {
	CustomerCount     int     `json:"customer_count"`
	CloudManagedCount int     `json:"cloud_managed_count"`
	GrantOptionCount  int     `json:"grant_option_count"`
	Inventory         []Grant `json:"inventory,omitzero"`
	CloudManaged      []Grant `json:"cloud_managed,omitzero"`
}

// Grant is a row of system.grants.
type Grant struct {
	UserName        *string `json:"user_name"`
	RoleName        *string `json:"role_name"`
	AccessType      string  `json:"access_type"`
	Database        *string `json:"database"`
	Table           *string `json:"table"`
	Column          *string `json:"column"`
	IsPartialRevoke bool    `json:"is_partial_revoke"`
	GrantOption     bool    `json:"grant_option"`
}

// SettingsProfiles lists the settings profiles. Inventory holds the
// customer's profiles, and CloudManaged ClickHouse Cloud's own, the ones
// stored in users_xml.
type SettingsProfiles struct {
	CustomerCount     int               `json:"customer_count"`
	CloudManagedCount int               `json:"cloud_managed_count"`
	Inventory         []SettingsProfile `json:"inventory,omitzero"`
	CloudManaged      []SettingsProfile `json:"cloud_managed,omitzero"`
}

// SettingsProfile is a row of system.settings_profiles.
type SettingsProfile struct {
	Name          string   `json:"name"`
	Storage       string   `json:"storage"`
	ApplyToAll    bool     `json:"apply_to_all"`
	ApplyToList   []string `json:"apply_to_list"`
	ApplyToExcept []string `json:"apply_to_except"`
}

// SettingsProfileElements lists what each settings profile, user, and role
// sets. Inventory holds the elements of the customer's profiles, users, and
// roles, and CloudManaged those of ClickHouse Cloud's own.
type SettingsProfileElements struct {
	CustomerCount     int                      `json:"customer_count"`
	CloudManagedCount int                      `json:"cloud_managed_count"`
	Inventory         []SettingsProfileElement `json:"inventory,omitzero"`
	CloudManaged      []SettingsProfileElement `json:"cloud_managed,omitzero"`
}

// SettingsProfileElement is a row of system.settings_profile_elements.
type SettingsProfileElement struct {
	ProfileName    *string `json:"profile_name"`
	UserName       *string `json:"user_name"`
	RoleName       *string `json:"role_name"`
	SettingName    *string `json:"setting_name"`
	Value          *string `json:"value"`
	Min            *string `json:"min"`
	Max            *string `json:"max"`
	Writability    *string `json:"writability"`
	InheritProfile *string `json:"inherit_profile"`
}

// Quotas lists the quotas. Inventory holds the customer's quotas, and
// CloudManaged ClickHouse Cloud's own, the ones stored in users_xml.
type Quotas struct {
	CustomerCount     int     `json:"customer_count"`
	CloudManagedCount int     `json:"cloud_managed_count"`
	Inventory         []Quota `json:"inventory,omitzero"`
	CloudManaged      []Quota `json:"cloud_managed,omitzero"`
}

// Quota is a row of system.quotas.
type Quota struct {
	Name          string   `json:"name"`
	Storage       string   `json:"storage"`
	Keys          []string `json:"keys"`
	Durations     []uint32 `json:"durations"`
	ApplyToAll    bool     `json:"apply_to_all"`
	ApplyToList   []string `json:"apply_to_list"`
	ApplyToExcept []string `json:"apply_to_except"`
}

// QuotaLimits lists each quota's limits for each of its intervals.
// Inventory holds the limits of the customer's quotas, and CloudManaged
// those of ClickHouse Cloud's own.
type QuotaLimits struct {
	CustomerCount     int          `json:"customer_count"`
	CloudManagedCount int          `json:"cloud_managed_count"`
	Inventory         []QuotaLimit `json:"inventory,omitzero"`
	CloudManaged      []QuotaLimit `json:"cloud_managed,omitzero"`
}

// QuotaLimit is a row of system.quota_limits, with the limits that are set
// keyed by their name without max_.
type QuotaLimit struct {
	QuotaName            string                 `json:"quota_name"`
	Duration             uint32                 `json:"duration"`
	IsRandomizedInterval bool                   `json:"is_randomized_interval"`
	Limits               map[string]json.Number `json:"limits"`
}

// RowPolicies lists the row policies. Inventory holds the customer's
// policies, and CloudManaged ClickHouse Cloud's own, the ones stored in
// users_xml.
type RowPolicies struct {
	CustomerCount     int         `json:"customer_count"`
	CloudManagedCount int         `json:"cloud_managed_count"`
	Inventory         []RowPolicy `json:"inventory,omitzero"`
	CloudManaged      []RowPolicy `json:"cloud_managed,omitzero"`
}

// RowPolicy is a row of system.row_policies, without its filter expressions.
type RowPolicy struct {
	Name          string   `json:"name"`
	ShortName     string   `json:"short_name"`
	Database      string   `json:"database"`
	Table         string   `json:"table"`
	Storage       string   `json:"storage"`
	IsRestrictive bool     `json:"is_restrictive"`
	ApplyToAll    bool     `json:"apply_to_all"`
	ApplyToList   []string `json:"apply_to_list"`
	ApplyToExcept []string `json:"apply_to_except"`
}
