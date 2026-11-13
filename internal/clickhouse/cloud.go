// Package clickhouse reads a ClickHouse Cloud organization through the Cloud
// API, and the access settings of its services through each service's SQL
// interface over HTTPS.
package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// APIHost is the Cloud API's host, the only host the API key is sent to.
const APIHost = "api.clickhouse.cloud"

const apiBase = "https://" + APIHost + "/v1"

// Operation names of the Cloud API calls. They count each call in the
// collector result and key the test kit's fault matrix and the trace map, so
// rename one only on purpose.
const (
	OpGetOrganization = "clickhouse.organization.get"
	OpListMembers     = "clickhouse.members.list"
	OpListInvitations = "clickhouse.invitations.list"
	OpListKeys        = "clickhouse.keys.list"
	OpListRoles       = "clickhouse.roles.list"
)

// Permissions an API key's role grants, in ClickHouse Cloud's terms, which a
// permission_denied gap names. No call here needs PermissionViewActivities.
// The not_read gaps name it as the permission that reading the activities
// would need.
const (
	PermissionViewOrganization   = "control-plane:organization:view"
	PermissionViewAPIKeys        = "control-plane:organization:view-api-keys"
	PermissionManageOrganization = "control-plane:organization:manage"
	PermissionViewActivities     = "control-plane:organization:view-activities"
)

// operationPermissions holds the permission each call needs, which the
// collector result lists with the call. The API reference names it for each
// call. The members list is the exception. Its reference names
// control-plane:organization:view, but a key without
// control-plane:organization:manage gets an empty list.
var operationPermissions = map[string]string{
	OpGetOrganization: PermissionViewOrganization,
	OpListMembers:     PermissionManageOrganization,
	OpListInvitations: PermissionViewOrganization,
	OpListKeys:        PermissionViewAPIKeys,
	OpListRoles:       PermissionManageOrganization,
}

const (
	maxResponseBytes = 32 << 20
	maxErrorBytes    = 4 << 10
	// maxKeyPages caps how many pages of API keys the client reads, at 250
	// keys a page.
	maxKeyPages = 200
)

// Cloud reads one organization through the Cloud API. Its calls go through
// the client componentsdk.NewHTTPClient returns, which retries the calls it
// can.
type Cloud struct {
	http         *http.Client
	organization string
	keyID        string
	keySecret    string
}

// NewCloud returns a client that reads organization with the API key keyID
// and its secret.
func NewCloud(httpClient *http.Client, organization, keyID, keySecret string) *Cloud {
	return &Cloud{http: httpClient, organization: organization, keyID: keyID, keySecret: keySecret}
}

// Organization is the organization the client reads.
type Organization struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
}

// AssignedRole is a console role assigned to a member, an invitation, or an
// API key.
type AssignedRole struct {
	RoleID   string `json:"roleId"`
	RoleName string `json:"roleName"`
	RoleType string `json:"roleType"`
}

// Member is a user who belongs to the organization. The collector does not
// emit Name; record_test.go reads it to scrub it from recordings.
type Member struct {
	UserID        string         `json:"userId"`
	Name          string         `json:"name"`
	Email         string         `json:"email"`
	JoinedAt      string         `json:"joinedAt"`
	AssignedRoles []AssignedRole `json:"assignedRoles"`
}

// Invitation is an invitation to join the organization that has not been
// accepted.
type Invitation struct {
	ID            string         `json:"id"`
	Email         string         `json:"email"`
	CreatedAt     string         `json:"createdAt"`
	ExpireAt      string         `json:"expireAt"`
	AssignedRoles []AssignedRole `json:"assignedRoles"`
}

// APIKey is one of the organization's API keys. ExpireAt and UsedAt are nil
// or empty when the key never expires or was never used.
type APIKey struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	State         string          `json:"state"`
	AssignedRoles []AssignedRole  `json:"assignedRoles"`
	CreatedAt     string          `json:"createdAt"`
	ExpireAt      *string         `json:"expireAt"`
	UsedAt        *string         `json:"usedAt"`
	IPAccessList  []IPAccessEntry `json:"ipAccessList"`
}

// IPAccessEntry is one address or CIDR range an API key may be used from.
type IPAccessEntry struct {
	Source string `json:"source"`
}

// Role is a console role, a system role or a custom one, with the policies
// that say what it grants and the members and keys that hold it.
type Role struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Actors   []string `json:"actors"`
	Policies []Policy `json:"policies"`
}

// Policy allows or denies permissions on resources.
type Policy struct {
	AllowDeny   string     `json:"allowDeny"`
	Permissions []string   `json:"permissions"`
	Resources   []string   `json:"resources"`
	Tags        PolicyTags `json:"tags"`
}

// PolicyTags are a policy's tags. RoleV2 is sql-console-readonly for
// read-only SQL console access, or sql-console-admin for admin access.
// Grants lists database grants, such as database names. Each is empty when
// the policy has no such tag.
type PolicyTags struct {
	RoleV2 *string  `json:"roleV2"`
	Grants []string `json:"grants"`
}

func (c *Cloud) orgPath() string {
	return "/organizations/" + url.PathEscape(c.organization)
}

// GetOrganization reads the organization. It is the collector's sign-in: it
// proves the key works and belongs to the organization. A 404 means there is
// no organization with that ID, which is a configuration error.
func (c *Cloud) GetOrganization(ctx context.Context) (*Organization, error) {
	var env struct {
		Result *Organization `json:"result"`
	}
	resp, err := c.get(ctx, OpGetOrganization, c.orgPath(), &env)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		return nil, componentsdk.CodeError(componentsdk.CodeConfigInvalid, fmt.Errorf("organization %s was not found: %w", c.organization, err))
	}
	if err != nil {
		return nil, err
	}
	if env.Result == nil || env.Result.ID == "" {
		return nil, componentsdk.ResponseError(resp, invalidResponse(OpGetOrganization, "has no organization id"))
	}
	return env.Result, nil
}

// MembersDocs is ClickHouse Cloud's API reference for listing members, which
// says control-plane:organization:view is enough.
const MembersDocs = "https://clickhouse.com/docs/products/cloud/api-reference/user-management/list-organization-members"

// ErrMembersHidden is the error ListMembers returns for an empty member list.
// The Cloud API answers a key without control-plane:organization:manage with
// one, although its reference says control-plane:organization:view is
// enough, and an organization always has at least one member, its Admin.
var ErrMembersHidden = errors.New(OpListMembers + ": the API returned no members, and an organization always has at least one")

// AdminRole is the system role with every permission in the organization.
const AdminRole = "Admin"

// validRoles reports whether each role names its ID, its name, and whether
// it is a system role or a custom one.
func validRoles(roles []AssignedRole) bool {
	for _, r := range roles {
		if r.RoleID == "" || r.RoleName == "" || (r.RoleType != "system" && r.RoleType != "custom") {
			return false
		}
	}
	return true
}

// validTime reports whether at is an RFC 3339 time, as the API reference
// says each of its timestamps is.
func validTime(at string) bool {
	_, err := time.Parse(time.RFC3339, at)
	return err == nil
}

// ListMembers lists the organization's members. An empty list is
// ErrMembersHidden, coded permission_denied, never an answer. Nor is a list
// where no member holds the system Admin role: an organization always has
// its Admin, and a list without one would count no admins.
func (c *Cloud) ListMembers(ctx context.Context) ([]Member, error) {
	var env struct {
		Result []Member `json:"result"`
	}
	resp, err := c.get(ctx, OpListMembers, c.orgPath()+"/members", &env)
	if err != nil {
		return nil, err
	}
	if env.Result == nil {
		return nil, componentsdk.ResponseError(resp, invalidResponse(OpListMembers, "has no list of members"))
	}
	if len(env.Result) == 0 {
		return nil, componentsdk.ResponseError(resp, componentsdk.CodeError(componentsdk.CodePermissionDenied, ErrMembersHidden))
	}
	admins := 0
	for _, m := range env.Result {
		if m.Email == "" || m.AssignedRoles == nil || !validRoles(m.AssignedRoles) {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListMembers, "lists a member with no email, or with assignedRoles that are missing or name no role"))
		}
		for _, r := range m.AssignedRoles {
			if r.RoleType == "system" && r.RoleName == AdminRole {
				admins++
				break
			}
		}
	}
	if admins == 0 {
		return nil, componentsdk.ResponseError(resp, invalidResponse(OpListMembers, "lists no member who holds the Admin role, and an organization always has one"))
	}
	return env.Result, nil
}

// ListInvitations lists the invitations that have not been accepted.
func (c *Cloud) ListInvitations(ctx context.Context) ([]Invitation, error) {
	var env struct {
		Result []Invitation `json:"result"`
	}
	resp, err := c.get(ctx, OpListInvitations, c.orgPath()+"/invitations", &env)
	if err != nil {
		return nil, err
	}
	if env.Result == nil {
		return nil, componentsdk.ResponseError(resp, invalidResponse(OpListInvitations, "has no list of invitations"))
	}
	for _, inv := range env.Result {
		if inv.Email == "" || !validTime(inv.ExpireAt) || inv.AssignedRoles == nil || !validRoles(inv.AssignedRoles) {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListInvitations, "lists an invitation with no email, an expireAt that is not a time, or assignedRoles that are missing or name no role"))
		}
	}
	return env.Result, nil
}

// ErrKeysHidden is the error ListKeys returns when the API lists no keys.
// The key the collector signs in with is always one of them.
var ErrKeysHidden = errors.New(OpListKeys + ": the API returned no keys, and the key the collector signs in with is always one")

// ListKeys lists every API key, oldest first, following nextCursor from page
// to page. An empty list is ErrKeysHidden, coded permission_denied.
func (c *Cloud) ListKeys(ctx context.Context) ([]APIKey, error) {
	var keys []APIKey
	cursor := ""
	for range maxKeyPages {
		path := c.orgPath() + "/keys"
		if cursor != "" {
			path += "?" + url.Values{"cursor": {cursor}}.Encode()
		}
		var env struct {
			Result     []APIKey `json:"result"`
			NextCursor *string  `json:"nextCursor"`
		}
		resp, err := c.get(ctx, OpListKeys, path, &env)
		if err != nil {
			return nil, err
		}
		if env.Result == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListKeys, "has no list of keys"))
		}
		for _, k := range env.Result {
			if k.Name == "" || (k.State != "enabled" && k.State != "disabled") || k.AssignedRoles == nil || !validRoles(k.AssignedRoles) {
				return nil, componentsdk.ResponseError(resp, invalidResponse(OpListKeys, "lists a key with no name or state, or with assignedRoles that are missing or name no role"))
			}
			if !validTime(k.CreatedAt) || (k.ExpireAt != nil && *k.ExpireAt != "" && !validTime(*k.ExpireAt)) || (k.UsedAt != nil && !validTime(*k.UsedAt)) {
				return nil, componentsdk.ResponseError(resp, invalidResponse(OpListKeys, "lists a key with no createdAt, or a createdAt, expireAt, or usedAt that is not a time"))
			}
			if k.IPAccessList == nil || slices.ContainsFunc(k.IPAccessList, func(e IPAccessEntry) bool { return e.Source == "" }) {
				return nil, componentsdk.ResponseError(resp, invalidResponse(OpListKeys, "lists a key with no ipAccessList, or an entry with no source"))
			}
		}
		keys = append(keys, env.Result...)
		if env.NextCursor == nil || *env.NextCursor == "" {
			if len(keys) == 0 {
				return nil, componentsdk.ResponseError(resp, componentsdk.CodeError(componentsdk.CodePermissionDenied, ErrKeysHidden))
			}
			return keys, nil
		}
		if *env.NextCursor == cursor {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListKeys, "repeats the cursor it was sent"))
		}
		cursor = *env.NextCursor
	}
	return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: more than %d pages of keys", OpListKeys, maxKeyPages))
}

// ErrRolesHidden is the error ListRoles returns for an empty list of roles.
// Every organization has the system roles, so the list is never empty.
var ErrRolesHidden = errors.New(OpListRoles + ": the API returned no roles, and an organization always has its system roles")

// ListRoles lists the organization's console roles. It needs
// control-plane:organization:manage, which can also change the organization.
// An empty list is ErrRolesHidden, coded permission_denied.
func (c *Cloud) ListRoles(ctx context.Context) ([]Role, error) {
	var env struct {
		Result []Role `json:"result"`
	}
	resp, err := c.get(ctx, OpListRoles, c.orgPath()+"/roles", &env)
	if err != nil {
		return nil, err
	}
	if env.Result == nil {
		return nil, componentsdk.ResponseError(resp, invalidResponse(OpListRoles, "has no list of roles"))
	}
	if len(env.Result) == 0 {
		return nil, componentsdk.ResponseError(resp, componentsdk.CodeError(componentsdk.CodePermissionDenied, ErrRolesHidden))
	}
	for _, r := range env.Result {
		if r.Name == "" || r.Type == "" || r.Actors == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListRoles, "lists a role with no name, type, or actors"))
		}
	}
	return env.Result, nil
}

// get sends a GET named op and decodes the JSON response into out. It
// returns the response, its body read and closed, so a caller that finds the
// body wanting can build an error with componentsdk.ResponseError, which
// gives a gap recorded from it the response's call.
func (c *Cloud) get(ctx context.Context, op, path string, out any) (*http.Response, error) {
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op, Permission: operationPermissions[op]})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.keyID, c.keySecret)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return resp, componentsdk.ResponseError(resp, &APIError{StatusCode: resp.StatusCode, Message: apiErrorMessage(body), Header: resp.Header})
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return resp, componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding the response: %w", op, err))
	}
	return resp, nil
}

// APIError is a Cloud API response whose status is not 200.
type APIError struct {
	StatusCode int
	// Message is the error the API sent, such as "FORBIDDEN: IP address not
	// allowed".
	Message string
	Header  http.Header
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the ClickHouse Cloud API returned status %d", e.StatusCode)
	}
	return fmt.Sprintf("the ClickHouse Cloud API returned status %d: %s", e.StatusCode, e.Message)
}

// HTTPStatus and HTTPHeader let componentsdk.Classify give the error its
// code, such as permission_denied for a 403 or rate_limited for a 429.
func (e *APIError) HTTPStatus() int         { return e.StatusCode }
func (e *APIError) HTTPHeader() http.Header { return e.Header }

// IPNotAllowed reports whether the API refused the key because the request
// came from an address outside the key's IP access list.
func (e *APIError) IPNotAllowed() bool {
	return e.StatusCode == http.StatusForbidden && strings.Contains(strings.ToLower(e.Message), "ip address not allowed")
}

// APINamesPermission reports whether a refused Cloud API call shows that the
// key's role lacks the call's permission, for
// componentsdk.HTTPOptions.NamesPermission. It is false for a 403 that
// refuses the runner's address, which the key's IP access list controls.
func APINamesPermission(resp *http.Response, body []byte) bool {
	refused := APIError{StatusCode: resp.StatusCode, Message: apiErrorMessage(body)}
	return !refused.IPNotAllowed()
}

// apiErrorMessage reads the error field of a Cloud API error body, or the
// start of the body when it is not JSON.
func apiErrorMessage(body []byte) string {
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Error != "" {
		return payload.Error
	}
	text := strings.TrimSpace(string(body))
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}

var apiErrorCode = regexp.MustCompile(`^([A-Z][A-Z_]{2,63})(?::|$)`)

// APIVendorCode reads the code that starts a Cloud API error, such as
// FORBIDDEN in "FORBIDDEN: IP address not allowed" or in "FORBIDDEN", for
// componentsdk.HTTPOptions.VendorCode. It returns the code alone, never the
// message, which can name a resource.
func APIVendorCode(_ *http.Response, body []byte) string {
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return ""
	}
	if m := apiErrorCode.FindStringSubmatch(payload.Error); m != nil {
		return m[1]
	}
	return ""
}

func invalidResponse(op, problem string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("%s: the response %s", op, problem))
}
