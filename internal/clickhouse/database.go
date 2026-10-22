package clickhouse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/locktivity/epack/componentsdk"
)

// DatabasePort is the port of a ClickHouse Cloud service's HTTPS interface.
const DatabasePort = "8443"

// Operation names of the SQL queries the client sends to a service.
const (
	OpGetVersion                  = "clickhouse.db.version.get"
	OpListUsers                   = "clickhouse.db.users.list"
	OpListDatabaseRoles           = "clickhouse.db.roles.list"
	OpListRoleGrants              = "clickhouse.db.role_grants.list"
	OpListGrants                  = "clickhouse.db.grants.list"
	OpListSettingsProfiles        = "clickhouse.db.settings_profiles.list"
	OpListSettingsProfileElements = "clickhouse.db.settings_profile_elements.list"
	OpListQuotas                  = "clickhouse.db.quotas.list"
	OpListQuotaLimits             = "clickhouse.db.quota_limits.list"
	OpListRowPolicies             = "clickhouse.db.row_policies.list"
)

// Database reads the access settings of one service as a database user. Its
// first query, Version, goes through a client of its own whose attempts wait
// longer, since it also wakes a service that has gone idle.
type Database struct {
	query    *http.Client
	wake     *http.Client
	host     string
	user     string
	password string
}

// NewDatabase returns a client for the service at host that signs in as
// user. wake sends the first query and query sends the rest.
func NewDatabase(query, wake *http.Client, host, user, password string) *Database {
	return &Database{query: query, wake: wake, host: host, user: user, password: password}
}

// Flag is a ClickHouse UInt8 column that holds 0 or 1.
type Flag bool

// UnmarshalJSON reads 0 or 1, or true or false.
func (f *Flag) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case "0", "false":
		*f = false
	case "1", "true":
		*f = true
	default:
		return fmt.Errorf("%s is not 0 or 1", data)
	}
	return nil
}

// User is a row of system.users, with each sign-in method's type, the time
// it stops working, and its second factor in lists of the same length.
type User struct {
	Name            string   `json:"name"`
	Storage         string   `json:"storage"`
	AuthTypes       []string `json:"auth_types"`
	ValidUntil      []string `json:"valid_until"`
	SecondFactors   []string `json:"second_factors"`
	HostIP          []string `json:"host_ip"`
	HostNames       []string `json:"host_names"`
	HostNamesRegexp []string `json:"host_names_regexp"`
	HostNamesLike   []string `json:"host_names_like"`
}

// DatabaseRole is a row of system.roles.
type DatabaseRole struct {
	Name    string `json:"name"`
	Storage string `json:"storage"`
}

// RoleGrant is a row of system.role_grants: a role granted to a user or to
// another role. UserStorage is where the server keeps the user, and empty
// for a grant to a role.
type RoleGrant struct {
	UserName             *string `json:"user_name"`
	RoleName             *string `json:"role_name"`
	GrantedRoleName      string  `json:"granted_role_name"`
	GrantedRoleIsDefault Flag    `json:"granted_role_is_default"`
	WithAdminOption      Flag    `json:"with_admin_option"`
	UserStorage          string  `json:"user_storage"`
}

// Grant is a row of system.grants: a privilege granted to a user or a role,
// or partly revoked from one. UserStorage is where the server keeps the
// user, and empty for a grant to a role.
type Grant struct {
	UserName        *string `json:"user_name"`
	RoleName        *string `json:"role_name"`
	AccessType      string  `json:"access_type"`
	Database        *string `json:"database"`
	Table           *string `json:"table"`
	Column          *string `json:"column"`
	IsPartialRevoke Flag    `json:"is_partial_revoke"`
	GrantOption     Flag    `json:"grant_option"`
	UserStorage     string  `json:"user_storage"`
}

// SettingsProfile is a row of system.settings_profiles.
type SettingsProfile struct {
	Name          string   `json:"name"`
	Storage       string   `json:"storage"`
	ApplyToAll    Flag     `json:"apply_to_all"`
	ApplyToList   []string `json:"apply_to_list"`
	ApplyToExcept []string `json:"apply_to_except"`
}

// SettingsProfileElement is a row of system.settings_profile_elements: a
// setting, a constraint on one, or an inherited profile, set in a settings
// profile or on a user or a role. ProfileStorage and UserStorage are where
// the server keeps the element's profile or user, and empty otherwise.
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
	ProfileStorage string  `json:"profile_storage"`
	UserStorage    string  `json:"user_storage"`
}

// Quota is a row of system.quotas.
type Quota struct {
	Name          string   `json:"name"`
	Storage       string   `json:"storage"`
	Keys          []string `json:"keys"`
	Durations     []uint32 `json:"durations"`
	ApplyToAll    Flag     `json:"apply_to_all"`
	ApplyToList   []string `json:"apply_to_list"`
	ApplyToExcept []string `json:"apply_to_except"`
}

// QuotaLimit is a row of system.quota_limits. Limits holds each max_ column
// that is set, by its name without the prefix, such as queries for
// max_queries. The columns differ between server versions. QuotaStorage is
// where the server keeps the quota.
type QuotaLimit struct {
	QuotaName            string
	Duration             uint32
	IsRandomizedInterval bool
	Limits               map[string]json.Number
	QuotaStorage         string
}

// UnmarshalJSON reads a quota_limits row selected with *.
func (q *QuotaLimit) UnmarshalJSON(data []byte) error {
	var row map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&row); err != nil {
		return err
	}
	var randomized Flag
	if err := json.Unmarshal(row["quota_name"], &q.QuotaName); err != nil {
		return fmt.Errorf("quota_name: %w", err)
	}
	if err := json.Unmarshal(row["duration"], &q.Duration); err != nil {
		return fmt.Errorf("duration: %w", err)
	}
	if err := json.Unmarshal(row["is_randomized_interval"], &randomized); err != nil {
		return fmt.Errorf("is_randomized_interval: %w", err)
	}
	if raw, ok := row["quota_storage"]; ok {
		if err := json.Unmarshal(raw, &q.QuotaStorage); err != nil {
			return fmt.Errorf("quota_storage: %w", err)
		}
	}
	q.IsRandomizedInterval = bool(randomized)
	q.Limits = map[string]json.Number{}
	for column, raw := range row {
		name, ok := strings.CutPrefix(column, "max_")
		if !ok || string(raw) == "null" {
			continue
		}
		limit, err := limitValue(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", column, err)
		}
		q.Limits[name] = limit
	}
	return nil
}

// limitValue reads a limit, which FORMAT JSON quotes when it is a UInt64.
func limitValue(raw json.RawMessage) (json.Number, error) {
	var quoted string
	if json.Unmarshal(raw, &quoted) == nil {
		raw = json.RawMessage(quoted)
	}
	n := json.Number(strings.TrimSpace(string(raw)))
	if _, err := strconv.ParseFloat(n.String(), 64); err != nil {
		return "", fmt.Errorf("%s is not a number", raw)
	}
	return n, nil
}

// RowPolicy is a row of system.row_policies. Its filter expressions are not
// read, since they can hold the customer's data values.
type RowPolicy struct {
	Name          string   `json:"name"`
	ShortName     string   `json:"short_name"`
	Database      string   `json:"database"`
	Table         string   `json:"table"`
	Storage       string   `json:"storage"`
	IsRestrictive Flag     `json:"is_restrictive"`
	ApplyToAll    Flag     `json:"apply_to_all"`
	ApplyToList   []string `json:"apply_to_list"`
	ApplyToExcept []string `json:"apply_to_except"`
}

// Version reads the server's version. It is the first query a run sends to
// a service, and it wakes a service that has gone idle.
func (d *Database) Version(ctx context.Context) (string, error) {
	type row struct {
		Version string `json:"version"`
	}
	rows, resp, err := query[row](ctx, d, d.wake, OpGetVersion, `SELECT version() AS version`)
	if err != nil {
		return "", err
	}
	if len(rows) != 1 || rows[0].Version == "" {
		return "", componentsdk.ResponseError(resp, invalidResponse(OpGetVersion, "has no version"))
	}
	return rows[0].Version, nil
}

// Users lists the service's database users. valid_until is formatted in UTC
// here, since the server renders it in its own time zone.
func (d *Database) Users(ctx context.Context) ([]User, error) {
	rows, resp, err := query[User](ctx, d, d.query, OpListUsers, `SELECT name, storage,
	arrayMap(t -> toString(t), auth_type) AS auth_types,
	arrayMap(t -> formatDateTime(t, '%Y-%m-%dT%H:%i:%SZ', 'UTC'), valid_until) AS valid_until,
	arrayMap(p -> JSONExtractString(p, 'second_factor'), auth_params) AS second_factors,
	host_ip, host_names, host_names_regexp, host_names_like
FROM system.users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for _, u := range rows {
		n := len(u.AuthTypes)
		if u.Name == "" || u.AuthTypes == nil || len(u.ValidUntil) != n || len(u.SecondFactors) != n ||
			u.HostIP == nil || u.HostNames == nil || u.HostNamesRegexp == nil || u.HostNamesLike == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListUsers, "lists a user with missing or mismatched columns"))
		}
	}
	return rows, nil
}

// Roles lists the service's database roles.
func (d *Database) Roles(ctx context.Context) ([]DatabaseRole, error) {
	rows, resp, err := query[DatabaseRole](ctx, d, d.query, OpListDatabaseRoles, `SELECT name, storage FROM system.roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.Name == "" {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListDatabaseRoles, "lists a role with no name"))
		}
	}
	return rows, nil
}

// RoleGrants lists the roles granted to users and to other roles, with
// where the server keeps each user.
func (d *Database) RoleGrants(ctx context.Context) ([]RoleGrant, error) {
	rows, resp, err := query[RoleGrant](ctx, d, d.query, OpListRoleGrants, `SELECT g.user_name, g.role_name, g.granted_role_name, g.granted_role_is_default, g.with_admin_option, u.storage AS user_storage
FROM system.role_grants AS g LEFT JOIN system.users AS u ON u.name = g.user_name
ORDER BY g.user_name, g.role_name, g.granted_role_name`)
	if err != nil {
		return nil, err
	}
	for _, g := range rows {
		if (g.UserName == nil) == (g.RoleName == nil) || g.GrantedRoleName == "" {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListRoleGrants, "lists a grant with no single grantee or no role"))
		}
	}
	return rows, nil
}

// Grants lists the privileges granted to users and roles, and the parts of
// them revoked again, with where the server keeps each user.
func (d *Database) Grants(ctx context.Context) ([]Grant, error) {
	rows, resp, err := query[Grant](ctx, d, d.query, OpListGrants, `SELECT g.user_name, g.role_name, toString(g.access_type) AS access_type, g.database, g.table, g.column, g.is_partial_revoke, g.grant_option, u.storage AS user_storage
FROM system.grants AS g LEFT JOIN system.users AS u ON u.name = g.user_name
ORDER BY g.user_name, g.role_name, access_type, g.database, g.table, g.column, g.is_partial_revoke`)
	if err != nil {
		return nil, err
	}
	for _, g := range rows {
		if (g.UserName == nil) == (g.RoleName == nil) || g.AccessType == "" {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListGrants, "lists a grant with no single grantee or no access type"))
		}
	}
	return rows, nil
}

// SettingsProfiles lists the settings profiles.
func (d *Database) SettingsProfiles(ctx context.Context) ([]SettingsProfile, error) {
	rows, resp, err := query[SettingsProfile](ctx, d, d.query, OpListSettingsProfiles, `SELECT name, storage, apply_to_all, apply_to_list, apply_to_except
FROM system.settings_profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for _, p := range rows {
		if p.Name == "" || p.ApplyToList == nil || p.ApplyToExcept == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListSettingsProfiles, "lists a profile with no name or no apply_to lists"))
		}
	}
	return rows, nil
}

// SettingsProfileElements lists what each settings profile, user, and role
// sets, with where the server keeps each profile and user.
func (d *Database) SettingsProfileElements(ctx context.Context) ([]SettingsProfileElement, error) {
	rows, resp, err := query[SettingsProfileElement](ctx, d, d.query, OpListSettingsProfileElements, `SELECT e.profile_name, e.user_name, e.role_name, e.setting_name, e.value, e.min, e.max, toString(e.writability) AS writability, e.inherit_profile,
	p.storage AS profile_storage, u.storage AS user_storage
FROM system.settings_profile_elements AS e
LEFT JOIN system.settings_profiles AS p ON p.name = e.profile_name
LEFT JOIN system.users AS u ON u.name = e.user_name
ORDER BY e.profile_name, e.user_name, e.role_name, e.index`)
	if err != nil {
		return nil, err
	}
	for _, e := range rows {
		owners := 0
		for _, name := range []*string{e.ProfileName, e.UserName, e.RoleName} {
			if name != nil {
				owners++
			}
		}
		if owners != 1 {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListSettingsProfileElements, "lists an element with no single profile, user, or role"))
		}
	}
	return rows, nil
}

// Quotas lists the quotas.
func (d *Database) Quotas(ctx context.Context) ([]Quota, error) {
	rows, resp, err := query[Quota](ctx, d, d.query, OpListQuotas, `SELECT name, storage, arrayMap(k -> toString(k), keys) AS keys, durations, apply_to_all, apply_to_list, apply_to_except
FROM system.quotas ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for _, q := range rows {
		if q.Name == "" || q.Keys == nil || q.Durations == nil || q.ApplyToList == nil || q.ApplyToExcept == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListQuotas, "lists a quota with missing columns"))
		}
	}
	return rows, nil
}

// QuotaLimits lists each quota's limits for each of its intervals, with
// where the server keeps the quota.
func (d *Database) QuotaLimits(ctx context.Context) ([]QuotaLimit, error) {
	rows, resp, err := query[QuotaLimit](ctx, d, d.query, OpListQuotaLimits, `SELECT l.*, q.storage AS quota_storage
FROM system.quota_limits AS l LEFT JOIN system.quotas AS q ON q.name = l.quota_name
ORDER BY l.quota_name, l.duration`)
	if err != nil {
		return nil, err
	}
	for _, q := range rows {
		if q.QuotaName == "" {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListQuotaLimits, "lists a limit with no quota"))
		}
	}
	return rows, nil
}

// RowPolicies lists the row policies.
func (d *Database) RowPolicies(ctx context.Context) ([]RowPolicy, error) {
	rows, resp, err := query[RowPolicy](ctx, d, d.query, OpListRowPolicies, `SELECT name, short_name, database, table, storage, is_restrictive, apply_to_all, apply_to_list, apply_to_except
FROM system.row_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for _, p := range rows {
		if p.Name == "" || p.ApplyToList == nil || p.ApplyToExcept == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(OpListRowPolicies, "lists a policy with no name or no apply_to lists"))
		}
	}
	return rows, nil
}

// query sends one SELECT, named op, over the service's HTTPS interface and
// decodes its FORMAT JSON result. wait_end_of_query makes the server finish
// the query before it answers, so a failure arrives as an error status
// rather than after a 200. It is a parameter of the HTTP interface, not a
// setting, so a readonly user may send it.
func query[T any](ctx context.Context, d *Database, client *http.Client, op, sql string) ([]T, *http.Response, error) {
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op, Safe: true})
	endpoint := "https://" + net.JoinHostPort(d.host, DatabasePort) + "/?wait_end_of_query=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(sql+"\nFORMAT JSON"))
	if err != nil {
		return nil, nil, err
	}
	req.SetBasicAuth(d.user, d.password)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return nil, resp, componentsdk.ResponseError(resp, newDatabaseError(resp, body))
	}
	var result struct {
		Data      []T    `json:"data"`
		Rows      *int   `json:"rows"`
		Exception string `json:"exception"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&result); err != nil {
		return nil, resp, componentsdk.ResponseError(resp, fmt.Errorf("%s: decoding the response: %w", op, err))
	}
	switch {
	case result.Exception != "":
		return nil, resp, componentsdk.ResponseError(resp, componentsdk.CodeError(componentsdk.CodeVendorError, fmt.Errorf("%s: the query failed after it started: %s", op, firstLine(result.Exception))))
	case result.Data == nil || result.Rows == nil:
		return nil, resp, componentsdk.ResponseError(resp, invalidResponse(op, "has no data or rows"))
	case *result.Rows != len(result.Data):
		return nil, resp, componentsdk.ResponseError(resp, invalidResponse(op, fmt.Sprintf("says %d rows and holds %d", *result.Rows, len(result.Data))))
	}
	return result.Data, resp, nil
}

// DatabaseError is a service's answer to a query with a status other than
// 200. ClickHouse sends its exception's code in X-ClickHouse-Exception-Code
// and its message in the body.
type DatabaseError struct {
	StatusCode int
	// Code is ClickHouse's exception code, such as 497, or 0 when the
	// response carries none.
	Code int
	// Name is the exception's name, such as ACCESS_DENIED.
	Name    string
	Message string
	Header  http.Header
}

func newDatabaseError(resp *http.Response, body []byte) *DatabaseError {
	e := &DatabaseError{StatusCode: resp.StatusCode, Message: firstLine(string(body)), Header: resp.Header}
	e.Code, _ = strconv.Atoi(resp.Header.Get("X-ClickHouse-Exception-Code"))
	e.Name = exceptionName(body)
	return e
}

func (e *DatabaseError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the service returned status %d", e.StatusCode)
	}
	return fmt.Sprintf("the service returned status %d: %s", e.StatusCode, e.Message)
}

// HTTPStatus and HTTPHeader let componentsdk.Classify give the error a code
// when its exception code does not.
func (e *DatabaseError) HTTPStatus() int         { return e.StatusCode }
func (e *DatabaseError) HTTPHeader() http.Header { return e.Header }

// VendorCode is the exception's name, or its number when the body names
// none.
func (e *DatabaseError) VendorCode() string {
	if e.Name != "" {
		return e.Name
	}
	if e.Code != 0 {
		return strconv.Itoa(e.Code)
	}
	return ""
}

// CollectionCode reads the exception code. ClickHouse answers a rejected
// password and a missing grant both with a 403, so the status alone cannot
// tell them apart.
func (e *DatabaseError) CollectionCode() componentsdk.Code {
	return exceptionCode(e.Code)
}

// ClickHouse exception codes the collector reads.
const (
	exceptionNoSuchColumn        = 16
	exceptionUnknownFunction     = 46
	exceptionUnknownIdentifier   = 47
	exceptionUnknownTable        = 60
	exceptionSyntaxError         = 62
	exceptionTimeoutExceeded     = 159
	exceptionUnknownUser         = 192
	exceptionWrongPassword       = 193
	exceptionRequiredPassword    = 194
	exceptionIPAddressNotAllowed = 195
	exceptionQuotaExceeded       = 201
	exceptionTooManyQueries      = 202
	exceptionAccessDenied        = 497
	exceptionAuthFailed          = 516
)

// exceptionCode is the collection code for a ClickHouse exception code, or
// "" when the status should decide.
func exceptionCode(code int) componentsdk.Code {
	switch code {
	case exceptionUnknownUser, exceptionWrongPassword, exceptionRequiredPassword, exceptionAuthFailed:
		return componentsdk.CodeAuthFailed
	case exceptionAccessDenied, exceptionIPAddressNotAllowed:
		return componentsdk.CodePermissionDenied
	case exceptionQuotaExceeded, exceptionTooManyQueries:
		return componentsdk.CodeRateLimited
	case exceptionTimeoutExceeded:
		return componentsdk.CodeTimeout
	case exceptionNoSuchColumn, exceptionUnknownFunction, exceptionUnknownIdentifier, exceptionUnknownTable, exceptionSyntaxError:
		return componentsdk.CodeInvalidResponse
	}
	return ""
}

// DatabaseClassify gives a failed query's response its code from its
// exception code, for componentsdk.HTTPOptions.ClassifyResponse, so a
// rejected password is not counted as a missing grant and a query the
// server refuses as unknown is not retried.
func DatabaseClassify(resp *http.Response, _ []byte) (componentsdk.Code, bool) {
	code, err := strconv.Atoi(resp.Header.Get("X-ClickHouse-Exception-Code"))
	if err != nil {
		return "", false
	}
	c := exceptionCode(code)
	return c, c != ""
}

// DatabaseVendorCode reads the exception's name from a failed query's body,
// or its number from the response's header, for
// componentsdk.HTTPOptions.VendorCode.
func DatabaseVendorCode(resp *http.Response, body []byte) string {
	if name := exceptionName(body); name != "" {
		return name
	}
	return resp.Header.Get("X-ClickHouse-Exception-Code")
}

var exceptionNamePattern = regexp.MustCompile(`\(([A-Z][A-Z0-9_]{2,63})\)`)

// exceptionName reads the name ClickHouse puts in parentheses after an
// exception's message, such as ACCESS_DENIED.
func exceptionName(body []byte) string {
	matches := exceptionNamePattern.FindAllSubmatch(body, -1)
	if len(matches) == 0 {
		return ""
	}
	return string(matches[len(matches)-1][1])
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
