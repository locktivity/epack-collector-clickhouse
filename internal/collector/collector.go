package collector

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

// collect signs in to the Cloud API, then reads the console and each
// service, each part in a step of its own, which the collector result lists
// with its calls. It fails only when the sign-in fails. A value it cannot
// read after that is left out of the output with a gap, never written as
// zero or false.
func collect(ctx componentsdk.CollectorContext, cfg Config, cloud *clickhouse.Cloud, databases []*clickhouse.Database) (*Output, error) {
	signIn, step := componentsdk.StartCollectorStep(ctx, "sign_in", "Sign in")
	org, err := cloud.GetOrganization(signIn.Context())
	step.End()
	if err != nil {
		return nil, signInError(err)
	}
	rec := componentsdk.Records(ctx)
	rec.SignedInAs(componentsdk.Principal{
		Provider:   "clickhouse",
		Kind:       "api_key",
		TenantID:   org.ID,
		AuthMethod: componentsdk.AuthAPIToken,
	})
	gaps := gapLog{rec: rec}

	now := componentsdk.Now(ctx).UTC()
	out := &Output{
		SchemaVersion:    SchemaVersion,
		CollectedAt:      now.Format(time.RFC3339),
		CollectedAtLevel: string(ctx.Level()),
		Organization:     Organization{ID: org.ID, Name: org.Name, CreatedAt: timestamp(org.CreatedAt)},
		Services:         []Service{},
	}
	gaps.noAPI("/organization/sso_enabled", "ClickHouse Cloud has no API that reports whether the organization signs members in with SAML SSO.")

	people, step := componentsdk.StartCollectorStep(ctx, "members", "Members and invitations")
	out.Members = readMembers(people, cloud, gaps)
	out.Invitations = readInvitations(people, cloud, gaps, now)
	step.End()

	keys, step := componentsdk.StartCollectorStep(ctx, "api_keys", "API keys")
	out.APIKeys = readAPIKeys(keys, cloud, gaps)
	step.End()

	roles, step := componentsdk.StartCollectorStep(ctx, "console_roles", "Console roles")
	out.ConsoleRoles = readConsoleRoles(roles, cloud, gaps)
	step.End()

	if len(databases) > 0 {
		dbs, step := componentsdk.StartCollectorStep(ctx, "databases", "Database access")
		for i, db := range databases {
			dbs.Progress(int64(i+1), int64(len(databases)), fmt.Sprintf("Reading service %d of %d", i+1, len(databases)))
			out.Services = append(out.Services, readService(dbs, db, gaps, i, cfg.Services[i]))
		}
		step.End()
	}
	return out, nil
}

// signInError says what to fix when the sign-in fails. The SDK gives the
// error its exit code: 3 for a rejected key or a refused address, 2 for an
// organization that does not exist.
func signInError(err error) error {
	var apiErr *clickhouse.APIError
	if errors.As(err, &apiErr) {
		switch {
		case apiErr.IPNotAllowed():
			return fmt.Errorf("signing in: ClickHouse Cloud refused the API key from this runner's address. Add the address to the key's IP access list. A key created through the API with no IP access list cannot be used from any address: %w", err)
		case apiErr.StatusCode == http.StatusUnauthorized:
			return fmt.Errorf("signing in: ClickHouse Cloud rejected the API key. Check %s and %s: %w", keyIDEnv, keySecretEnv, err)
		case apiErr.StatusCode == http.StatusForbidden:
			return fmt.Errorf("signing in: the API key cannot read the organization. Its role needs %s in this organization: %w", clickhouse.PermissionViewOrganization, err)
		}
	}
	return fmt.Errorf("signing in: %w", err)
}

// timestamp rewrites an ISO 8601 time from the Cloud API in RFC 3339 at
// second precision in UTC, or returns nil when the API sent none.
func timestamp(raw string) *string {
	if raw == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return &raw
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}
