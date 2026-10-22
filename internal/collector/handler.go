package collector

import (
	"time"

	"github.com/locktivity/epack/componentsdk"

	"github.com/locktivity/epack-collector-clickhouse/docs/schema"
	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

const (
	// artifactPath is where the collector's artifact sits in the pack.
	artifactPath = "artifacts/clickhouse.json"

	// The variables the credentials arrive in, which epack.yaml lists under
	// secrets: the Cloud API key's ID and secret, and the password of the
	// database user the collector reads each service as.
	keyIDEnv      = "CLICKHOUSE_KEY_ID"
	keySecretEnv  = "CLICKHOUSE_KEY_SECRET"
	dbPasswordEnv = "CLICKHOUSE_DB_PASSWORD"
)

// A service that has gone idle starts again when a query arrives, which can
// take a minute or more. The first query to each service gets attempts that
// wait longer and, together, at most wakeBudget.
const (
	wakeAttemptTimeout = 2 * time.Minute
	wakeMaxAttempts    = 20
	wakeBudget         = 3 * time.Minute
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        "clickhouse",
		Version:     version,
		Commit:      commit,
		Description: "Who can reach a ClickHouse Cloud organization: console members, invitations, and API keys, and each service's database users, roles, grants, settings profiles, quotas, and row policies.",
		Timeout:     10 * time.Minute,
		Schemas:     map[string][]byte{artifactPath: schema.Artifact},
		TraceMap:    schema.TraceMap,
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in to the Cloud API, and otherwise emits what it collected
// with a gap recorded for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	cfg, err := ParseConfig(ctx.Config())
	if err != nil {
		return componentsdk.NewConfigError("%w", err)
	}
	keyID, keySecret := ctx.Secret(keyIDEnv), ctx.Secret(keySecretEnv)
	if keyID == "" || keySecret == "" {
		return componentsdk.NewConfigError("%s and %s are required", keyIDEnv, keySecretEnv)
	}
	var password string
	if len(cfg.Services) > 0 {
		password = ctx.Secret(dbPasswordEnv)
		if password == "" {
			return componentsdk.NewConfigError("%s is required when services lists a service", dbPasswordEnv)
		}
	}

	api := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts: []string{clickhouse.APIHost},
		VendorCode:      clickhouse.APIVendorCode,
	})
	cloud := clickhouse.NewCloud(api, cfg.OrganizationID, keyID, keySecret)

	var databases []*clickhouse.Database
	if len(cfg.Services) > 0 {
		hosts := make([]string, len(cfg.Services))
		for i, s := range cfg.Services {
			hosts[i] = s.Host
		}
		queryOpts := componentsdk.HTTPOptions{
			CredentialHosts:  hosts,
			VendorCode:       clickhouse.DatabaseVendorCode,
			ClassifyResponse: clickhouse.DatabaseClassify,
		}
		wakeOpts := queryOpts
		wakeOpts.AttemptTimeout = wakeAttemptTimeout
		wakeOpts.MaxAttempts = wakeMaxAttempts
		query := componentsdk.NewHTTPClient(ctx, queryOpts)
		wake := componentsdk.NewHTTPClient(ctx, wakeOpts)
		for _, s := range cfg.Services {
			databases = append(databases, clickhouse.NewDatabase(query, wake, s.Host, s.User, password))
		}
	}

	output, err := collect(ctx, cfg, cloud, databases)
	if err != nil {
		return err
	}
	return ctx.Emit([]componentsdk.CollectedArtifact{
		componentsdk.JSONArtifact(artifactPath, output, componentsdk.ArtifactMeta{
			DisplayName: "ClickHouse Cloud access",
			Description: "Console members, invitations, and API keys, and each service's database users, roles, and grants",
		}),
	})
}
