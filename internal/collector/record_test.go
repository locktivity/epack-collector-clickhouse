//go:build record

package collector

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

// TestRecord records a sandbox, a ClickHouse Cloud organization kept with
// known settings, to testdata/recordings/clickhouse.json for the
// collectortest suite. It reads the organization's ID, the service's host,
// and the mailbox the members' addresses are made from in
// SANDBOX_CLICKHOUSE_ORG_ID, SANDBOX_CLICKHOUSE_SERVICE_HOST, and
// SANDBOX_CLICKHOUSE_MAILBOX, and the credentials in CLICKHOUSE_KEY_ID,
// CLICKHOUSE_KEY_SECRET, and CLICKHOUSE_DB_PASSWORD, and skips when any is
// not set. The recording names the organization and the service by the
// kit's IDs, and each member by its plus tag on kit@example.com. The value
// of any other SANDBOX_ variable becomes a stable fake, and Record writes
// nothing if one remains:
//
//	SANDBOX_CLICKHOUSE_ORG_ID=... SANDBOX_CLICKHOUSE_SERVICE_HOST=... SANDBOX_CLICKHOUSE_MAILBOX=... \
//	CLICKHOUSE_KEY_ID=... CLICKHOUSE_KEY_SECRET=... CLICKHOUSE_DB_PASSWORD=... \
//	go test -tags record -run 'TestRecord/^clickhouse$' -count=1 ./internal/collector/
func TestRecord(t *testing.T) {
	t.Run("clickhouse", func(t *testing.T) {
		orgID := os.Getenv("SANDBOX_CLICKHOUSE_ORG_ID")
		host := os.Getenv("SANDBOX_CLICKHOUSE_SERVICE_HOST")
		mailbox := os.Getenv("SANDBOX_CLICKHOUSE_MAILBOX")
		secrets := map[string]string{
			keyIDEnv:      os.Getenv(keyIDEnv),
			keySecretEnv:  os.Getenv(keySecretEnv),
			dbPasswordEnv: os.Getenv(dbPasswordEnv),
		}
		if orgID == "" || host == "" || mailbox == "" || secrets[keyIDEnv] == "" || secrets[keySecretEnv] == "" || secrets[dbPasswordEnv] == "" {
			t.Skip("set SANDBOX_CLICKHOUSE_ORG_ID, SANDBOX_CLICKHOUSE_SERVICE_HOST, SANDBOX_CLICKHOUSE_MAILBOX, " +
				keyIDEnv + ", " + keySecretEnv + ", and " + dbPasswordEnv + " to record")
		}
		identifiers := collectortest.EnvIdentifiers("SANDBOX_", map[string]string{
			"SANDBOX_CLICKHOUSE_ORG_ID":       kitOrgID,
			"SANDBOX_CLICKHOUSE_SERVICE_HOST": kitHost,
			"SANDBOX_CLICKHOUSE_MAILBOX":      "kit@example.com",
		})
		// The members' addresses are plus addresses on the mailbox, such as
		// name+ch-reader@example.com, which hold its local part and its domain
		// but never the whole mailbox.
		local, domain, ok := strings.Cut(mailbox, "@")
		if !ok || len(local) < 4 || len(domain) < 4 {
			t.Fatal("SANDBOX_CLICKHOUSE_MAILBOX must be an address whose local part and domain each have at least four characters, so they can be scrubbed")
		}
		identifiers[local] = "kit"
		identifiers[domain] = "example.com"
		// The host's first label names the service on its own.
		label, _, _ := strings.Cut(host, ".")
		identifiers[label] = strings.Split(kitHost, ".")[0]
		addNames(t, identifiers, orgID, secrets)

		var keep []string
		for _, tag := range []string{"ch-owner", "ch-reader", "ch-auditor", "ch-billing", "ch-pending"} {
			keep = append(keep, "kit+"+tag+"@example.com")
		}
		report, err := collectortest.Record(collectortest.RecordOptions{
			Spec: Spec("record", "collectortest"),
			Run:  Run,
			Config: map[string]any{
				"organization_id": orgID,
				"services":        []any{map[string]any{"host": host, "user": defaultDatabaseUser}},
				"level":           "audit",
			},
			Secrets: secrets,
			Out:     "testdata/recordings/clickhouse.json",
			Scrub:   collectortest.ScrubRules{Identifiers: identifiers, Patterns: recordScrubPatterns, Keep: keep},
		})
		if err != nil {
			t.Fatal(err)
		}
		if report.ExitCode != 0 {
			t.Errorf("the recorded run exited %d: %+v", report.ExitCode, report.Failure)
		}
		t.Logf("recorded %d responses", report.Responses)
	})
}

// kitUserID is the nth fake member user ID. ClickHouse Cloud's user IDs are
// 24 hex digits.
func kitUserID(n int) string { return fmt.Sprintf("%024x", n) }

// addNames adds the organization's name, and each member's name and user
// ID, to identifiers, read with the collector's own API key before the
// recorded run, since nothing in the environment holds them. A user ID gets
// a fake of the same form, 24 hex digits.
func addNames(t *testing.T, identifiers map[string]string, orgID string, secrets map[string]string) {
	t.Helper()
	cloud := clickhouse.NewCloud(http.DefaultClient, orgID, secrets[keyIDEnv], secrets[keySecretEnv])
	ctx := context.Background()
	org, err := cloud.GetOrganization(ctx)
	if err != nil {
		t.Fatalf("reading the organization's name: %v", err)
	}
	// A key without control-plane:organization:manage sees no members, and
	// the recording then holds none of their names.
	members, err := cloud.ListMembers(ctx)
	if err != nil && componentsdk.Classify(err) != componentsdk.CodePermissionDenied {
		t.Fatalf("reading the members' names: %v", err)
	}
	names := map[string]string{org.Name: "Kit Org"}
	for i, m := range members {
		if m.Name != "" {
			names[m.Name] = "Kit Member"
		}
		identifiers[m.UserID] = kitUserID(i + 1)
	}
	for name, fake := range names {
		if len(name) < 4 {
			t.Fatal("the organization or a member has a name shorter than four characters, too short to scrub safely; rename it in the console")
		}
		identifiers[name] = fake
	}
}
