package collector

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/locktivity/epack-collector-clickhouse/internal/clickhouse"
)

func TestParseConfig(t *testing.T) {
	cfg, err := ParseConfig(map[string]any{
		"organization_id": strings.ToUpper(kitOrgID),
		"services": []any{
			map[string]any{"host": "KIT0SERVICE1.us-east-1.aws.clickhouse.cloud."},
			map[string]any{"host": "other.eu-west-1.aws.clickhouse.cloud", "user": "auditor"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Config{OrganizationID: kitOrgID, Services: []ServiceConfig{
		{Host: kitHost, User: defaultDatabaseUser},
		{Host: "other.eu-west-1.aws.clickhouse.cloud", User: "auditor"},
	}}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("parsed %+v, want %+v", cfg, want)
	}

	cfg, err = ParseConfig(map[string]any{"organization_id": kitOrgID})
	if err != nil || len(cfg.Services) != 0 {
		t.Errorf("with no services: %+v, %v", cfg, err)
	}
}

func TestParseConfigRejectsHostsThatAreNotNames(t *testing.T) {
	for _, host := range []string{"https://" + kitHost, kitHost + ":8443", kitHost + "/", "localhost", "", "bad_label.clickhouse.cloud"} {
		_, err := ParseConfig(map[string]any{"organization_id": kitOrgID, "services": []any{map[string]any{"host": host}}})
		if err == nil {
			t.Errorf("host %q was accepted", host)
		}
	}
}

func TestSignInErrorSaysWhatToFix(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"refused address": {&clickhouse.APIError{StatusCode: http.StatusForbidden, Message: "FORBIDDEN: IP address not allowed"}, "refused the API key from this runner's address"},
		"rejected key":    {&clickhouse.APIError{StatusCode: http.StatusUnauthorized, Message: "Unauthorized"}, "Check CLICKHOUSE_KEY_ID and CLICKHOUSE_KEY_SECRET"},
		"missing role":    {&clickhouse.APIError{StatusCode: http.StatusForbidden, Message: "FORBIDDEN: no access"}, "control-plane:organization:view"},
	}
	for name, tc := range cases {
		if got := signInError(tc.err).Error(); !strings.Contains(got, tc.want) || !errors.Is(signInError(tc.err), tc.err) {
			t.Errorf("%s: %q does not say %q", name, got, tc.want)
		}
	}
}

func TestReachWarning(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	cases := map[string]struct {
		err  error
		want string
	}{
		"connection reset":  {reset, "IP access list"},
		"host not found":    {&net.DNSError{Err: "no such host", Name: kitHost, IsNotFound: true}, "host could not be found"},
		"deadline":          {context.DeadlineExceeded, "minute or more to start"},
		"password rejected": {&clickhouse.DatabaseError{StatusCode: 403, Code: 516}, "rejected the password for epack_collector"},
		"host refused":      {&clickhouse.DatabaseError{StatusCode: 403, Code: 195}, "HOST setting"},
	}
	for name, tc := range cases {
		if got := reachWarning(tc.err, defaultDatabaseUser); !strings.Contains(got, tc.want) {
			t.Errorf("%s: %q does not say %q", name, got, tc.want)
		}
	}
}
