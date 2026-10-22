package clickhouse

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestAPIVendorCode(t *testing.T) {
	for body, want := range map[string]string{
		`{"status": 403, "error": "FORBIDDEN: IP address not allowed", "requestId": "r"}`: "FORBIDDEN",
		`{"status": 404, "error": "NOT_FOUND: Organization not found"}`:                   "NOT_FOUND",
		`{"status": 403, "error": "FORBIDDEN", "requestId": "r"}`:                         "FORBIDDEN",
		`{"status": 401, "error": "Unauthorized"}`:                                        "",
		`{"error": {"code": "x"}}`:                                                        "",
		`<html>Bad Gateway</html>`:                                                        "",
	} {
		if got := APIVendorCode(nil, []byte(body)); got != want {
			t.Errorf("APIVendorCode(%s) = %q, want %q", body, got, want)
		}
	}
}

func TestAPIErrorIPNotAllowed(t *testing.T) {
	refused := &APIError{StatusCode: http.StatusForbidden, Message: apiErrorMessage([]byte(`{"status": 403, "error": "FORBIDDEN: IP address not allowed"}`))}
	if !refused.IPNotAllowed() {
		t.Errorf("%v is not read as a refused address", refused)
	}
	denied := &APIError{StatusCode: http.StatusForbidden, Message: "FORBIDDEN: The API key does not have the required permissions"}
	if denied.IPNotAllowed() {
		t.Errorf("%v is read as a refused address", denied)
	}
}

// TestDatabaseErrorCodes checks that the exception code, not the status,
// decides the code: ClickHouse answers a rejected password and a missing
// grant both with a 403.
func TestDatabaseErrorCodes(t *testing.T) {
	cases := []struct {
		status    int
		exception string
		body      string
		code      componentsdk.Code
		vendor    string
	}{
		{403, "516", "Code: 516. DB::Exception: epack_collector: Authentication failed: password is incorrect, or there is no user with such name. (AUTHENTICATION_FAILED)", componentsdk.CodeAuthFailed, "AUTHENTICATION_FAILED"},
		{403, "497", "Code: 497. DB::Exception: epack_collector: Not enough privileges. To execute this query, it's necessary to have the grant SHOW USERS ON *.*. (ACCESS_DENIED) (version 26.8.33.10 (official build))", componentsdk.CodePermissionDenied, "ACCESS_DENIED"},
		{404, "47", "Code: 47. DB::Exception: Unknown expression identifier `valid_until` in scope SELECT. (UNKNOWN_IDENTIFIER) (version 25.8.1.1 (official build))", componentsdk.CodeInvalidResponse, "UNKNOWN_IDENTIFIER"},
		{500, "202", "Code: 202. DB::Exception: Too many simultaneous queries. (TOO_MANY_SIMULTANEOUS_QUERIES)", componentsdk.CodeRateLimited, "TOO_MANY_SIMULTANEOUS_QUERIES"},
		{500, "159", "Code: 159. DB::Exception: Timeout exceeded. (TIMEOUT_EXCEEDED)", componentsdk.CodeTimeout, "TIMEOUT_EXCEEDED"},
		{500, "241", "Code: 241. DB::Exception: Memory limit exceeded. (MEMORY_LIMIT_EXCEEDED)", componentsdk.CodeVendorError, "MEMORY_LIMIT_EXCEEDED"},
		{503, "", "upstream connect error", componentsdk.CodeVendorError, ""},
	}
	for _, tc := range cases {
		resp := &http.Response{StatusCode: tc.status, Header: http.Header{}}
		if tc.exception != "" {
			resp.Header.Set("X-ClickHouse-Exception-Code", tc.exception)
		}
		err := newDatabaseError(resp, []byte(tc.body))
		if got := componentsdk.Classify(err); got != tc.code {
			t.Errorf("status %d, exception %q: code %s, want %s", tc.status, tc.exception, got, tc.code)
		}
		if got := DatabaseVendorCode(resp, []byte(tc.body)); got != tc.vendor {
			t.Errorf("status %d, exception %q: vendor code %q, want %q", tc.status, tc.exception, got, tc.vendor)
		}
		classified, ok := DatabaseClassify(resp, nil)
		if want := tc.code != componentsdk.CodeVendorError; ok != want || ok && classified != tc.code {
			t.Errorf("status %d, exception %q: DatabaseClassify = %s, %t", tc.status, tc.exception, classified, ok)
		}
	}
}

func TestQuotaLimitDecodesEveryLimit(t *testing.T) {
	var q QuotaLimit
	row := `{"quota_name": "reader_quota", "duration": 3600, "is_randomized_interval": 1, "max_queries": "1000",
		"max_execution_time": 2.5, "max_errors": null, "max_failed_sequential_authentications": "5"}`
	if err := json.Unmarshal([]byte(row), &q); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(q.Limits)
	if want := `{"execution_time":2.5,"failed_sequential_authentications":5,"queries":1000}`; string(got) != want {
		t.Errorf("limits %s, want %s", got, want)
	}
	if q.QuotaName != "reader_quota" || q.Duration != 3600 || !q.IsRandomizedInterval {
		t.Errorf("read %+v", q)
	}
	if err := json.Unmarshal([]byte(`{"quota_name": "q", "duration": 60, "is_randomized_interval": 0, "max_queries": "lots"}`), &q); err == nil {
		t.Error("a limit that is not a number was read")
	}
}

func TestFlagReadsOnlyZeroOrOne(t *testing.T) {
	var f Flag
	for raw, want := range map[string]bool{"0": false, "1": true, "false": false, "true": true} {
		if err := json.Unmarshal([]byte(raw), &f); err != nil || bool(f) != want {
			t.Errorf("%s read as %v, %v", raw, f, err)
		}
	}
	if err := json.Unmarshal([]byte("2"), &f); err == nil {
		t.Error("2 was read as a flag")
	}
}
