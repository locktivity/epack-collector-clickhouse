package collector

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitClusterHost replaces the Kubernetes host names ClickHouse Cloud's own
// database users may connect from, which name the service's instance.
const kitClusterHost = "c-kit-server-0.c-kit-server-headless.ns-kit.svc.cluster.local"

// recordScrubPatterns remove from a recording what a public repository must
// not hold: the last characters of each API key, which the Cloud API lists
// as keySuffix, and the internal host names of the service, which name its
// instance.
var recordScrubPatterns = []collectortest.ScrubPattern{
	{Pattern: regexp.MustCompile(`"keySuffix"\s*:\s*"(?:[^"\\]|\\.)*"`), Replace: `"keySuffix": "XXXX"`},
	{Pattern: clusterHost, Replace: kitClusterHost},
}

var (
	userID            = regexp.MustCompile(`\b[0-9a-f]{24}\b`)
	fakeUserID        = regexp.MustCompile(`^0{16}[0-9a-f]{8}$`)
	clusterHost       = regexp.MustCompile(`(?:[a-z0-9-]+\.)+svc\.cluster\.local`)
	recordedKeySuffix = regexp.MustCompile(`"keySuffix"\s*:\s*"((?:[^"\\]|\\.)*)"`)
	recordedEmail     = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	fakeEmail         = regexp.MustCompile(`^(kit\+ch-[a-z]+|user[0-9]+)@example\.com$`)
)

func TestRecordScrubPatterns(t *testing.T) {
	for in, want := range map[string]string{
		`{"id": "6f3a4b50-0000-4000-8000-000000000001", "name": "sandbox-admin", "keySuffix": "q9Zx"}`:                              `{"id": "6f3a4b50-0000-4000-8000-000000000001", "name": "sandbox-admin", "keySuffix": "XXXX"}`,
		`"host_names": ["localhost", "c-abcd-ef-12-server-x1y2z3a-0.c-abcd-ef-12-server-headless.ns-abcd-ef-12.svc.cluster.local"]`: `"host_names": ["localhost", "` + kitClusterHost + `"]`,
	} {
		got := in
		for _, p := range recordScrubPatterns {
			got = p.Pattern.ReplaceAllString(got, p.Replace)
		}
		if got != want {
			t.Errorf("scrubbed %s to %s, want %s", in, got, want)
		}
	}
}

// TestRecordingsScrubbed fails while a committed recording still holds a key
// suffix, a service's internal host name, a member's user ID, or an email
// address other than the kit's plus addresses and the recorder's fakes.
func TestRecordingsScrubbed(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "recordings", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range recordedKeySuffix.FindAllSubmatch(raw, -1) {
			if string(m[1]) != "XXXX" {
				t.Errorf("%s: a keySuffix is not scrubbed", path)
			}
		}
		for _, id := range userID.FindAll(raw, -1) {
			if !fakeUserID.Match(id) {
				t.Errorf("%s: holds a member's user ID", path)
			}
		}
		for _, host := range clusterHost.FindAll(raw, -1) {
			if string(host) != kitClusterHost {
				t.Errorf("%s: holds a service's internal host name", path)
			}
		}
		for _, email := range recordedEmail.FindAll(raw, -1) {
			if !fakeEmail.Match(email) {
				t.Errorf("%s: holds an email address that is not one of the kit's", path)
			}
		}
	}
}
