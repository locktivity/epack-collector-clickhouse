package collector

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// defaultDatabaseUser is the database user a service is read as when its
// configuration names none.
const defaultDatabaseUser = "epack_collector"

// Config is the collector's configuration from epack.yaml. The SDK reads
// the level key itself, through componentsdk.CollectorContext.Level.
type Config struct {
	// OrganizationID is the ClickHouse Cloud organization to collect from.
	OrganizationID string
	// Services are the services whose database access settings the
	// collector reads, in the order the configuration lists them.
	Services []ServiceConfig
}

// ServiceConfig names one service and the database user to read it as.
type ServiceConfig struct {
	// Host is the service's HTTPS host, such as
	// abc123xyz.us-east-1.aws.clickhouse.cloud.
	Host string
	// User is the database user, epack_collector unless the configuration
	// names another.
	User string
}

var (
	organizationIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hostLabelPattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ParseConfig reads Config from the collector's config. A missing or
// malformed field is an error, which Run reports as a config error (exit 2).
func ParseConfig(raw map[string]any) (Config, error) {
	organizationID, ok := raw["organization_id"].(string)
	if !ok || !organizationIDPattern.MatchString(organizationID) {
		return Config{}, errors.New("organization_id must be the organization's ID, a UUID such as the one Organization details shows in the ClickHouse Cloud console")
	}
	cfg := Config{OrganizationID: strings.ToLower(organizationID)}

	rawServices, present := raw["services"]
	if !present || rawServices == nil {
		return cfg, nil
	}
	list, ok := rawServices.([]any)
	if !ok {
		return Config{}, errors.New("services must be a list of services, each with a host")
	}
	seen := map[string]bool{}
	for i, item := range list {
		entry, ok := item.(map[string]any)
		if !ok {
			return Config{}, fmt.Errorf("services[%d] must be a map with a host and, optionally, a user", i)
		}
		host, ok := entry["host"].(string)
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if !ok || !validHost(host) {
			return Config{}, fmt.Errorf("services[%d].host must be the service's host name alone, such as abc123xyz.us-east-1.aws.clickhouse.cloud, with no scheme, port, or path", i)
		}
		if seen[host] {
			return Config{}, fmt.Errorf("services[%d].host lists %s a second time", i, host)
		}
		seen[host] = true
		user := defaultDatabaseUser
		if rawUser, present := entry["user"]; present {
			name, ok := rawUser.(string)
			if !ok || strings.TrimSpace(name) == "" {
				return Config{}, fmt.Errorf("services[%d].user must be a database user's name", i)
			}
			user = name
		}
		for key := range entry {
			if key != "host" && key != "user" {
				return Config{}, fmt.Errorf("services[%d] has a key the collector does not know: %s", i, key)
			}
		}
		cfg.Services = append(cfg.Services, ServiceConfig{Host: host, User: user})
	}
	return cfg, nil
}

// validHost reports whether host is a DNS name of at least two labels.
func validHost(host string) bool {
	labels := strings.Split(host, ".")
	if len(host) > 253 || len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !hostLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
