## Basic Usage

Counts for the console and one service, at the default `trust` level:

```yaml
collectors:
  clickhouse:
    source: locktivity/epack-collector-clickhouse@^0.1
    config:
      organization_id: 8c1f2a4e-5b6d-4e7f-9a0b-1c2d3e4f5a6b
      services:
        - host: abc123xyz.us-east-1.aws.clickhouse.cloud
    secrets:
      - CLICKHOUSE_KEY_ID
      - CLICKHOUSE_KEY_SECRET
      - CLICKHOUSE_DB_PASSWORD
```

## With Inventories

At `audit`, for two services, the second read as a database user named `evidence_reader`:

```yaml
collectors:
  clickhouse:
    source: locktivity/epack-collector-clickhouse@^0.1
    config:
      organization_id: 8c1f2a4e-5b6d-4e7f-9a0b-1c2d3e4f5a6b
      services:
        - host: abc123xyz.us-east-1.aws.clickhouse.cloud
        - host: def456uvw.eu-west-1.aws.clickhouse.cloud
          user: evidence_reader
      level: audit
    secrets:
      - CLICKHOUSE_KEY_ID
      - CLICKHOUSE_KEY_SECRET
      - CLICKHOUSE_DB_PASSWORD
```

## Console Only

With no `services`, the collector reads only the Cloud API and needs no database password:

```yaml
collectors:
  clickhouse:
    source: locktivity/epack-collector-clickhouse@^0.1
    config:
      organization_id: 8c1f2a4e-5b6d-4e7f-9a0b-1c2d3e4f5a6b
    secrets:
      - CLICKHOUSE_KEY_ID
      - CLICKHOUSE_KEY_SECRET
```

## Example Output

With a key whose role has `control-plane:organization:manage`, at the `trust` level, `artifacts/clickhouse.json` holds:

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-10-22T12:00:00Z",
  "collected_at_level": "trust",
  "organization": {
    "id": "8c1f2a4e-5b6d-4e7f-9a0b-1c2d3e4f5a6b",
    "name": "Example Org",
    "created_at": "2026-10-21T13:58:12Z",
    "sso_enabled": null
  },
  "members": {"total_count": 4, "admin_count": 1, "mfa_enabled_count": null},
  "invitations": {"total_count": 2, "pending_count": 1, "expired_count": 1},
  "api_keys": {
    "total_count": 6,
    "enabled_count": 5,
    "admin_count": 1,
    "never_expires_count": 4,
    "any_address_count": 5,
    "never_used_count": 4
  },
  "console_roles": {"total_count": 4, "custom_count": 2},
  "services": [
    {
      "host": "abc123xyz.us-east-1.aws.clickhouse.cloud",
      "user": "epack_collector",
      "version": "26.8.1.2045",
      "users": {
        "customer_count": 9,
        "cloud_managed_count": 2,
        "no_password_count": 1,
        "plaintext_password_count": 1,
        "any_host_count": 7
      },
      "roles": {"customer_count": 3, "cloud_managed_count": 4},
      "role_grants": {"customer_count": 5, "cloud_managed_count": 2, "with_admin_option_count": 2},
      "grants": {"customer_count": 5, "cloud_managed_count": 3, "grant_option_count": 1},
      "settings_profiles": {"customer_count": 2, "cloud_managed_count": 1},
      "settings_profile_elements": {"customer_count": 4, "cloud_managed_count": 2},
      "quotas": {"customer_count": 1, "cloud_managed_count": 1},
      "quota_limits": {"customer_count": 1, "cloud_managed_count": 1},
      "row_policies": {"customer_count": 1, "cloud_managed_count": 0}
    }
  ]
}
```

`sso_enabled` and `mfa_enabled_count` are null because ClickHouse Cloud has no API that reports them, and `artifacts/clickhouse.collector-result.json` records a gap for each.

With a read-only key, `members` and `console_roles` are absent too, and the collector result records why:

```json
"gaps": [
  {
    "path": "artifacts/clickhouse.json",
    "pointer": "/console_roles",
    "status": "not_collected",
    "code": "permission_denied",
    "owner": "customer",
    "vendor_code": "FORBIDDEN",
    "operation": "clickhouse.roles.list",
    "call": 6,
    "missing_permission": "control-plane:organization:manage",
    "warning": "Reading console role definitions needs control-plane:organization:manage, which can also change the organization."
  },
  {
    "path": "artifacts/clickhouse.json",
    "pointer": "/members",
    "status": "not_collected",
    "code": "permission_denied",
    "owner": "customer",
    "operation": "clickhouse.members.list",
    "call": 2,
    "missing_permission": "control-plane:organization:manage",
    "warning": "Reading members needs control-plane:organization:manage, which can also change the organization."
  },
  {"path": "artifacts/clickhouse.json", "pointer": "/organization/sso_enabled", "status": "not_collected", "code": "not_licensed", "owner": "nobody"}
]
```

At `audit`, each count has its rows beside it. A database user's row:

```json
{
  "name": "ops_admin",
  "storage": "replicated",
  "auth_methods": [
    {"type": "sha256_password", "valid_until": "2030-01-01T00:00:00Z", "second_factor": null}
  ],
  "no_password": false,
  "plaintext_password": false,
  "host_ip": ["::/0"],
  "host_names": [],
  "host_names_regexp": [],
  "host_names_like": [],
  "any_host": true
}
```
