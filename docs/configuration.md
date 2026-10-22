# Configuration

The collector reads the console through the ClickHouse Cloud API with an API key, and each service you list through its HTTPS interface as a database user.

## 1. Create the API key

The key's role decides what the collector reads from the console:

| Permissions on the organization | The collector reads |
|---------------------------------|---------------------|
| `control-plane:organization:view` and `control-plane:organization:view-api-keys` | The organization, its invitations, and its API keys |
| Both of those and `control-plane:organization:manage` | Also the members, their console roles, and what each console role grants |

`control-plane:organization:manage` also lets the key change the organization, including its members and their roles. Without it, the collector leaves the members and the role definitions out with a `permission_denied` gap. ClickHouse's [API reference](https://clickhouse.com/docs/products/cloud/api-reference/user-management/list-organization-members) says `control-plane:organization:view` is enough to list members, but the API returns an empty list without `control-plane:organization:manage`.

1. In the ClickHouse Cloud console, open your organization's **Users and roles**, select **Roles**, and select **Create new role**.
2. Name the role `epack-collector`, select **Allow**, and give it the permissions from the table.
3. Create an API key with only the `epack-collector` role. Add every address the collector runs from to the key's IP access list. If the role has `control-plane:organization:manage`, also give the key an expiry date.
4. Keep the key ID and the key secret for step 3.

A key created through the Cloud API with no IP access list cannot be used from any address.

## 2. Create the database user in each service

Skip this step to read only the console, and leave `services` out of the configuration.

Run these statements as the `default` user in each service the collector reads, with a password you generate in place of `YOUR-PASSWORD`. Use the same password in every service.

```sql
CREATE ROLE IF NOT EXISTS epack_access_reader;
GRANT CURRENT GRANTS(SHOW ACCESS ON *.*) TO epack_access_reader;
GRANT SELECT ON system.grants TO epack_access_reader;
GRANT SELECT ON system.role_grants TO epack_access_reader;
GRANT SELECT ON system.settings_profile_elements TO epack_access_reader;
GRANT SELECT ON system.quota_limits TO epack_access_reader;
CREATE USER IF NOT EXISTS epack_collector IDENTIFIED WITH sha256_password BY 'YOUR-PASSWORD' SETTINGS readonly = 1;
GRANT epack_access_reader TO epack_collector;
```

ClickHouse Cloud refuses `GRANT SHOW ACCESS ON *.*` from the `default` user. `GRANT CURRENT GRANTS` passes on the part of it the `default` user holds.

Add every address the collector runs from to each service's IP access list, under the service's **Settings**.

## 3. Configure epack

```yaml
collectors:
  clickhouse:
    source: locktivity/epack-collector-clickhouse@^0.1
    config:
      organization_id: 8c1f2a4e-5b6d-4e7f-9a0b-1c2d3e4f5a6b
      services:
        - host: abc123xyz.us-east-1.aws.clickhouse.cloud
      level: audit
    secrets:
      - CLICKHOUSE_KEY_ID
      - CLICKHOUSE_KEY_SECRET
      - CLICKHOUSE_DB_PASSWORD
```

```bash
export CLICKHOUSE_KEY_ID=YOUR-KEY-ID CLICKHOUSE_KEY_SECRET=YOUR-KEY-SECRET CLICKHOUSE_DB_PASSWORD=YOUR-PASSWORD
```

## Options

| Option | Required | Description |
|--------|----------|-------------|
| `organization_id` | Yes | The organization's ID, from **Organization details** in the console. |
| `services` | No | The services whose database access the collector reads. Each has a `host`, the service's HTTPS host name without `https://` or a port, and an optional `user`, which is `epack_collector` unless you set it. Leave `services` out to read only the console. |
| `level` | No | `trust` (the default), `audit`, or `internal`. See [levels.md](levels.md). |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CLICKHOUSE_KEY_ID` | The API key's ID. |
| `CLICKHOUSE_KEY_SECRET` | The API key's secret. |
| `CLICKHOUSE_DB_PASSWORD` | The database user's password. Required when `services` lists a service. |

## Idle Services

A service that has gone idle starts again when the collector's first query reaches it, which can take a minute or more. The collector waits up to three minutes for each service.

## Partial Collection and Exit Codes

The run fails only when the configuration is invalid (exit 2), when the Cloud API rejects the key or refuses its address (exit 3), or when the Cloud API cannot be reached (exit 4). Every other read that fails leaves its values out of `artifacts/clickhouse.json`, and `artifacts/clickhouse.collector-result.json` records a gap for each, with the call that failed and what to check.

Some values are left out every time their condition holds:

| Value | Code | When |
|-------|------|------|
| `members` | `permission_denied` | The key's role lacks `control-plane:organization:manage`. |
| `console_roles` | `permission_denied` | The key's role lacks `control-plane:organization:manage`. |
| `organization.sso_enabled` | `not_licensed` | Always. ClickHouse Cloud has no API that reports SAML SSO. |
| `members.mfa_enabled_count` | `not_licensed` | Whenever the members are read. ClickHouse Cloud has no API that reports a member's MFA. |
