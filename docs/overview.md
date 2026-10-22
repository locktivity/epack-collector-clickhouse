epack-collector-clickhouse collects evidence of who can reach a ClickHouse Cloud organization and its data: the people and keys that can use the console and the Cloud API, and the database users, roles, and grants in each service.

## What it collects

From the Cloud API:

- **Members** and the console roles each one holds, with a count of those who hold Admin, when the key's role has `control-plane:organization:manage` (see [configuration.md](configuration.md#1-create-the-api-key)).
- **Invitations** that have not been accepted, pending or expired.
- **API keys**: each key's state, roles, expiry, IP access list, and when it was last used.
- **Console roles** and what each one grants, when the key's role has `control-plane:organization:manage`.

From each service you list, read with SQL over HTTPS as a read-only database user:

- **Database users**: each user's sign-in methods, when each one stops working, any second factor, and the addresses the user may connect from.
- **Roles**, the roles granted to users and to other roles, and every privilege granted.
- **Settings profiles** and what they set, **quotas** and their limits, and **row policies** and whom they apply to.

ClickHouse Cloud creates its own database users, roles, settings profiles, and quotas in every service. The collector lists them apart from the customer's, with the grants, settings, and limits that belong to them, and counts them separately. Cloud's own are the users, profiles, quotas, and row policies stored in `users_xml`, and the roles `clickpipes_system`, `default_role`, `sql_console_admin`, and `sql_console_read_only`. Cloud also creates the `default` and `sql-console` users, and they count as the customer's.

## What it never collects

- Passwords, password hashes, SSH keys, and API key secrets.
- Member names. A member appears by email, from the `audit` level.
- Row policy filter expressions, which can hold the customer's data.

## Values ClickHouse Cloud does not report

ClickHouse Cloud has no API that says whether the organization uses SAML SSO or whether a member signs in with MFA. The artifact holds both as null, and the collector result records a gap for each.

## Artifacts

- `artifacts/clickhouse.json`, described by [docs/schema/v1.0.0.json](schema/v1.0.0.json).
- `artifacts/clickhouse.collector-result.json`, which records each value left out and why, the run's steps, and its calls.

See [levels.md](levels.md) for what each collection level adds and [examples.md](examples.md) for sample output.
