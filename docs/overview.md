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

## Not Collected

ClickHouse Cloud offers the following through its API, and the collector does not read them.

- **Service settings and backups.** Each service's IP access list, private endpoints, JWT providers and server settings as the Cloud API describes them, whether it encrypts with a customer-managed key, which ClickHouse Cloud offers on the Enterprise plan, and its backup and snapshot configuration. The collector reads the organization's members, roles, API keys and invitations, and each configured service's database users, roles, grants, settings profiles, quotas and row policies through SQL. It writes no cloud-posture file.
- **Organization activity and exposed queries.** The organization's activity log, and the saved queries exposed as HTTP endpoints with the roles allowed to call them.
- **Other ClickHouse Cloud products.** ClickPipes ingestion pipelines, bring-your-own-cloud infrastructure, Postgres services and ClickStack, each a product beside the ClickHouse services the collector covers.

The coverage reference lists what the collector reads of the ClickHouse Cloud API, and everything else the API offers with why it is left out, checked against ClickHouse Cloud's published API description: https://github.com/locktivity/epack-collector-clickhouse/blob/main/docs/coverage.md

## What it never collects

- Passwords, password hashes, SSH keys, and API key secrets.
- Member names. A member appears by email, from the `audit` level.
- Row policy filter expressions, which can hold the customer's data.

## Access posture

`artifacts/clickhouse.access-posture.json` holds the console's members, admins, and API keys in the `evidencepack/access-posture@v1` form. Its admins are the members who can change who has access to the organization, or change or delete every service: those who hold the system Admin role, and those whose console roles allow `control-plane:organization:manage` on the organization, `control-plane:service:manage` or `control-plane:service:delete` on every service, or `control-plane:postgres-service:manage` on every Postgres service. When the console roles can't be read, the admin count and share are left out with a `partial` gap. Its credentials are the API keys that are enabled and have not expired.

- A key never expires when it has no expiry date.
- A key is unused when it was never used or was last used more than 90 days before the run.
- A key is unrestricted when it holds the Admin role and its IP access list admits any address. A key with another role or a narrower IP access list is restricted.
- A key has write access when it holds the Admin role, or console roles that would make a member who held them an admin. When the console roles can't be read, the write access count and share are left out with a `partial` gap.
- A key is overdue for rotation when it was created more than 90 days before the run.

## Values ClickHouse Cloud does not report

ClickHouse Cloud has no API that says whether the organization uses SAML SSO or whether a member signs in with MFA. The detailed artifact holds both as null, and the collector result records an `unsupported` gap for each.

The access-posture file leaves out these values, each with an `unsupported` gap:

- The sign-in rules for SSO, MFA, and SCIM.
- Members and admins who can sign in without SSO, and their MFA. ClickHouse Cloud keeps a person's SAML account apart from their password account, and the member list does not say which kind each member is.
- Members who sign in through SSO, and members from outside the organization. The member list marks neither.
- Root accounts, since an organization has none.
- Connected apps, since the Cloud API does not list them.

## Values the collector does not read

The access-posture file leaves out inactive members with a `not_read` gap. ClickHouse Cloud's activities list reports member sign-ins. Reading it needs `control-plane:organization:view-activities`, which is not among the permissions in [configuration.md](configuration.md#1-create-the-api-key). A `not_read` gap does not make the run partial.

## Artifacts

- `artifacts/clickhouse.details.json`, described by [docs/schema/v1.0.0.json](schema/v1.0.0.json).
- `artifacts/clickhouse.access-posture.json`, described by epack's `evidencepack/access-posture@v1` schema, with the collector's methods from [docs/schema/methods.json](schema/methods.json).
- `artifacts/clickhouse.collector-result.json`, which records each value left out and why, the run's steps, and its calls.

See [levels.md](levels.md) for what each collection level adds and [examples.md](examples.md) for sample output.
