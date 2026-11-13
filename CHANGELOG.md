# Changelog

## Unreleased

- The Not Collected section of `docs/overview.md` is rendered from `docs/surface.yaml`, which gives a verdict to every read operation of the ClickHouse Cloud API description that the collector's recordings never call, so the list comes from ClickHouse's description rather than from memory. A new `docs/coverage.md` lists what the collector reads, by area, every operation it leaves out with the reason, and the SQL queries to each service that the Cloud API description does not cover.

## v0.2.4

- A service's answer is left out with an `invalid_response` gap when a row doesn't hold exactly the columns its `meta` lists, or holds null in a column that isn't Nullable. Through v0.2.3 a row with no `storage` or `user_storage` counted as the customer's, and a missing flag such as `grant_option` or `with_admin_option` read as false.
- The API keys are left out with an `invalid_response` gap when a key has no `createdAt`, or a `createdAt`, `expireAt` or `usedAt` that isn't an RFC 3339 time. Through v0.2.3 such a key left out only the unused and rotation overdue values, with a `partial` gap that named no call. An empty list of keys is a `permission_denied` gap, since the key the collector signs in with is always listed. Through v0.2.3 it counted as no keys.
- The members, invitations, and API keys are left out with an `invalid_response` gap when one of their console roles has no ID, name, or type, or an IP access list entry has no source. So are the members when none holds the system Admin role, and the console roles when one has no `actors` list. Through v0.2.3 these read as holding no Admin role and as no members or keys.

## v0.2.3

- In the access file, an API key has write access when it holds the system Admin role, or console roles that would make a member who held them an admin, such as a custom role that allows `control-plane:organization:manage`. Only the system Admin role counted before. When the console roles can't be read, `write_access_credential_count` and `write_access_pct` are left out with a `partial` gap. A key is still unrestricted only with the system Admin role.
- The collector is built on epack v0.11.3.

## v0.2.2

- In the access file, a member counts as an admin when they can change who has access to the organization, or change or delete every service. That is a member with the system Admin role, or one whose console roles allow `control-plane:organization:manage` on the organization, `control-plane:service:manage` or `control-plane:service:delete` on every service, or `control-plane:postgres-service:manage` on every Postgres service, with no DENY policy on the same permission and resources. A member with the Service Admin role, or a custom role with these permissions, now counts. The detailed artifact's `members.admin_count` still counts the system Admin role only.
- A run that writes the access file reads the console roles even when `collect` lists only `access-posture`. When they can't be read, `admin_count` and `admin_share_pct` are left out with a `partial` gap, and so is `admins_present` when no member holds the system Admin role.
- The collector is built on Go 1.26.11.

## v0.2.1

- The collector is built on epack v0.10.5.
- `organization.id` and each service's `host` in `artifacts/clickhouse.details.json` are written from the audit level. A ClickHouse Cloud service host is a private endpoint, so a trust run identifies each service by its position in `services`. The schema marks both `audit` and keeps them required for the runs that write them.
- The collector result's `targets` says what the run was pointed at: the organization, chosen by `organization_id`, at `organization` in `artifacts/clickhouse.details.json`, and the services `services` lists, at `services`. A service the run could not reach marks the services incomplete.

## v0.2.0

- The collector is built on epack v0.10.0. The detailed artifact moves from `artifacts/clickhouse.json` to `artifacts/clickhouse.details.json`, the path epack's `ArtifactPath` gives it. A reader of the old path needs the new one
- A new file, `artifacts/clickhouse.access-posture.json`, holds the console's members, admins, and API keys as `evidencepack/access-posture@v1`. `collect` lists it as `access-posture`, and the build file and `--capabilities` list its schema ID. It is built from the members and API keys the collector already reads, so the API key needs no new permission.
- The access-posture file's admins are the members who hold the system Admin role. Its credentials are the API keys that are enabled and have not expired. A disabled key or a key past its expiry date is left out. Its counts can then be lower than the detailed artifact's, which count every key.
- A key in the access-posture file is unrestricted when it holds the Admin role and its IP access list admits any address. A key with another role or a narrower IP access list is restricted, so `unrestricted_credential_count` can be lower than the detailed artifact's `any_address_count`.
- The access-posture file leaves out each value ClickHouse Cloud does not report, such as its sign-in rules and admin MFA. Each has an `unsupported` gap, which does not make the run partial. `docs/overview.md` lists them.
- The access-posture file leaves out inactive members with a `not_read` gap, which does not make the run partial either. ClickHouse Cloud's activities list reports member sign-ins, and reading it needs `control-plane:organization:view-activities`.
- `organization.sso_enabled` and `members.mfa_enabled_count` now have an `unsupported` gap. It was `not_licensed` before, which made every run partial. A run with no other gaps is now `collected`.
- With `collect: [access-posture]`, only the organization, the members, and the API keys are read.
- The collector result lists the permission each Cloud API call needs, such as `control-plane:organization:view-api-keys` for the API keys. A `permission_denied` gap from a call names that permission. A gap for a call refused from the runner's address names no permission, since adding the address to the key's IP access list fixes it.
