# Changelog

## Unreleased

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
