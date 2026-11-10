# Collection Levels

The `level` config key sets how much detail the collector writes. The levels are cumulative: each one holds everything the level below it holds.

| Level | What `artifacts/clickhouse.details.json` holds |
|-------|----------------------------------------|
| `trust` (the default) | The organization's name, and counts. For the console: members and admins, invitations, and API keys by state, role, expiry, IP access list, and use. For each service, in the order the configuration lists them: the customer's entries and ClickHouse Cloud's own in each access table, the customer's users who can sign in with no password or from any address, and the customer's grants that the grantee may pass on. No organization ID, service hosts, emails, key names, or database user names other than the collector's own. |
| `audit` | Adds the organization's ID, each service's host, and the rows behind each count: each member's email and console roles, each invitation, and each API key's name, roles, expiry, IP access list, and last use. For each service: every database user with its sign-in methods and allowed hosts, every role, role grant, and privilege, and every settings profile, quota, and row policy, with ClickHouse Cloud's own listed apart from the customer's. |
| `internal` | The same as `audit`. |

The level the collector ran at is the artifact's `collected_at_level`.

`artifacts/clickhouse.access-posture.json` holds its present flags and percentages at every level. Its counts appear from the `audit` level.
