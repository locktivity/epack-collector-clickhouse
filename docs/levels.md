# Collection Levels

The `level` config key sets how much detail the collector writes. The levels are cumulative: each one holds everything the level below it holds.

| Level | What `artifacts/clickhouse.json` holds |
|-------|----------------------------------------|
| `trust` (the default) | The organization's ID and name, and counts. For the console: members and admins, invitations, and API keys by state, role, expiry, IP access list, and use. For each service: the customer's entries and ClickHouse Cloud's own in each access table, the customer's users who can sign in with no password or from any address, and the customer's grants that the grantee may pass on. No emails, key names, or database user names. |
| `audit` | Adds the rows behind each count: each member's email and console roles, each invitation, and each API key's name, roles, expiry, IP access list, and last use. For each service: every database user with its sign-in methods and allowed hosts, every role, role grant, and privilege, and every settings profile, quota, and row policy, with ClickHouse Cloud's own listed apart from the customer's. |
| `internal` | The same as `audit`. |

The level the collector ran at is the artifact's `collected_at_level`.
