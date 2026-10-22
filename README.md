# epack-collector-clickhouse

An epack collector that reads who can reach a ClickHouse Cloud organization: console members, invitations, and API keys from the Cloud API, and each service's database users, roles, grants, settings profiles, quotas, and row policies over the service's HTTPS interface.

See [docs/](docs/) for setup and the output: [configuration](docs/configuration.md), [overview](docs/overview.md), [levels](docs/levels.md), and [examples](docs/examples.md).

## Layout

| Path | Contents |
|------|----------|
| `cmd/epack-collector-clickhouse/main.go` | The entrypoint, which runs the handler |
| `internal/collector/handler.go` | The collector's spec and handler, and the HTTP clients for the Cloud API and the services |
| `internal/collector/collector.go` | The sign-in and the run's steps |
| `internal/collector/console.go` | Members, invitations, API keys, and console roles |
| `internal/collector/services.go` | Each service's database access settings |
| `internal/collector/gaps.go` | Records each value the collector leaves out, and why |
| `internal/clickhouse/cloud.go` | The Cloud API client, with one named operation per call |
| `internal/clickhouse/database.go` | The SQL client, with one named operation per query |
| `docs/schema/v1.0.0.json` | The artifact's JSON Schema, with the `x-epack` annotations the output checks read |
| `docs/schema/trace-map.json` | The trace map, which links each field to the calls and the code behind it |

## Development

```bash
make build
./epack-collector-clickhouse --capabilities
```

## Testing

```bash
make test
```

`internal/collector/collectortest_test.go` runs the collector against canned responses: an organization like the sandbox's written by hand in `fixtures_test.go`, an empty one, and scenarios for a read-only key that sees no members, a refused key, a rejected database password, and a database user missing a grant. It then makes each call fail in turn, with errors such as a 403, a timeout, or a malformed body, and checks that each value the collector could not read is left out with a gap. It also checks the output against `docs/schema/v1.0.0.json` at every collection level, and checks that no credential reaches another host or any output.

### Recording the sandbox

`internal/collector/record_test.go` runs the collector once against a sandbox, a ClickHouse Cloud organization kept with known settings, and writes the responses to `internal/collector/testdata/recordings/clickhouse.json`, which the suite loads as one more scenario. It reads the sandbox's organization ID, service host, and mailbox from `SANDBOX_CLICKHOUSE_ORG_ID`, `SANDBOX_CLICKHOUSE_SERVICE_HOST`, and `SANDBOX_CLICKHOUSE_MAILBOX`, and the credentials from the three variables the collector reads:

```bash
make record
```

The recording replaces the organization, the service, and the mailbox with the kit's fakes, and the organization's and members' names with placeholders. It fails rather than write a recording that still holds one of them or a credential.

### Trace map

After a change to the code, rewrite the trace map and commit the result:

```bash
make trace-map
```

CI fails when the committed map is stale, and so does `go test` when the suite finds a call or field the map lacks.

### Conformance

```bash
make conformance
```

This runs the conformance harness at the epack version `go.mod` pins, with `testdata/conformance.json` as the config and a canary value in each variable `CONFORMANCE_SECRETS` lists in the Makefile. The canary key reaches the Cloud API, which rejects it, so conformance checks that the run exits 3 and that no output prints a canary.

## CI

`.github/workflows/ci.yaml` calls epack's shared collector workflow, which runs the tests, lint, release builds, conformance, the trace map check, and govulncheck. On a pull request it also compares each scenario's output with the output of the latest release.

## Release

Tag a version to trigger the release workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The workflow runs CI, builds binaries for linux and darwin on amd64 and arm64 with [SLSA Level 3](https://slsa.dev/spec/v1.0/levels#build-l3) provenance, and creates the GitHub release. When the repository variable `SANDBOX_RELEASE_CHECK` is `true`, the release starts as a draft, and `publish.yaml` publishes it once the sandbox check passes on the tag's commit.

## License

Apache 2.0. See [LICENSE](LICENSE).
