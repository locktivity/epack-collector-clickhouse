# ClickHouse Cloud API coverage

What the collector reads of the ClickHouse Cloud API, and what it leaves out, checked against the ClickHouse Cloud API description at revision info.version 1.0, fetched 2026-11-13 22:30 UTC: https://api.clickhouse.cloud/v1, the OpenAPI document the API serves at its root.

| | Operations |
|---|---|
| In the description | 185 |
| Read operations in scope | 86 |
| Called by the collector | 5 |
| Not collected | 55, in 8 items |
| Left out as irrelevant | 26 |

## What the collector reads

- **organizations:** `organizationGet` (GET /v1/organizations/{organizationId}); `invitationGetList` (GET /v1/organizations/{organizationId}/invitations); `openapiKeyGetList` (GET /v1/organizations/{organizationId}/keys); `memberGetList` (GET /v1/organizations/{organizationId}/members); `organizationRolesGetList` (GET /v1/organizations/{organizationId}/roles)

## Not collected

### Service settings

Each service as the Cloud API describes it: its IP access list, endpoints and private endpoint configuration, the JWT providers it trusts for sign-in, its ClickHouse server settings, its replica-aware routing, and its encryption key settings. The collector reads each configured service through SQL, as the database user the configuration names.

- `instanceGetList` (GET /v1/organizations/{organizationId}/services)
- `instanceGet` (GET /v1/organizations/{organizationId}/services/{serviceId})
- `serviceClickhouseSettingsListGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickhouseSettings)
- `serviceClickhouseSettingsSchemaGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickhouseSettings/schema)
- `serviceClickhouseSettingGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickhouseSettings/{settingName})
- `jwtProviderGetList` (GET /v1/organizations/{organizationId}/services/{serviceId}/jwtProviders)
- `jwtProviderGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/jwtProviders/{jwtProviderName})
- `instancePrivateEndpointConfigGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/privateEndpointConfig)
- `replicaAwareRoutingGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/replicaAwareRouting)
- `instanceQueryEndpointGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/serviceQueryEndpoint)

### Backups and snapshots

Each service's backup configuration, backup bucket and backup history, and its snapshot configuration and snapshots.

- `backupBucketGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/backupBucket)
- `backupConfigurationGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/backupConfiguration)
- `backupGetList` (GET /v1/organizations/{organizationId}/services/{serviceId}/backups)
- `backupGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/backups/{backupId})
- `snapshotConfigurationGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/snapshotConfiguration)
- `snapshotGetList` (GET /v1/organizations/{organizationId}/services/{serviceId}/snapshots)
- `snapshotGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/snapshots/{snapshotId})

### Organization activity

The organization's activity log: who changed what in the Cloud console and API, and when, including member sign-ins. Reading it needs the view-activities permission, which the collector's API key does not hold.

- `activityGetList` (GET /v1/organizations/{organizationId}/activities)
- `activityGet` (GET /v1/organizations/{organizationId}/activities/{activityId})

### Query API endpoints and saved queries

The saved queries exposed as HTTP endpoints, and the roles allowed to call each.

- `queryApiEndpointList` (GET /v1/organizations/{organizationId}/services/{serviceId}/query-api-endpoints)
- `queryApiEndpointGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/query-api-endpoints/{endpointId})
- `savedQueryList` (GET /v1/organizations/{organizationId}/services/{serviceId}/saved-queries)
- `savedQueryGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/saved-queries/{queryId})

### ClickPipes

ClickPipes ingestion pipelines, their settings and source connections, reverse private endpoints, and change data capture scaling.

- `clickPipeGetList` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickpipes)
- `clickPipesServiceContextGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickpipes/context)
- `clickPipeGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickpipes/{clickPipeId})
- `clickPipeSettingsGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickpipes/{clickPipeId}/settings)
- `clickPipeCdcScalingGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickpipesCdcScaling)
- `clickPipeReversePrivateEndpointGetList` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickpipesReversePrivateEndpoints)
- `clickPipeReversePrivateEndpointGet` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickpipesReversePrivateEndpoints/{reversePrivateEndpointId})

### Bring your own cloud

Bring-your-own-cloud infrastructure: its details, private endpoint configuration, provisioning progress, tags, and the access the customer has authorized ClickHouse to it.

- `organizationByocInfrastructureGet` (GET /v1/organizations/{organizationId}/byocInfrastructure/{byocInfrastructureId})
- `organizationByocInfrastructureCustomerAuthorizedAccessGet` (GET /v1/organizations/{organizationId}/byocInfrastructure/{byocInfrastructureId}/customerAuthorizedAccess)
- `organizationByocInfrastructurePrivateEndpointConfigGet` (GET /v1/organizations/{organizationId}/byocInfrastructure/{byocInfrastructureId}/privateEndpointConfig)
- `organizationByocInfrastructureProgressGet` (GET /v1/organizations/{organizationId}/byocInfrastructure/{byocInfrastructureId}/progress)
- `organizationByocInfrastructureTagsGet` (GET /v1/organizations/{organizationId}/byocInfrastructure/{byocInfrastructureId}/tags)

### Postgres services

The organization's Postgres services: their configuration, CA certificates, backups and server logs.

- `postgresServiceGetList` (GET /v1/organizations/{organizationId}/postgres)
- `postgresServiceGet` (GET /v1/organizations/{organizationId}/postgres/{postgresId})
- `postgresServiceBackupGetList` (GET /v1/organizations/{organizationId}/postgres/{postgresId}/backups)
- `postgresServiceCertsGet` (GET /v1/organizations/{organizationId}/postgres/{postgresId}/caCertificates)
- `postgresInstanceConfigGet` (GET /v1/organizations/{organizationId}/postgres/{postgresId}/config)
- `postgresLogsGetList` (GET /v1/organizations/{organizationId}/postgres/{postgresId}/logs)
- `postgresInstanceMetricsGet` (GET /v1/organizations/{organizationId}/postgres/{postgresId}/metrics)
- `slowQueryPatternsGetList` (GET /v1/organizations/{organizationId}/postgres/{postgresId}/slowQueryPatterns)
- `slowQueryPatternGet` (GET /v1/organizations/{organizationId}/postgres/{postgresId}/slowQueryPatterns/{queryId})

### ClickStack

The ClickStack observability product: its roles, sources, dashboards, alerts, saved searches and webhooks.

- `clickStackListAlerts` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/alerts)
- `clickStackGetAlert` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/alerts/{clickStackAlertId})
- `clickStackListDashboards` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/dashboards)
- `clickStackGetDashboard` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/dashboards/{clickStackDashboardId})
- `clickStackListRoles` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/roles)
- `clickStackGetRole` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/roles/{clickStackRoleId})
- `clickStackListSavedSearches` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/saved-searches)
- `clickStackGetSavedSearch` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/saved-searches/{clickStackSavedSearchId})
- `clickStackListSources` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/sources)
- `clickStackGetSource` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/sources/{clickStackSourceId})
- `clickStackListWebhooks` (GET /v1/organizations/{organizationId}/services/{serviceId}/clickstack/webhooks)

## Left out as irrelevant

- **Metrics, billing, quotas, notifications and capacity settings.** `creditBalancesGet`, `memberNotificationSettingsGetList`, `notificationTypesGetList`, `notificationGetList`, `postgresOrgPrometheusGet`, `postgresInstancePrometheusGet`, `organizationPublicPreviewsGetList`, `organizationPrometheusDiscoveryGet`, `organizationQuotasGetList`, `organizationQuotaGet`, `serviceProfilesList`, `instancePrometheusGet`, `scalingScheduleGet`, `upgradeWindowGet`, `usageCostGet`
- **User-defined functions, which are code rather than access.** `udfList`, `udfGet`, `udfAttachmentList`, `udfAttachmentGet`, `udfVersionList`
- **Detail of, or another view on, what the collector already reads.** `organizationGetList`, `invitationGet`, `openapiKeyGet`, `memberGet`, `organizationRoleGet`, `whoamiGet`

## Outside the description

- clickhouse.db.grants.list (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover
- clickhouse.db.quota_limits.list (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover
- clickhouse.db.quotas.list (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover
- clickhouse.db.role_grants.list (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover
- clickhouse.db.roles.list (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover
- clickhouse.db.row_policies.list (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover
- clickhouse.db.settings_profile_elements.list (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover
- clickhouse.db.settings_profiles.list (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover
- clickhouse.db.users.list (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover
- clickhouse.db.version.get (POST /): A SQL query to the service's HTTPS interface, which the Cloud API description does not cover

Generated by `epack sdk surface` from `docs/surface.yaml` and the collector's recordings. Edit the verdicts there, then run `epack sdk surface --write`.
