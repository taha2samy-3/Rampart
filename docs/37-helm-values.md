# 37. Helm values: every values file and what it does

This is the reference for the values files of a Rampart installation: the chart's own `values.yaml`, the three charts it depends on,
and the files that overlay them in the GitOps repository. For each key it says what the key does and what its default is. A key is
described by what the templates and the server do with it, not by what its name suggests; where nothing reads a key, it says so.

## 1. The files

| File | What it is | Who edits it |
|---|---|---|
| `deploy/helm/rampart/values.yaml` | The defaults of the Rampart chart. Section 3 describes every key. | Nobody installing: copy the keys you change into your own overlay. |
| `deploy/helm/rampart/values.schema.json` | Checks a few of those keys when you install (section 4). | Whoever adds a key that must be one of a fixed set. |
| `rampart-policies/charts/rampart-policies/values.yaml` | The defaults of the policy set: the risk policy, the SLA policy, the compliance frameworks (section 5). | Nobody installing. |
| `rampart-policies/charts/rampart-policies/ci/*.yaml` | Three value sets the policies repository's CI renders and checks. They are not for installs. | The policies repository. |
| `parsers/charts/rampart-parsers/values.yaml` | Which of the 17 default report parsers are installed (section 6). | Nobody installing. |
| `sbom-parsers/charts/rampart-sbom-parsers/values.yaml` | Which of the 3 default SBOM readers are installed (section 6). | Nobody installing. |
| `gitops/charts/rampart/values.yaml`, `values-dev.yaml`, `values.schema.json` | A copy of the Rampart chart that the GitOps repository carries, and the overlay for the dev cluster (section 7). | The cluster's operator. |
| `gitops/charts/rampart-policies/values-dev.yaml` | The policy set of the dev cluster, written out so that a change is a change in Git. | The cluster's operator. |
| `gitops/charts/rampart-resources/values.yaml`, `values-dev.yaml` | A small chart that creates the tenant, an application and the Dependency-Track connection of the dev cluster (section 7). | The cluster's operator. |

### How values combine

Helm merges, last wins: the chart's `values.yaml`, then the defaults of each chart it depends on, then every `-f file` in the order given,
then every `--set`. A dependency has an alias, and its values are written under that alias in the parent:

| Dependency chart | Alias in Rampart's values | Switch |
|---|---|---|
| `rampart-policies` | `policies` | `policies.enabled` |
| `rampart-parsers` | `parsers` | `parsers.defaultParsers.enabled` |
| `rampart-sbom-parsers` | `sbomParsers` | `sbomParsers.defaultSBOMParsers.enabled` |

So `parsers.defaultParsers.trivy.enabled=false` reaches the `rampart-parsers` chart as `defaultParsers.trivy.enabled=false`. All three are
on by default and are OCI charts (`oci://ghcr.io/rampart-aspm/charts`): `helm dependency update` pulls them, so the packages have to be
published and public.

## 2. Reading the tables

A **default** is the value in `values.yaml`. "Env" is the environment variable the chart sets on the Rampart container for the key. A key with
no env is read by a template (a Secret, a Job, a policy) and not by the server. Secrets never go through values: where a key names a Secret, you
create the Secret and the chart reads it.

## 3. The Rampart chart: `deploy/helm/rampart/values.yaml`

### 3.1 The pod

| Key | Default | What it does |
|---|---|---|
| `replicaCount` | `1` | Pods of the Deployment. Keep it at 1: `-target=all` also runs the operator and the scheduler in every replica and there is no leader election yet (doc 15). The schema refuses less than 1. |
| `image.repository` | `ghcr.io/rampart-aspm/rampart` | The image of the server, of the migrate Job and of the maintenance CronJob. |
| `image.tag` | `v0.1.1` | The tag. Empty means the chart's `appVersion`. |
| `image.pullPolicy` | `IfNotPresent` | Pull policy of the same three. |
| `imagePullSecrets` | `[]` | Secrets for a private registry, on the pod. |
| `nameOverride`, `fullnameOverride` | `""` | Replace the chart name, or the whole resource name prefix, in every resource name. |
| `serviceAccount.create` | `true` | Creates the ServiceAccount. With `false` the pod uses `serviceAccount.name`, or `default`. |
| `serviceAccount.name` | `""` | Its name. Empty with `create: true` is the release's full name. |
| `serviceAccount.annotations` | `{}` | Annotations on it, for example a cloud identity. |
| `podAnnotations`, `podLabels` | `{}` | Added to the pod template. |
| `podSecurityContext` | non-root 65532, `fsGroup` 65532, `RuntimeDefault` seccomp | On the pod, and on the migrate Job, the CronJob and the feed plugins. |
| `securityContext` | no privilege escalation, read-only root file system, all capabilities dropped | On the containers of the server, the migrate Job and the maintenance CronJob. |
| `resources` | requests 500m CPU and 1Gi, limits 2 CPU and 4Gi | The server container. |
| `nodeSelector`, `tolerations`, `affinity` | `{}`, `[]`, `{}` | Scheduling of the pod, passed as given. |
| `service.type` | `ClusterIP` | Type of the Service. |
| `service.port` | `8080` | The API and the screens. |
| `service.opsPort` | `9090` | `/metrics`, `/healthz` and `/readyz`. It is never meant to be routed outside the cluster. |

The chart has no Ingress template. Expose the Service on port 8080 with your own Ingress or Gateway API route.

### 3.2 `telemetry`

| Key | Default | Env | What it does |
|---|---|---|---|
| `telemetry.logLevel` | `info` | `RAMPART_LOG_LEVEL` | `debug`, `info`, `warn` or `error` (the schema checks). |
| `telemetry.logFormat` | `json` | `RAMPART_LOG_FORMAT` | `json` or `text` (the schema checks). |
| `telemetry.otlpEndpoint` | `""` | `RAMPART_TELEMETRY_OTLP_ENDPOINT` | Where traces and metrics go over OTLP/HTTP, for example `http://otel-collector:4318`. Empty turns OTLP export off. With `networkPolicy.enabled`, allow the address in `networkPolicy.egressExtra`: `allowHttpsEgress` covers port 443 only. |

### 3.3 `database`

PostgreSQL holds everything. The server connects as `rampart_app` (row-level security applies), migrations run as `rampart_owner`, and tenant
bootstrap as `rampart_system` (D4).

| Key | Default | What it does |
|---|---|---|
| `database.cnpg.enabled` | `true` | Creates a CloudNativePG `Cluster`, so the CloudNativePG operator must be installed. The chart generates the three role passwords into Secrets. |
| `database.cnpg.instances` | `3` | Instances of the cluster. |
| `database.cnpg.image` | `ghcr.io/cloudnative-pg/postgresql:16.4` | The PostgreSQL image. |
| `database.cnpg.podMonitor` | `false` | Sets `enablePodMonitor` on the cluster. |
| `database.cnpg.storage.size` | `20Gi` | Volume size per instance. |
| `database.existingSecret` | `""` | Required when `cnpg.enabled` is `false`. A Secret with the keys `url` (rampart_app, pooled), `directUrl` (rampart_app, direct), `migrateUrl` (rampart_owner) and `systemUrl` (rampart_system). Credentials never go through values. |
| `database.minSchemaVersion` | `53` | An init container waits (up to 300 s) until the database has reached this schema version before the server starts. It has to match the image: a server that needs a newer schema than the database has would otherwise start and fail. The schema refuses less than 15. |

### 3.4 `objectStorage` and `seaweedfs`

Raw reports are kept in S3-compatible storage. SeaweedFS is the bundled one.

| Key | Default | Env or use | What it does |
|---|---|---|---|
| `seaweedfs.enabled` | `true` | | Runs SeaweedFS in the release. With `false`, `objectStorage.endpoint` and `objectStorage.existingSecret` are required. |
| `seaweedfs.image` | `chrislusf/seaweedfs:4.53` | | Its image. |
| `seaweedfs.persistence.size` | `50Gi` | | Its volume. |
| `objectStorage.endpoint` | `""` | endpoint | The S3 API. Used only with `seaweedfs.enabled: false`; required then. |
| `objectStorage.existingSecret` | `""` | credentials | With `seaweedfs.enabled: false`, a Secret with the keys `accessKey` and `secretKey`. |
| `objectStorage.externalEndpoint` | `""` | external endpoint | The address clients outside the cluster use to `PUT` reports. Presigned URLs are signed for it. Empty means the in-cluster address, which only clients inside the cluster can reach. |
| `objectStorage.region` | `us-east-1` | region | Region of the S3 API. |
| `objectStorage.bucketRaw` | `rampart-raw-reports` | bucket | Where raw reports go. |
| `objectStorage.usePathStyle` | `true` | path style | Path-style addressing, which SeaweedFS and most S3 look-alikes need. |
| `objectStorage.bucketExports` | `rampart-exports` | | Reserved: nothing reads it yet. The server has no export that writes to a bucket. |

### 3.5 `server` and `auth`

| Key | Default | What it does |
|---|---|---|
| `server.publicUrl` | `""` | The external base URL. It builds the OIDC redirect address, and `https://` makes the session cookie `Secure`. Set it before using single sign-on. |
| `auth.bootstrapAdmin.enabled` | `true` | Creates the first administrator, like Argo CD's initial admin (D3), so you can sign in before an identity provider exists. Its password is generated into the Secret `<release>-admin`; the install notes print the command that reads it. |
| `auth.bootstrapAdmin.username` | `admin` | Its user name. |
| `auth.bootstrapAdmin.keepEnabled` | `false` | With single sign-on configured the account switches itself off. `true` keeps it as break-glass access. |
| `auth.oidc.issuer` | `""` | The identity provider. Empty runs without browser sign-in; API tokens still work. |
| `auth.oidc.clientId` | `""` | Required when `issuer` is set. |
| `auth.oidc.clientSecretName` | `""` | Required when `issuer` is set: the Secret that holds the client secret. It never goes through values. |
| `auth.oidc.clientSecretKey` | `clientSecret` | The key inside that Secret. |
| `auth.oidc.defaultRole` | `viewer` | The role at first sign-in when no binding matches: `viewer`, `triager`, `admin`, or `""` for no access. |
| `auth.oidc.bindings` | `[]` | Roles are granted here and never read straight from the identity provider (doc 14 section 3). Each is `{kind: group or user, name, role}`. |

### 3.6 `feeds`: threat intelligence

Feeds fill the vulnerability tables that scoring and the screens read: known exploitation, exploit maturity, probability, advisories.

| Key | Default | What it does |
|---|---|---|
| `feeds.enabled` | `true` | The server downloads feeds on a schedule. |
| `feeds.interval` | `6h` | How often. `metrics.prometheusRule.feedStaleSeconds` is two intervals and an hour. |
| `feeds.kevUrl`, `epssUrl`, `nvdUrl`, `osvBaseUrl`, `osvEcosystems` | empty | The addresses of the built-in feeds. Empty is the public address. `kevUrl`, `epssUrl`, `osvBaseUrl` and `osvEcosystems` are passed to the server as environment variables. All of them fill in a source of `defaultMirror` whose own `url` (or `ecosystems`) is empty; the one in `defaultMirror` wins. |
| `feeds.tokenSecret` | `""` | A Secret you create with the feed API tokens, one key per token (for example `nvd-api-key`). It is mounted read-only at `/etc/rampart/feed-secrets`, the only directory a `tokenFile` may point to. The server's own secrets are never readable as a feed token. The chart refuses a `tokenFile` when this is empty. |
| `feeds.plugins` | `[]` | Feed plugins (D89, D94): one CronJob each, a container that fetches a vulnerability database and posts it as `intel-jsonl` to `/api/v1/feeds/<name>`. Each is `{name, image, schedule, tokenSecret, env}`; the Secret holds the key `token` and is also mounted into Rampart, which the ClusterFeed names as `pushTokenFile`. |

#### `feeds.defaultMirror`: the ClusterFeed of the cluster

`defaultMirror` is one `ClusterFeed` resource: where each feed is read from and which are on. `enabled: false` installs no resource.

| Key | Default | What it does |
|---|---|---|
| `defaultMirror.enabled` | `true` | Install the resource. |
| `defaultMirror.name` | `default` | Its name. |
| `defaultMirror.egress` | `allow` | `allow` or `deny`. `deny` is for an air-gapped cluster: every `url` must then be your mirror's address, and a public address is refused. |
| `defaultMirror.storageMode` | `lightweight` | `lightweight` keeps what matching, scoring and the screens need. `full` also keeps the complete source record of every advisory and reads the Go, npm, PyPI and Maven ecosystems of OSV when none is named. |
| `defaultMirror.cwe` | not rendered | The spec accepts a `cwe` block and refuses it with the reason "not synced by this version"; the chart does not write one. |
| `defaultMirror.custom` | `[]` | Feeds of your own, each `{name, format, url, tokenFile, enabled}`. The format is `osv-zip` (a zip of OSV JSON records) or `intel-jsonl` (one exploitation record per line). |

Every source has `enabled` and `url` (empty: the public address, or your mirror's). A source that is off is not read, and its rows are removed.

| Source | Default | What it gives | Notes |
|---|---|---|---|
| `kev` | on | Known exploited vulnerabilities (CISA) | |
| `epss` | on | Exploitation probability scores | |
| `nvd` | on | Advisories and CVSS from NIST | `tokenFile` is the file with the NVD API key, under `/etc/rampart/feed-secrets`. |
| `osv` | on | Advisories by package and ecosystem | `ecosystems` defaults to `[Go, npm, PyPI, Maven]`: four of the 47 OSV has (the list is below). One archive per ecosystem is downloaded to `/tmp`, and npm and PyPI are hundreds of megabytes, so name only the ones you use. Empty falls back to `feeds.osvEcosystems`. |
| `vulnrichment` | on | SSVC, and CVSS and CWE that NVD has not added (CISA ADP) | |
| `exploitdb` | on | Public exploit code (maturity `poc`) | |
| `metasploit` | on | Exploit modules (maturity `weaponized`) | |
| `euvd` | on | ENISA's EUVD identifiers and exploitation reported in the EU | |
| `vulncheckKev` | **off** | VulnCheck's known exploited list | VulnCheck answers no request without a token. Enabling it without a `tokenFile` makes the chart fail. |

**The OSV ecosystems** (the names in `ecosystems.txt` of the OSV bucket, 47 at the time of writing; write one exactly as it appears, case included):
`AlmaLinux`, `Alpaquita`, `Alpine`, `Android`, `Azure Linux`, `BellSoft Hardened Containers`, `Bitnami`, `CRAN`, `Chainguard`, `CleanStart`, `Debian`, `Docker Hardened Images`, `Echo`, `GHC`, `GIT`, `GSD`, `GitHub Actions`, `Go`, `Hackage`, `Hex`, `Julia`, `Linux`, `Mageia`, `Maven`, `MinimOS`, `NuGet`, `OSS-Fuzz`, `Packagist`, `Pub`, `PyPI`, `Red Hat`, `Red Hat Lightwell`, `Rocky Linux`, `Root`, `RubyGems`, `SUSE`, `SwiftURL`, `TuxCare`, `UVI`, `Ubuntu`, `VSCode`, `Wolfi`, `crates.io`, `npm`, `opam`, `openEuler`, `openSUSE`.
The default has four of them. A package of an ecosystem that is not named has none of its OSV advisories in Rampart, so a deployment that scans .NET, Ruby, PHP, Rust or
container images should add `NuGet`, `RubyGems`, `Packagist`, `crates.io`, or the distribution (`Debian`, `Alpine`, `Ubuntu`, and so on). Whether that default should be
wider is a decision about download size and disk, which was not measured here.

### 3.7 `retention`

How long each kind of data is kept, in days. `0` keeps it for ever. The server removes tenant data every `interval`, as the application role.
The monthly partitions of the event and audit logs are maintained by a CronJob, as the owner role; it also creates the coming months'
partitions, so keep it on even with retention off.

| Key | Default | What goes after this long |
|---|---|---|
| `retention.enabled` | `true` | The sweep runs at all. |
| `retention.interval` | `6h` | How often it runs (at least one minute). |
| `retention.occurrencesDays` | `180` | An occurrence no scanner reports any more, counted from when it was last seen. The finding stays; only the stale evidence goes. |
| `retention.rawReportsDays` | `90` | The report as the scanner wrote it, in object storage. |
| `retention.secretReportsDays` | `7` | The raw report of a run that found secrets. The stored findings never hold a secret, but the report does, so it goes sooner. |
| `retention.resolvedFindingsDays` | `730` | A finding fixed this long ago and not reported since, with its timeline. |
| `retention.eventsDays` | `730` | Finding timelines, dropped a month at a time. |
| `retention.auditDays` | `2555` | The audit log, dropped a month at a time. |
| `retention.runResultsDays` | `30` | What each run found new or fixed, kept for the CI gate. |
| `retention.maintenance.schedule` | `17 3 * * *` | When the CronJob runs (cron syntax). |

Minimums are enforced: `auditDays` and `eventsDays` at least 365 (PCI DSS 10.5.1), `resolvedFindingsDays` at least 180 (SLA and trend views look back that far).

### 3.8 `operator`

| Key | Default | What it does |
|---|---|---|
| `operator.enabled` | `true` | Installs the operator's permissions (RBAC), and lets the pod use the Kubernetes API (it mounts the ServiceAccount token). |
| `operator.mode` | `auto` | `auto` starts the operator when the pod runs in a cluster (or has a kubeconfig) and carries on without it otherwise. `on` refuses to start when there is no cluster configuration. `off` never starts it. The schema checks the three words. |

### 3.9 `metrics`

The ops port serves `/metrics`. All three are off because each needs a CRD or a sidecar of its own.

| Key | Default | What it does |
|---|---|---|
| `metrics.serviceMonitor.enabled` | `false` | Creates a `ServiceMonitor`; needs the prometheus-operator CRDs. |
| `metrics.serviceMonitor.interval`, `scrapeTimeout` | `30s`, `10s` | Scrape timing. |
| `metrics.serviceMonitor.namespace` | `""` | Empty is the release namespace. |
| `metrics.serviceMonitor.labels` | `{}` | For example `{release: kube-prometheus-stack}`, so your Prometheus selects it. |
| `metrics.prometheusRule.enabled` | `false` | Creates the alert rules; needs the `PrometheusRule` CRD. |
| `metrics.prometheusRule.feedStaleSeconds` | `46800` | `RampartFeedStale` fires when a feed's last success is older than this: two sync intervals and an hour at the default 6 h. |
| `metrics.prometheusRule.namespace`, `labels` | `""`, `{}` | As above. |
| `metrics.grafanaDashboards.enabled` | `false` | Creates ConfigMaps that the Grafana sidecar loads. |
| `metrics.grafanaDashboards.namespace` | `""` | Empty is the release namespace. |
| `metrics.grafanaDashboards.labels` | `{grafana_dashboard: "1"}` | The label the sidecar looks for. |

### 3.10 `networkPolicy`

Off by default; it needs a CNI that enforces NetworkPolicy. When on, the release's pods get default-deny in both directions and then only what
they need. The bundled PostgreSQL cluster and SeaweedFS are not denied by this chart: their own charts and operators own their policies.

| Key | Default | What it does |
|---|---|---|
| `networkPolicy.enabled` | `false` | Create the policies. |
| `networkPolicy.ingressFrom` | every namespace | Who may reach the HTTP port: the ingress controller and anything else that calls the API. Narrow it, for example to `- namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: ingress-nginx}}`. |
| `networkPolicy.metricsFrom` | the `monitoring` namespace | Who may scrape the ops port. |
| `networkPolicy.kubeApiCidrs` | `[]` | Where the operator reaches the Kubernetes API. Empty: any address on ports 443 and 6443. Used only with `operator.enabled`. |
| `networkPolicy.allowHttpsEgress` | `true` | Outbound HTTPS to the internet: feeds, the identity provider, connectors and Dependency-Track. Turn off for an air-gapped install and list the mirrors in `egressExtra`. |
| `networkPolicy.database.to`, `port` | `[]`, `5432` | Where PostgreSQL is when the chart does not run it. **Required** (the chart fails) when `database.cnpg.enabled` is `false`. A list of NetworkPolicy peers. |
| `networkPolicy.objectStore.to`, `port` | `[]`, `443` | The same for the object store. **Required** when `seaweedfs.enabled` is `false`. |
| `networkPolicy.egressExtra` | `[]` | Extra egress rules, verbatim NetworkPolicy entries. |

### 3.11 `parsers` and `sbomParsers`

Rampart's server knows no parser by name (D141): each one reaches it as a `ClusterParser` or `ClusterSBOMParser` resource. The defaults are
installed by the two dependency charts; these keys hold their switches and how the WASM modules the resources name reach the pod.

| Key | Default | What it does |
|---|---|---|
| `parsers.defaultParsers.enabled` | `true` | Install the 17 default report parsers (the `rampart-parsers` chart). `false` installs none, and also stops that chart from rendering. |
| `parsers.defaultParsers.<name>.enabled` | `true` | One switch for each of: `sarif`, `openvex`, `trivy`, `grype`, `semgrep`, `gitleaks`, `trufflehog`, `checkov`, `snyk`, `kubebench`, `prowler`, `gitlab`, `dependencycheck` (WASM), and `bandit`, `zap`, `nuclei`, `genericjson` (Lua). `false` leaves that parser out. |
| `sbomParsers.defaultSBOMParsers.enabled` | `true` | Install the 3 default SBOM readers (the `rampart-sbom-parsers` chart). |
| `sbomParsers.defaultSBOMParsers.<name>.enabled` | `true` | `cyclonedx`, `spdx`, `syft`. |
| `sbomParsers.defaultSBOMParsers.cyclonedx.extractVulnerabilities` | `false` | Turn the vulnerabilities a CycloneDX document states (a VDR) into findings, besides filling the inventory. Off: an SBOM is assets, and what is found in it is the matcher's work (D131). |
| `parsers.delivery.mode` | `none` | How the WASM modules reach the pod. `none` mounts nothing: only the Lua parsers work, unless `RAMPART_WASM_DIR` points at modules you provide, and the server warns that nothing is verified. `imageVolume` mounts every module image below read-only as an image volume (needs a Kubernetes version with the ImageVolume feature), and the server **refuses to start** unless each module is present and its `parser.wasm` has the SHA-256 listed. Signature checking of the images belongs to the cluster: an admission policy such as Kyverno or the sigstore policy-controller. |
| `parsers.delivery.mountPath` | `/opt/rampart/wasm` | Where they are mounted (becomes `RAMPART_WASM_DIR`). |
| `parsers.delivery.pullPolicy` | `IfNotPresent` | Pull policy of the module images. |
| `parsers.modules.<name>` | `{image: "", sha256: ""}` | One entry per module: the image, pinned by digest, and the SHA-256 (hex) of the `parser.wasm` inside it. The names are the 13 WASM parsers and `sbom-cyclonedx`, `sbom-spdx`, `sbom-syft`. `python3 hack/wasm-modules.py <path of the parsers repository>` prints the hashes. |

### 3.12 Analyzers: `analysis`, `sbomAnalyzer` and the external analyzer

An SBOM reader fills the inventory and never opens findings (D131). Findings for the components of an SBOM come from **analyzers** (D128, D143), which run the way
Dependency-Track's do: when an SBOM is uploaded, when a person asks, and on a schedule. The full description, with what was verified and what was not, is
[docs/38](38-analyzers.md).

#### How they run: `analysis`

| Key | Default | Environment variable | What it does |
|---|---|---|---|
| `analysis.enabled` | `true` | `RAMPART_ANALYSIS_ENABLED` | Starts an analysis when an SBOM is uploaded or asked for, and runs the scheduled sweep. Off, an analyzer is still listed and can be tested, and nothing runs it; the two "analyze" endpoints answer 409. |
| `analysis.maxAge` | `24h` | `RAMPART_ANALYSIS_MAX_AGE` | The sweep asks an analyzer again about an SBOM whose last analysis is older than this. At least one minute; the schema takes minutes or hours (`90m`, `24h`). An SBOMAnalyzer with a `schedule` follows its cron expression instead. |
| `analysis.maxInFlight` | `50` | `RAMPART_ANALYSIS_MAX_IN_FLIGHT` | How many analyses may be queued or running at once, in every tenant (Dependency-Track: 50). |

The scheduled sweep reads the SBOMs and analyzers of every tenant, which row-level security allows only the system database role: **it runs only with `database.systemUrl`**, and the
server logs a warning when that is missing (uploads and requests still work). One replica sweeps at a time (an advisory lock). **Enabling analysis on a cluster that already holds SBOMs
analyses them all, 50 at a time, and opens findings for applications that had none;** the matcher is off by default (below), so nothing changes until an analyzer is on.

#### The in-process matcher: `sbomAnalyzer`

The native matcher (`ClusterSBOMAnalyzer`) matches the components of an SBOM (by package URL and version) against the affected ranges the OSV feed loaded (`vulnerability_affected`), and opens
findings for them. It is **off by default.** It is only as good as that data: with the OSV feed not synced it matches nothing, and **Test** on the Analyzers tab says how many ranges are loaded.

| Key | Default | Effect today |
|---|---|---|
| `sbomAnalyzer.enabled` | `false` | Creates the resource. |
| `sbomAnalyzer.engine` | `hybrid` | Read and accepted. **Does not change the matching:** there is one matcher. |
| `sbomAnalyzer.rules.minConfidence` | `0.8` | Read and accepted. **No effect:** a match is exact (package URL and version range), so there is no confidence to compare. |
| `sbomAnalyzer.rules.includePreRelease` | `false` | Read and accepted. **No effect:** a pre-release version is compared by the matcher's own rule. |
| `sbomAnalyzer.rules.matchDirectOnly` | `false` | **Used:** only the direct dependencies of the SBOM are matched. |
| `sbomAnalyzer.sources.osv`, `ghsa`, `nvd` | `true`, `true`, `false` | Read and accepted. **No effect:** the matcher compares every package with all the advisories the OSV feed loaded. These three are all the CRD defines (a key it does not define is dropped by the API server). They are not the `feeds` above. |
| `schedule` (on the resource, not a chart value) | none | **Used:** a five-field cron expression in UTC; the SBOMs are matched again when it has fired since their last analysis. A bad expression is refused with the reason. |

The matcher compares versions as dotted numbers with a simple pre-release rule. The ordering rules of a particular ecosystem (Debian epochs, Maven qualifiers, PyPI local versions) are
not implemented, so a match in those ecosystems can be wrong in either direction. The `vulnerability` table holds a CVSS score but no severity word, so the matcher's severity comes from the score
(9.0 and above critical, 7.0 high, 4.0 medium, the rest low); an advisory with no score is `unknown`. A row of the OSV data that names no package URL cannot be found by it.

Which of Rampart's data can be a source: only one that says which package versions are affected. Of the feeds that is `osv` (and a custom `osv-zip` feed), and `nvd` by
CPE. `kev`, `epss`, `vulnrichment`, `exploitdb`, `metasploit`, `euvd` and `vulncheckKev` enrich a CVE and name no package, so they cannot match a component. `ghsa` has no
feed of its own: the GHSA feed is not built (docs/33), and a GHSA id reaches Rampart as an alias inside an OSV record.

#### The external analyzer: `ClusterExternalAnalyzer` and `ExternalAnalyzer`

The other way is a service that Rampart calls over **gRPC**: a scanner such as Snyk, Grype or Trivy, an in-house database, or Sonatype OSS Index through its own repository
(`sonatype-analyzer`, whose chart creates the resource). It is a `ClusterExternalAnalyzer` (cluster-wide) or an `ExternalAnalyzer` (one tenant's namespace). **This chart has no value and no
template for it:** you write the resource (`examples/external-analyzer/k8s-manifest.yaml` is a complete example: a Deployment, a Service and the resource) or install the analyzer's own chart.

| Part | Where | State |
|---|---|---|
| The contract | `pkg/api/analyzer/v1/analyzer.proto` | `Analyze` (components in, findings out), `GetMetadata` and `HealthCheck`. |
| The controller | `internal/operator` | Reconciles all four kinds (`ClusterExternalAnalyzer`, `ExternalAnalyzer`, `ClusterSBOMAnalyzer`, `SBOMAnalyzer`); the chart's RBAC grants them, with status and finalizers. |
| Storage | migration 53 (`cluster_policy`, `policy_object`, `sbom_analysis`, `analyzer_event`) | Last-valid-spec semantics: an edit that is refused keeps the spec in force and shows the reason. |
| The page | Ingestion, tab **Analyzers** | Lists them by kind, shows each one's set-up, **Test**, **Analyze every SBOM**, and the history. |
| The call | `internal/analysis` | One call per SBOM and analyzer with the whole SBOM (up to 64 MiB), timeout from the spec, TLS when `tls.insecure` is not true. |

The spec of a `ClusterExternalAnalyzer` (the namespaced kind has the same fields). A spec the server cannot honour is **refused with its reason** (it shows on the page) rather than accepted and ignored:

| Field | Default | What it is |
|---|---|---|
| `enabled` | `true` | Use this analyzer. |
| `protocol` | `grpc` | `grpc` only. `http` is refused: there is no HTTP client. |
| `endpoint` | | A full `host:port`. Refused in a tenant's `ExternalAnalyzer`: a tenant could point the server at any address (SSRF). |
| `service.name`, `namespace`, `port` | | An in-cluster Service, reached as `<name>.<namespace>.svc.cluster.local:<port>`; the resource's own namespace when none is given. |
| `timeoutSeconds` | `60` | How long one call may take, 0 to 600. docs/32 writes this as `timeout: 60s`; the CRD field is `timeoutSeconds`. |
| `tls.insecure` | `true` | With `false` the connection is TLS, checked against the system roots. |
| `tls.caSecretRef`, `auth.secretRef` | | **Refused:** the server cannot read a Secret to build a private CA or send a credential on the call, so accepting them would send the request without them. |

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterExternalAnalyzer
metadata:
  name: sample-analyzer
spec:
  enabled: true
  protocol: grpc
  service: {name: sample-analyzer-svc, namespace: security-tools, port: 50051}
  timeoutSeconds: 30
```

### 3.13 `policies`

| Key | Default | What it does |
|---|---|---|
| `policies.enabled` | `true` | Install the `rampart-policies` chart: the risk policy, the SLA policy (profile `strictest`) and eleven compliance frameworks, as the default of every tenant (a tenant that has a policy of its own keeps it). Their risk policy reads `app.environment`, so the chart and the server move together (schema version 51). Everything else under `policies` is that chart's own values, in section 5. |

## 4. `values.schema.json`

Helm refuses an install whose values break the schema. It checks only these keys:

| Key | Rule |
|---|---|
| `replicaCount` | integer, at least 1 |
| `image.repository` | non-empty string; `image.tag` a string |
| `operator.enabled`, `operator.mode` | boolean; `auto`, `on` or `off` |
| `telemetry.logLevel`, `logFormat`, `otlpEndpoint` | `debug`/`info`/`warn`/`error`; `json`/`text`; string |
| `database.cnpg.enabled`, `instances` | boolean; integer at least 1 |
| `database.existingSecret`, `minSchemaVersion` | string; integer at least 15 |
| `auth.oidc.issuer`, `clientId`, `defaultRole`, `bindings` | strings; `""`, `viewer`, `triager` or `admin`; array |
| `auth.bootstrapAdmin.enabled`, `username`, `keepEnabled` | boolean; non-empty string; boolean |
| `server.publicUrl`, `policies.enabled` | string; boolean |

It does **not** forbid unknown keys. A misspelled key, or a key at the wrong level, is silently ignored. After a change, check the effect with
`helm template` before you rely on it.

## 5. `rampart-policies`

The policy set: one chart, one version. Everything is on, so a plain install gives every tenant the risk policy, the SLA policy and the compliance
frameworks. In Rampart's chart these keys are under `policies:`.

| Key | Default | What it does |
|---|---|---|
| `scope` | `cluster` | `cluster` creates `ClusterRiskPolicy`, `ClusterSLAPolicy` and `ClusterComplianceFramework`: the default of every tenant. `namespace` creates `RiskPolicy`, `SLAPolicy` and `ComplianceFramework` in `namespace`: one tenant's own policy, which wins over a cluster one. |
| `namespace` | `rampart` | The namespace for `scope: namespace`. |
| `riskPolicy.enabled` | `true` | The scoring formula, named `default`, the name the server reads first. |
| `slaPolicy.enabled` | `true` | How long a finding may stay open. |
| `slaPolicy.profile` | `strictest` | `strictest`, `rampart`, `pci-dss`, `fedramp` or `cisa-bod`. One policy is in force, so one profile is rendered. `strictest` is the smallest allowance of the other four, cell by cell. |
| `compliance.<framework>.enabled` | `true` | One switch for each of `nist80053`, `nist800171`, `nistcsf`, `pcidss`, `iso27001`, `soc2`, `hipaa`, `gdpr`, `owaspapi`, `eucra`, `nis2`. A framework reads an application only when the application lists the framework's scope in `complianceScope` (`nist-800-53`, `nist-800-171`, `nist-csf`, `pci-dss`, `iso-27001`, `soc2`, `hipaa`, `gdpr`, `owasp-api`, `eu-cra`, `eu-nis2`). |
| `compliance.logos` | `true` | Give each framework a logo: an SVG Rampart draws itself, kept in the policies repository and fetched by the Rampart server from `logoBaseUrl`. The repository has to be public. `false` for a cluster that cannot reach the internet. |
| `compliance.logoBaseUrl` | the policies repository's `logos/` on GitHub raw | Serve the SVGs from your own copy instead. |
| `compliance.logoUrls` | `{}` | A logo of your own for one framework by its key (for example `nist80053: "https://example.org/nist.png"`). It wins over the two above. |

The three files in `ci/` (`all-off-values.yaml`, `cluster-all-values.yaml`, `namespace-all-values.yaml`) are what the policies repository's CI renders
and checks: everything off (the chart renders nothing), everything on at cluster scope, everything on at namespace scope. They are not for installs.

## 6. `rampart-parsers` and `rampart-sbom-parsers`

Each chart renders one resource for every manifest in its `manifests/` folder, which is a copy of the `parser.yaml` that sits next to each parser's code;
its template names no parser.

| Chart | Key | Default | What it does |
|---|---|---|---|
| `rampart-parsers` | `defaultParsers.enabled` | `true` | `false` installs no parser. |
| | `defaultParsers.<name>.enabled` | `true` | One for each of the 17 parsers named in 3.11. A parser not listed is on. |
| `rampart-sbom-parsers` | `defaultSBOMParsers.enabled` | `true` | `false` installs no reader. |
| | `defaultSBOMParsers.<name>.enabled` | `true` | `cyclonedx`, `spdx`, `syft` (the resource is named `sbom-<name>`). |
| | `defaultSBOMParsers.cyclonedx.extractVulnerabilities` | `false` | Sets `options.extractVulnerabilities` on the CycloneDX reader. The chart changes the spec only for this key, and only when you set it. |

Neither chart installs the WASM module a manifest names (`source.oci`). The modules reach the pod through `parsers.delivery` and `parsers.modules` in
Rampart's chart (3.11), or through `RAMPART_WASM_DIR` in Compose.

## 7. The GitOps repository

`gitops/charts/rampart/` carries a **copy** of the Rampart chart (chart version 0.2.1), older than `deploy/helm/rampart`: it has no parser, SBOM or
module templates and a shorter `values.yaml`. Compare it with the current chart before you update it. Its dev overlay, `values-dev.yaml`, sets only:

| Key | Value in dev | Why |
|---|---|---|
| `image.repository`, `image.tag` | the project's image under `ghcr.io/taha2samy-3`, a commit SHA | The image under test. |
| `server.publicUrl` | `https://rampart.dev.k8s.trypair.ai` | The address of the dev cluster. |
| `database.cnpg.enabled`, `database.existingSecret` | `false`, `rampart-db-urls` | PostgreSQL is not run by the chart; the Secret holds the four URLs (3.3). |
| `seaweedfs.persistence.size` | `20Gi` | Smaller volume than the default. |
| `resources` | 200m / 512Mi requests, 1 CPU / 2Gi limits | A smaller footprint than the default. |

`gitops/charts/rampart-policies/values-dev.yaml` writes out the policy set of section 5 (scope `cluster`, profile `strictest`, all eleven frameworks on)
so that changing one is a change in Git.

`gitops/charts/rampart-resources/` is a small chart of its own. `values.yaml` and `values-dev.yaml` are the same:

| Key | What it does |
|---|---|
| `tenant.enabled`, `name`, `displayName`, `namespaces` | Creates the `Tenant` and the namespaces it owns. |
| `applications[]` | One `Application` each: `name`, `displayName`, `businessCriticality`, `internetFacing`, and `selectors` (`repositories[].url`, `images[].repository`). |
| `dependencyTrack.enabled`, `url` | Creates a `Connector` and a `ScanSource` for Dependency-Track (a kind D139 retires). |
| `dependencyTrack.apiKey`, `webhook.token` | Written into Secrets by the chart. **They are plain text in a values file in Git.** Create these Secrets outside the chart instead, and rotate the values that were committed. |
| `parsers.cyclonedx.*` | Creates one namespaced `Parser` resource (`enabled`, `name`, `version`, `family`, `category`). |

## 8. Recipes

An overlay is a file you pass with `-f`; it needs only the keys you change.

**An external PostgreSQL and S3, with single sign-on.**

```yaml
database:
  cnpg: {enabled: false}
  existingSecret: rampart-db-urls          # keys url, directUrl, migrateUrl, systemUrl
seaweedfs: {enabled: false}
objectStorage:
  endpoint: https://s3.example.org
  existingSecret: rampart-s3               # keys accessKey, secretKey
  externalEndpoint: https://s3.example.org
server: {publicUrl: https://rampart.example.org}
auth:
  oidc:
    issuer: https://idp.example.org
    clientId: rampart
    clientSecretName: rampart-oidc          # key clientSecret
    bindings:
      - {kind: group, name: rampart-admins, role: admin}
networkPolicy:
  enabled: true
  database: {to: [{ipBlock: {cidr: 10.0.0.0/24}}], port: 5432}
  objectStore: {to: [{ipBlock: {cidr: 10.0.1.0/24}}], port: 443}
```

**An air-gapped cluster.** Point every feed at a mirror, deny egress, and close the network.

```yaml
feeds:
  defaultMirror:
    egress: deny
    kev: {url: https://mirror.internal/kev.json}
    epss: {url: https://mirror.internal/epss.csv.gz}
    nvd: {url: https://mirror.internal/nvd}
    osv: {url: https://mirror.internal/osv, ecosystems: [Go]}
    vulnrichment: {url: https://mirror.internal/vulnrichment.zip}
    exploitdb: {url: https://mirror.internal/exploitdb.csv}
    metasploit: {url: https://mirror.internal/metasploit.json}
    euvd: {url: https://mirror.internal/euvd}
networkPolicy: {enabled: true, allowHttpsEgress: false}
policies:
  compliance: {logos: false}   # no logo is fetched from the internet
```

**Leave things out.**

```yaml
parsers:
  defaultParsers:
    trivy: {enabled: false}
    snyk: {enabled: false}
sbomParsers:
  defaultSBOMParsers: {enabled: false}
policies:
  compliance: {hipaa: {enabled: false}, gdpr: {enabled: false}}
  slaPolicy: {profile: pci-dss}
```

## 9. Known gaps

- `objectStorage.bucketExports` is read by nothing (3.4).
- Of `sbomAnalyzer`, `engine`, `rules.minConfidence`, `rules.includePreRelease` and `sources` are read and accepted but do not change the matching (3.12).
- An external analyzer cannot use a private CA or a credential on the call, and a tenant's cannot name an endpoint (3.12).
- There is no Ingress template (3.1).
- The two parser charts are OCI dependencies that have to be published before `helm dependency update` works (section 1).
- `values.schema.json` checks few keys and ignores unknown ones (section 4).
- `gitops/charts/rampart` is an older copy of the chart (section 7), and `gitops/charts/rampart-resources` holds credentials in its values.
