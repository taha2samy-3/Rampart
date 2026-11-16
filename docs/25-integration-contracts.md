# 25. Integration contracts: adding a tool without a Rampart release

This document is for someone who wants Rampart to talk to a tool it does not know yet. It covers the two ways that work today, with no change to Rampart's code:

1. **A notifier described as data.** You write an `IntegrationPackage`: the request to send, the secrets it needs, and the hosts it may reach.
2. **A vulnerability database as a feed plugin.** You run a container that fetches the database and posts it to Rampart in one documented format.

The design behind both is in docs/19 (tiers), docs/23 §6 (the plugin design) and docs/16 D89 and D94 (the decisions and their reasons).

## 1. Notifier package

### What you write

```yaml
apiVersion: rampart.aspm.dev/v1alpha1
kind: IntegrationPackage
metadata: {name: google-chat, namespace: team-payments}
spec:
  kind: notifier
  runtime: declarative
  version: 1.0.0
  description: Posts to a Google Chat space
  secrets: [{name: webhookUrl}]
  egress: [chat.googleapis.com]
  send:
    request:
      method: POST
      url: "{{ secrets.webhookUrl }}"
      json:
        text: "*{{ message.title }}*\n{{ message.summary }}\n<{{ message.url }}|Open in Rampart>"
    expect: "status == 200"
---
apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: chat-sec, namespace: team-payments}
spec:
  type: plugin
  plugin:
    name: google-chat
    secrets:
      webhookUrl: {name: chat-sec-hook, key: url}
  routing: {minSeverity: high}
---
apiVersion: v1
kind: Secret
metadata: {name: chat-sec-hook, namespace: team-payments}
stringData:
  url: https://chat.googleapis.com/v1/spaces/.../messages?key=...
```

Apply them with `kubectl apply` or `rampart apply -f`. The package shows under **Integrations → Installed packages**, and the connector shows in the connector list as "Package google-chat".

### Fields

| Field | Meaning |
|---|---|
| `kind` | `notifier`. `tracker`, `source` and `parser` are refused by name: their declarative engines are not built yet. |
| `runtime` | `declarative`. `wasm` and `grpc` are code; they are tier 2 and are refused in a tenant namespace. |
| `version` | A semantic version, such as `1.0.0`. |
| `secrets` | The secrets the package needs, by name. The connector must supply every one, and no other. Each is stored as `connector:<connector>:<name>`. |
| `configSchema` | Optional. An object with typed properties (`string`, `integer`, `number`, `boolean`, optional `enum`) and `required`. The connector's `plugin.config` is checked against it. |
| `egress` | The hosts the package may reach: a name, or `*.domain`. IP addresses are refused. |
| `send.request` | `method` (POST, PUT or PATCH), `url`, optional `headers`, and either `json` or `body`. |
| `send.expect` | A CEL condition on `status`. The default is any 2xx status. |

### Templates

A template is `{{ root.field }}`, with no filters, logic or loops. It can read three roots:

| Root | Fields |
|---|---|
| `message` | `title`, `summary`, `severity`, `url`, `appName`, `findingId`, `timestamp`, `id` |
| `config` | the properties of `configSchema` |
| `secrets` | the names in `secrets` |

A placeholder that names a field that does not exist is refused when the package is applied, not when the first message is sent. Message text cannot go into a header.

### What Rampart guarantees

- **Escaping.** Inside `json`, every rendered value is a JSON string, so a finding title cannot break the document.
- **Network.** The rendered URL must be https, and its host must be in `egress`. The request then goes through the SSRF-safe client: private and loopback addresses are refused unless a platform administrator allowed them, and cross-host redirects are refused.
- **Tenant isolation.** A package is installed in one tenant. It reads only its own connector's secrets.
- **Failure.** A package that does not validate is kept with its error, and shown as "Not used: …". A connector that names it is `Ready=False` with reason `PackageInvalid`. A connector that names no installed package gets `UnknownIntegration`.
- **Connection status.** A declarative notifier has no check request, so its connector reads "Not checked yet" until its first delivery.

## 2. Feed plugin (vulnerability databases)

Findings always come from scanners and Dependency-Track (D39). A feed only adds intelligence to them: exploited or not, and how mature the exploit is. A feed plugin is a container you own. It fetches one database, often a licensed one (VulnDB, a vendor's exploit intelligence, an in-house list), and hands Rampart a file. **It never writes Rampart's database**: the feed syncer is the only writer of the global tables (D19).

### Format: intel-jsonl

One JSON object per line:

```json
{"id":"CVE-2024-3094","exploited":true,"maturity":"weaponized","reportedAt":"2024-03-29","evidence":"vendor advisory"}
```

| Key | Meaning |
|---|---|
| `id` | A CVE id. |
| `exploited` | Exploitation seen in the wild. |
| `maturity` | `none`, `poc` or `weaponized`. |
| `reportedAt` | When the source reported it (optional). |
| `evidence` | Free text shown with the score's reason (optional). |

**One bad line refuses the whole file.** A half-read feed would silently drop records.

A record changes the score through the built-in factors `EXPLOITED_REPORTED` (+300, only when the CVE is not already in KEV) and `EXPLOIT_WEAPONIZED` (+120). In a `RiskPolicy` the same data is available as `vuln.exploited`, `vuln.exploited_sources` and `vuln.exploit_maturity` (D88).

### Two ways to deliver

**Pull.** Serve the file at a URL inside the cluster:

```yaml
kind: ClusterFeedMirror
metadata: {name: default}
spec:
  custom:
    - {name: vulndb, url: http://vulndb-proxy.feeds.svc/intel.jsonl, format: intel-jsonl}
```

A pulled feed can also be an OSV zip (`format: osv-zip`).

**Push.** Post the file, up to 64 MiB:

```yaml
kind: ClusterFeedMirror
metadata: {name: default}
spec:
  custom:
    - {name: vulndb, format: intel-jsonl, pushTokenFile: /var/run/rampart/feeds/vulndb/token}
```

```
POST /api/v1/feeds/vulndb
Authorization: Bearer <the token>
Content-Type: application/x-ndjson

<the intel-jsonl file>
```

| Answer | Meaning |
|---|---|
| `202` | Staged. It is loaded on the next feed sync (`feeds.interval`, 6 h by default). The body gives the record count and SHA-256. |
| `401` | Unknown feed, or wrong token. Both give the same answer, so a caller cannot tell which feeds exist. |
| `413` | Over 64 MiB. Serve a larger feed at a URL instead. |
| `422` | A line did not validate. Nothing was kept, and the error names the line. |

A push feed's token reaches that feed and nothing else. It is not a user and has no role.

### Running it with the Helm chart

```yaml
feeds:
  plugins:
    - name: vulndb
      image: registry.example.com/vulndb-to-intel:1.0.0
      schedule: "0 */6 * * *"
      tokenSecret: rampart-feed-vulndb        # a Secret with key "token"
      env:
        - {name: VULNDB_API_KEY, valueFrom: {secretKeyRef: {name: vulndb-licence, key: apiKey}}}
```

For each plugin, the chart:
- creates a CronJob, with no database credentials and no service account token;
- gives the container `RAMPART_FEED_PUSH_URL` and `RAMPART_FEED_TOKEN`;
- mounts the same Secret into Rampart at `/var/run/rampart/feeds/<name>/token`;
- with network policies on, lets the plugin's pods reach the API port.

The plugin's own egress to its source is yours to restrict.

A minimal plugin is a shell step:

```sh
fetch-my-feed | to-intel-jsonl > /tmp/intel.jsonl
curl -fsS -X POST -H "Authorization: Bearer $RAMPART_FEED_TOKEN" \
  -H 'Content-Type: application/x-ndjson' --data-binary @/tmp/intel.jsonl "$RAMPART_FEED_PUSH_URL"
```

## 3. Not built yet

| Not built | Instead |
|---|---|
| Declarative trackers, sources and parser mappings | Built-in trackers (Jira, GitHub), the Dependency-Track source, the built-in parsers |
| Code plugins (WebAssembly parsers, gRPC sources, trackers and notifiers) and `ClusterIntegrationPackage` with signature verification | Tier 2, a later phase (docs/19 §7, docs/23 §6.6) |
| Packages pulled from an OCI registry | Packages are applied as resources |
| A push feed in OSV format | Pull it from a URL |
