package domain

import (
	"reflect"
	"strings"
)

// ConnectorCatalogueEntry describes one connector type for the UI (D82). Connectors are created only as resources
// (kubectl, GitOps, or `rampart apply -f`); the UI uses this entry to render a form, produce the resource and a
// Secret template, and validate them before the user applies them. The schema is generated from the same Go struct
// the server decodes, so the form cannot drift from what the server accepts.
type ConnectorCatalogueEntry struct {
	Type        ConnectorType        `json:"type"`
	Name        string               `json:"name"`
	Kind        string               `json:"kind"` // tracker | notifier | source
	Directions  []ConnectorDirection `json:"directions"`
	Description string               `json:"description"`
	// ConfigKey is the key of the type's block under spec (jira, slack, dependencyTrack …).
	ConfigKey    string            `json:"config_key"`
	ConfigSchema map[string]any    `json:"config_schema"`
	Secrets      []CatalogueSecret `json:"secrets"`
	// Example is a complete Connector and a Secret template with placeholders. It is checked by a test against
	// Validate, so it always describes a resource the server accepts.
	Example string `json:"example"`
}

// CatalogueSecret names a secret reference inside the type's block and what the referenced Secret must hold.
type CatalogueSecret struct {
	Field   string `json:"field"` // e.g. credentialsSecretRef, or smtp.credentialsSecretRef
	Holds   string `json:"holds"`
	Purpose string `json:"purpose"`
}

type catalogueSpec struct {
	entry ConnectorCatalogueEntry
	cfg   any
}

var connectorCatalogue = []catalogueSpec{
	{ConnectorCatalogueEntry{
		Type: ConnectorTypeJira, Name: "Jira Cloud", Kind: "tracker", ConfigKey: "jira",
		Directions:  []ConnectorDirection{DirectionOutbound, DirectionBidirectional},
		Description: "Opens Jira Cloud issues for findings; with twoWaySync, a resolution in Jira becomes a request in Rampart (D27). Jira Data Center is not supported (REST v3 only, D70).",
		Secrets: []CatalogueSecret{
			{Field: "credentialsSecretRef", Holds: "email:apiToken (Basic) or a personal access token", Purpose: "calls the Jira API"},
			{Field: "webhookSecretRef", Holds: "the secret Jira signs webhooks with; required with twoWaySync", Purpose: "verifies Jira's callbacks (D70)"},
		},
		Example: `apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: jira-sec, namespace: <tenant-namespace>}
spec:
  type: jira
  jira:
    url: https://example.atlassian.net
    credentialsSecretRef: {name: jira-sec-creds, key: token}
    defaultProject: SEC
    issueType: Bug
    twoWaySync: true
    webhookSecretRef: {name: jira-sec-creds, key: webhook}
---
apiVersion: v1
kind: Secret
metadata: {name: jira-sec-creds, namespace: <tenant-namespace>}
stringData:
  token: <email>:<api-token>
  webhook: <random-webhook-secret>
`,
	}, JiraConnectorConfig{}},
	{ConnectorCatalogueEntry{
		Type: ConnectorTypeGitHub, Name: "GitHub Issues", Kind: "tracker", ConfigKey: "github",
		Directions:  []ConnectorDirection{DirectionOutbound, DirectionBidirectional},
		Description: "Opens GitHub issues for findings; with twoWaySync, closing an issue as not planned becomes a request in Rampart (D27).",
		Secrets: []CatalogueSecret{
			{Field: "credentialsSecretRef", Holds: "a token with Issues: write", Purpose: "calls the GitHub API"},
			{Field: "webhookSecretRef", Holds: "the repository webhook secret; required with twoWaySync", Purpose: "verifies X-Hub-Signature-256 (D70)"},
		},
		Example: `apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: github-issues, namespace: <tenant-namespace>}
spec:
  type: github
  github:
    owner: acme
    repo: security-issues
    credentialsSecretRef: {name: github-issues-creds, key: token}
---
apiVersion: v1
kind: Secret
metadata: {name: github-issues-creds, namespace: <tenant-namespace>}
stringData:
  token: <github-token>
`,
	}, GitHubConnectorConfig{}},
	{ConnectorCatalogueEntry{
		Type: ConnectorTypeSlack, Name: "Slack", Kind: "notifier", ConfigKey: "slack",
		Directions:  []ConnectorDirection{DirectionOutbound},
		Description: "Posts notifications with chat.postMessage and a bot token (D69).",
		Secrets:     []CatalogueSecret{{Field: "tokenSecretRef", Holds: "a bot token (xoxb-…)", Purpose: "posts messages"}},
		Example: `apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: slack-appsec, namespace: <tenant-namespace>}
spec:
  type: slack
  slack:
    tokenSecretRef: {name: slack-appsec-token, key: token}
    defaultChannel: "#appsec"
---
apiVersion: v1
kind: Secret
metadata: {name: slack-appsec-token, namespace: <tenant-namespace>}
stringData:
  token: <xoxb-bot-token>
`,
	}, SlackConnectorConfig{}},
	{ConnectorCatalogueEntry{
		Type: ConnectorTypeTeams, Name: "Microsoft Teams", Kind: "notifier", ConfigKey: "teams",
		Directions:  []ConnectorDirection{DirectionOutbound},
		Description: "Posts Adaptive Cards to a Teams Workflows webhook; Office 365 connectors were retired in May 2026 (D69).",
		Secrets:     []CatalogueSecret{{Field: "webhookSecretRef", Holds: "the Workflows webhook URL", Purpose: "the URL is the credential"}},
		Example: `apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: teams-appsec, namespace: <tenant-namespace>}
spec:
  type: teams
  teams:
    webhookSecretRef: {name: teams-appsec-url, key: url}
---
apiVersion: v1
kind: Secret
metadata: {name: teams-appsec-url, namespace: <tenant-namespace>}
stringData:
  url: <workflows-webhook-url>
`,
	}, TeamsConnectorConfig{}},
	{ConnectorCatalogueEntry{
		Type: ConnectorTypeEmail, Name: "Email (SMTP)", Kind: "notifier", ConfigKey: "email",
		Directions:  []ConnectorDirection{DirectionOutbound},
		Description: "Sends notifications by SMTP; STARTTLS is required unless tlsMode says otherwise (D69).",
		Secrets:     []CatalogueSecret{{Field: "smtp.credentialsSecretRef", Holds: "keys username and password", Purpose: "SMTP authentication"}},
		Example: `apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: email-appsec, namespace: <tenant-namespace>}
spec:
  type: email
  email:
    smtp:
      host: smtp.example.com
      port: 587
      tlsMode: starttls
      credentialsSecretRef: {name: email-appsec-smtp}
    from: rampart@example.com
    to: [appsec@example.com]
---
apiVersion: v1
kind: Secret
metadata: {name: email-appsec-smtp, namespace: <tenant-namespace>}
stringData:
  username: <smtp-user>
  password: <smtp-password>
`,
	}, EmailConnectorConfig{}},
	{ConnectorCatalogueEntry{
		Type: ConnectorTypeWebhook, Name: "Generic webhook", Kind: "notifier", ConfigKey: "webhook",
		Directions:  []ConnectorDirection{DirectionOutbound},
		Description: "Sends signed JSON (CloudEvents or raw) to an HTTPS endpoint.",
		Secrets:     []CatalogueSecret{{Field: "secretRef", Holds: "the HMAC key", Purpose: "signs each delivery"}},
		Example: `apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: siem-webhook, namespace: <tenant-namespace>}
spec:
  type: webhook
  webhook:
    url: https://siem.example.com/rampart
    secretRef: {name: siem-webhook-key, key: secret}
    format: cloudevents
---
apiVersion: v1
kind: Secret
metadata: {name: siem-webhook-key, namespace: <tenant-namespace>}
stringData:
  secret: <random-hmac-key>
`,
	}, WebhookConnectorConfig{}},
	{ConnectorCatalogueEntry{
		Type: ConnectorTypeDependencyTrack, Name: "Dependency-Track", Kind: "source", ConfigKey: "dependencyTrack",
		Directions:  []ConnectorDirection{DirectionInbound},
		Description: "The Dependency-Track API endpoint and key. The projects, mapping and webhook are set on a ScanSource of type apiPull that names this connector (docs/10 §8).",
		Secrets:     []CatalogueSecret{{Field: "credentialsSecretRef", Holds: "an API key with VIEW_PORTFOLIO and VIEW_VULNERABILITY", Purpose: "sent as X-Api-Key"}},
		Example: `apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: dtrack, namespace: <tenant-namespace>}
spec:
  type: dependencyTrack
  dependencyTrack:
    url: https://dtrack-api.example.com
    credentialsSecretRef: {name: dtrack-api-key, key: apiKey}
---
apiVersion: v1
kind: Secret
metadata: {name: dtrack-api-key, namespace: <tenant-namespace>}
stringData:
  apiKey: <odt_api_key>
`,
	}, DependencyTrackConnectorConfig{}},
	{ConnectorCatalogueEntry{
		Type: ConnectorTypePlugin, Name: "Installed package", Kind: "notifier", ConfigKey: "plugin",
		Directions:  []ConnectorDirection{DirectionOutbound},
		Description: "Any tool described by an IntegrationPackage installed in this namespace: a request template, the secrets it needs and the hosts it may reach. A new tool needs no Rampart release (docs/19 §6, D94). This version runs declarative notifiers.",
		Secrets:     []CatalogueSecret{{Field: "secrets.<name>", Holds: "each secret the package declares", Purpose: "read by the package's templates as {{ secrets.<name> }}"}},
		Example: `apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata: {name: chat-sec, namespace: <tenant-namespace>}
spec:
  type: plugin
  plugin:
    name: google-chat
    secrets:
      webhookUrl: {name: chat-sec-hook, key: url}
---
apiVersion: rampart.aspm.dev/v1alpha1
kind: IntegrationPackage
metadata: {name: google-chat, namespace: <tenant-namespace>}
spec:
  kind: notifier
  runtime: declarative
  version: 1.0.0
  secrets: [{name: webhookUrl}]
  egress: [chat.googleapis.com]
  send:
    request:
      method: POST
      url: "{{ secrets.webhookUrl }}"
      json: {text: "*{{ message.title }}*  {{ message.summary }}  <{{ message.url }}|Open in Rampart>"}
    expect: "status == 200"
---
apiVersion: v1
kind: Secret
metadata: {name: chat-sec-hook, namespace: <tenant-namespace>}
stringData:
  url: <https://chat.googleapis.com/v1/spaces/...>
`,
	}, PluginConnectorConfig{}},
}

// ConnectorCatalogue lists the connector types this build supports, with their schemas (D82).
func ConnectorCatalogue() []ConnectorCatalogueEntry {
	out := make([]ConnectorCatalogueEntry, 0, len(connectorCatalogue))
	for _, c := range connectorCatalogue {
		e := c.entry
		e.ConfigSchema = jsonSchemaOf(reflect.TypeOf(c.cfg))
		out = append(out, e)
	}
	return out
}

// jsonSchemaOf describes a config struct by its json tags: a field without omitempty is listed as required. It is
// a description for forms; the server's validation (Connector.Validate, run by the dry-run endpoint and the
// operator) is the authority.
func jsonSchemaOf(t reflect.Type) map[string]any {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": jsonSchemaOf(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": jsonSchemaOf(t.Elem())}
	case reflect.Struct:
		props := map[string]any{}
		var required []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if !f.IsExported() || tag == "-" {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if name == "" {
				name = f.Name
			}
			props[name] = jsonSchemaOf(f.Type)
			if !strings.Contains(opts, "omitempty") {
				required = append(required, name)
			}
		}
		s := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			s["required"] = required
		}
		return s
	}
	return map[string]any{}
}
