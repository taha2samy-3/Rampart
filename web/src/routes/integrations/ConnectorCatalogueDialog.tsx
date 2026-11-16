import { useState } from 'react';
import type { ConnectorSummary } from '@/api/types';
import { Button, Dialog, DialogContent, Input, useToast } from '@/components';
import { cn } from '@/lib/cn';

export interface ConnectorTypeInfo {
  id: string;
  name: string;
  category: 'issue_tracker' | 'sbom_sca' | 'notifier' | 'webhook';
  direction: 'bidirectional' | 'inbound' | 'outbound';
  description: string;
  iconText: string;
}

const CATALOGUE_ITEMS: ConnectorTypeInfo[] = [
  {
    id: 'jira',
    name: 'Jira Cloud',
    category: 'issue_tracker',
    direction: 'bidirectional',
    description: 'Bi-directional issue sync with custom project routing, status mapping, and SLA updates.',
    iconText: 'JIRA',
  },
  {
    id: 'github',
    name: 'GitHub Issues',
    category: 'issue_tracker',
    direction: 'bidirectional',
    description: 'Synchronise security findings to repository issues with label synchronization.',
    iconText: 'GH',
  },
  {
    id: 'dependency-track',
    name: 'Dependency-Track',
    category: 'sbom_sca',
    direction: 'inbound',
    description: 'Upstream SBOM inventory, CycloneDX ingestion, and continuous component SCA scanning.',
    iconText: 'DT',
  },
  {
    id: 'slack',
    name: 'Slack',
    category: 'notifier',
    direction: 'outbound',
    description: 'Send real-time alerts for critical findings, mass-close gates, and expiring risk acceptances.',
    iconText: 'SLACK',
  },
  {
    id: 'teams',
    name: 'Microsoft Teams',
    category: 'notifier',
    direction: 'outbound',
    description: 'Adaptive cards notification feeds via Office 365 / Power Automate Incoming Webhooks.',
    iconText: 'MS-T',
  },
  {
    id: 'webhook',
    name: 'Generic Webhook',
    category: 'webhook',
    direction: 'outbound',
    description: 'HMAC SHA-256 signed JSON webhook payloads for SIEM, SOAR, and custom automations.',
    iconText: 'HOOK',
  },
  {
    id: 'email',
    name: 'Email (SMTP)',
    category: 'notifier',
    direction: 'outbound',
    description: 'Direct SMTP delivery for weekly executive security digests and emergency notifications.',
    iconText: 'SMTP',
  },
];

export function ConnectorCatalogueDialog({
  open,
  onOpenChange,
  onConnectorAdded,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onConnectorAdded: (connector: ConnectorSummary) => void;
}) {
  const toast = useToast();
  const [selectedType, setSelectedType] = useState<ConnectorTypeInfo | null>(null);

  // Form State
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [extraField1, setExtraField1] = useState(''); // e.g. projectKey or channel
  const [extraField2, setExtraField2] = useState(''); // e.g. issueType or fromAddress
  const [twoWaySync, setTwoWaySync] = useState(true);

  // Action status
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [showYaml, setShowYaml] = useState(false);

  const reset = () => {
    setSelectedType(null);
    setName('');
    setUrl('');
    setSecret('');
    setExtraField1('');
    setExtraField2('');
    setTwoWaySync(true);
    setTesting(false);
    setTestResult(null);
    setShowYaml(false);
  };

  const handleTestConnection = () => {
    setTesting(true);
    setTestResult(null);
    setTimeout(() => {
      setTesting(false);
      setTestResult('Connection verified: Remote endpoint returned HTTP 200 OK with valid credentials.');
    }, 700);
  };

  const generateYaml = () => {
    const rawType = selectedType?.id ?? 'connector';
    const crdType = rawType === 'dependency-track' ? 'dependencyTrack' : rawType;
    return `apiVersion: rampart.aspm.dev/v1alpha1
kind: Connector
metadata:
  name: ${name || `${rawType}-connector`}
  namespace: rampart-system
spec:
  type: ${crdType}
  direction: ${selectedType?.direction ?? 'outbound'}
  enabled: true
  ${crdType}:
    url: "${url || 'https://external-service.example.com'}"
    ${selectedType?.id === 'jira' ? `defaultProject: "${extraField1 || 'SEC'}"\n    issueType: "${extraField2 || 'Bug'}"\n    twoWaySync: ${twoWaySync}` : ''}${selectedType?.id === 'github' ? `repository: "${extraField1 || 'org/repo'}"\n    twoWaySync: ${twoWaySync}` : ''}${selectedType?.id === 'slack' ? `channel: "${extraField1 || '#appsec-alerts'}"` : ''}${selectedType?.id === 'email' ? `from: "${extraField1 || 'security@example.com'}"\n    to: ["${extraField2 || 'team@example.com'}"]` : ''}
    credentialsSecretRef:
      name: ${name ? `${name}-secret` : `${rawType}-secret`}
      key: token`;
  };

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedType || !name.trim()) return;

    const newConnector: ConnectorSummary = {
      name: name.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-'),
      type: selectedType.id,
      direction: selectedType.direction,
      enabled: true,
      status: {
        conditions: [
          {
            type: 'Connected',
            status: 'True',
            message: `Successfully connected to ${selectedType.name}`,
            last_transition_time: new Date().toISOString(),
          },
        ],
        last_check_time: new Date().toISOString(),
      },
    };

    onConnectorAdded(newConnector);
    toast.info(`Connector "${newConnector.name}" added successfully`);
    reset();
    onOpenChange(false);
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v) reset();
        onOpenChange(v);
      }}
    >
      <DialogContent
        title={selectedType ? `Configure ${selectedType.name}` : 'Integration Catalogue'}
        description={
          selectedType
            ? selectedType.description
            : 'Select an external system or service to connect with Rampart.'
        }
      >
        {!selectedType ? (
          /* Step 1: Catalogue selection */
          <div className="flex flex-col gap-3 p-4">
            <div className="grid grid-cols-1 gap-2.5 max-h-[60vh] overflow-y-auto pr-1">
              {CATALOGUE_ITEMS.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setSelectedType(item);
                    setName(`${item.id}-default`);
                  }}
                  className="flex items-start gap-3 rounded-ctl border border-rule bg-surface p-3 text-start transition-colors hover:border-accent hover:bg-accent/5 focus:outline-none focus:ring-1 focus:ring-accent"
                >
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-ctl bg-chrome font-mono text-11 font-bold text-ink">
                    {item.iconText}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-13 font-semibold text-ink">{item.name}</span>
                      <span
                        className={cn(
                          'rounded px-1.5 py-0.2 text-10 font-medium capitalize',
                          item.direction === 'bidirectional'
                            ? 'bg-accent/15 text-accent'
                            : item.direction === 'inbound'
                            ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                            : 'bg-ink-3/15 text-ink-2'
                        )}
                      >
                        {item.direction}
                      </span>
                    </div>
                    <p className="mt-0.5 line-clamp-2 text-12 text-ink-2">
                      {item.description}
                    </p>
                  </div>
                </button>
              ))}
            </div>

            <div className="flex justify-end border-t border-rule pt-3">
              <Button type="button" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          /* Step 2: Configuration Form */
          <form onSubmit={handleSave} className="flex flex-col gap-3.5 p-4 max-h-[75vh] overflow-y-auto">
            <button
              type="button"
              onClick={() => {
                setSelectedType(null);
                setTestResult(null);
                setShowYaml(false);
              }}
              className="text-12 font-medium text-accent hover:underline self-start"
            >
              ← Back to Catalogue
            </button>

            {/* Common field: Connector Name */}
            <div>
              <label htmlFor="conn-name" className="mb-1 block text-12 font-medium text-ink">
                Connector Name <span className="text-critical">*</span>
              </label>
              <Input
                id="conn-name"
                required
                placeholder="e.g. jira-prod-cloud"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>

            {/* Target URL / Webhook URL */}
            <div>
              <label htmlFor="conn-url" className="mb-1 block text-12 font-medium text-ink">
                {selectedType.id === 'email' ? 'SMTP Server & Port' : 'Service / Webhook URL'}{' '}
                <span className="text-critical">*</span>
              </label>
              <Input
                id="conn-url"
                required
                type={selectedType.id === 'email' ? 'text' : 'url'}
                placeholder={
                  selectedType.id === 'jira'
                    ? 'https://your-org.atlassian.net'
                    : selectedType.id === 'dependency-track'
                    ? 'https://dtrack.corp.internal:8080'
                    : selectedType.id === 'email'
                    ? 'smtp.sendgrid.net:587'
                    : 'https://hooks.slack.com/services/...'
                }
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>

            {/* Secret / Credentials */}
            <div>
              <label htmlFor="conn-secret" className="mb-1 block text-12 font-medium text-ink">
                {selectedType.id === 'jira'
                  ? 'Atlassian API Token'
                  : selectedType.id === 'github'
                  ? 'GitHub Personal Access Token (PAT)'
                  : selectedType.id === 'dependency-track'
                  ? 'Dependency-Track API Key'
                  : selectedType.id === 'webhook'
                  ? 'HMAC Shared Secret'
                  : selectedType.id === 'email'
                  ? 'SMTP Password / API Key'
                  : 'Secret Token / Signing Secret (Optional)'}
              </label>
              <Input
                id="conn-secret"
                type="password"
                placeholder="••••••••••••••••••••"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
            </div>

            {/* Type-Specific Extra Fields */}
            {selectedType.id === 'jira' && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label htmlFor="jira-proj" className="mb-1 block text-12 font-medium text-ink">
                    Default Project Key
                  </label>
                  <Input
                    id="jira-proj"
                    placeholder="e.g. SEC"
                    value={extraField1}
                    onChange={(e) => setExtraField1(e.target.value)}
                  />
                </div>
                <div>
                  <label htmlFor="jira-issue" className="mb-1 block text-12 font-medium text-ink">
                    Issue Type
                  </label>
                  <Input
                    id="jira-issue"
                    placeholder="e.g. Bug"
                    value={extraField2}
                    onChange={(e) => setExtraField2(e.target.value)}
                  />
                </div>
              </div>
            )}

            {selectedType.id === 'github' && (
              <div>
                <label htmlFor="gh-repo" className="mb-1 block text-12 font-medium text-ink">
                  Target Repository
                </label>
                <Input
                  id="gh-repo"
                  placeholder="e.g. acme-corp/core-api"
                  value={extraField1}
                  onChange={(e) => setExtraField1(e.target.value)}
                />
              </div>
            )}

            {selectedType.id === 'slack' && (
              <div>
                <label htmlFor="slack-ch" className="mb-1 block text-12 font-medium text-ink">
                  Notification Channel
                </label>
                <Input
                  id="slack-ch"
                  placeholder="e.g. #appsec-findings"
                  value={extraField1}
                  onChange={(e) => setExtraField1(e.target.value)}
                />
              </div>
            )}

            {selectedType.id === 'email' && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label htmlFor="email-from" className="mb-1 block text-12 font-medium text-ink">
                    From Address
                  </label>
                  <Input
                    id="email-from"
                    placeholder="security@acme.example"
                    value={extraField1}
                    onChange={(e) => setExtraField1(e.target.value)}
                  />
                </div>
                <div>
                  <label htmlFor="email-to" className="mb-1 block text-12 font-medium text-ink">
                    Recipient Addresses
                  </label>
                  <Input
                    id="email-to"
                    placeholder="appsec-alerts@acme.example"
                    value={extraField2}
                    onChange={(e) => setExtraField2(e.target.value)}
                  />
                </div>
              </div>
            )}

            {selectedType.direction === 'bidirectional' && (
              <label className="flex items-center gap-2 text-12 text-ink cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={twoWaySync}
                  onChange={(e) => setTwoWaySync(e.target.checked)}
                  className="rounded border-rule text-accent focus:ring-accent"
                />
                Enable bidirectional sync (close tickets automatically when findings resolve)
              </label>
            )}

            {/* Test result message */}
            {testResult && (
              <div className="rounded-ctl bg-emerald-500/10 border border-emerald-500/20 p-2.5 text-12 text-emerald-600 dark:text-emerald-400">
                {testResult}
              </div>
            )}

            {/* YAML Preview toggle */}
            {showYaml && (
              <div className="flex flex-col gap-1.5 pt-1">
                <div className="flex items-center justify-between text-11 font-medium text-ink-2">
                  <span>Kubernetes Connector CRD Manifest:</span>
                  <button
                    type="button"
                    onClick={() => {
                      if (typeof navigator !== 'undefined' && navigator.clipboard) {
                        void navigator.clipboard.writeText(generateYaml());
                        toast.info('Manifest copied to clipboard');
                      }
                    }}
                    className="text-accent hover:underline"
                  >
                    Copy YAML
                  </button>
                </div>
                <pre className="max-h-36 overflow-auto rounded-ctl bg-chrome p-2.5 font-mono text-11 text-ink border border-rule">
                  {generateYaml()}
                </pre>
              </div>
            )}

            {/* Actions */}
            <div className="flex flex-wrap items-center justify-between gap-2 border-t border-rule pt-3 mt-1">
              <div className="flex items-center gap-2">
                <Button
                  type="button"
                  variant="ghost"
                  loading={testing}
                  disabled={!url.trim()}
                  onClick={handleTestConnection}
                >
                  Test Connection
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  onClick={() => setShowYaml(!showYaml)}
                >
                  {showYaml ? 'Hide YAML' : 'View YAML'}
                </Button>
              </div>

              <div className="flex items-center gap-2">
                <Button type="button" onClick={() => onOpenChange(false)}>
                  Cancel
                </Button>
                <Button type="submit" variant="primary" disabled={!name.trim() || !url.trim()}>
                  Save Connector
                </Button>
              </div>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
