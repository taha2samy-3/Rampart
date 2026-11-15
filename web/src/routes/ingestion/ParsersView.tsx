import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { listParsers, qk } from '@/api';
import type { ParserDescriptor } from '@/api/types';
import {
  Button,
  CommandLine,
  Dialog,
  DialogContent,
  EmptyState,
  Input,
  Spinner,
  Table,
  TBody,
  Td,
  Th,
  THead,
  Tr,
  useToast,
} from '@/components';
import { cn } from '@/lib/cn';

interface ParsersViewProps {
  onUploadClick?: () => void;
}

const FALLBACK_PARSERS: ParserDescriptor[] = [
  { id: 'builtin:sarif', name: 'SARIF 2.1.0 Parser', kind: 'parser', version: '2.1.0', support_level: 'builtin', description: 'OASIS SARIF 2.1.0 standard with enrichers for Semgrep, Trivy, Gitleaks, CodeQL' },
  { id: 'builtin:cyclonedx', name: 'CycloneDX Parser (JSON/XML)', kind: 'parser', version: '1.5.0', support_level: 'builtin', description: 'CycloneDX 1.4-1.7 SBOM, VDR, and VEX parser for JSON and XML formats' },
  { id: 'builtin:spdx', name: 'SPDX Parser (JSON/Tag-Value)', kind: 'parser', version: '2.3.0', support_level: 'builtin', description: 'SPDX 2.2 and 2.3 SBOM parser for JSON and Tag-Value formats' },
  { id: 'builtin:openvex', name: 'OpenVEX Parser', kind: 'parser', version: '0.2.0', support_level: 'builtin', description: 'OpenVEX triage statements and exploitability assertions parser' },
  { id: 'builtin:syft', name: 'Syft Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Anchore Syft SBOM parser with artifact catalog and dependency relationships' },
  { id: 'builtin:trivy', name: 'Trivy Parser (JSON)', kind: 'parser', version: '2.0.0', support_level: 'builtin', description: 'Trivy JSON (schema 2): package vulnerabilities, secrets, misconfigurations, licenses' },
  { id: 'builtin:grype', name: 'Grype Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Grype JSON: vulnerability matches with their related identifiers' },
  { id: 'builtin:semgrep', name: 'Semgrep Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Semgrep JSON: code findings with CWE, location and code snippet hash' },
  { id: 'builtin:trufflehog', name: 'TruffleHog Parser (JSON lines)', kind: 'parser', version: '3.0.0', support_level: 'builtin', description: 'TruffleHog JSON lines: secrets, verified against live endpoints' },
  { id: 'builtin:gitleaks', name: 'Gitleaks Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Gitleaks JSON: secrets found in git repositories; secret is hashed' },
  { id: 'builtin:dependencytrack', name: 'Dependency-Track Parser (FPF/JSON)', kind: 'parser', version: '1.4.0', support_level: 'builtin', description: 'Dependency-Track FPF export and direct API finding response parser with VEX' },
  { id: 'builtin:checkov', name: 'Checkov Parser (JSON)', kind: 'parser', version: '3.0.0', support_level: 'builtin', description: 'Checkov IaC scanning report for Terraform, CloudFormation, K8s, Dockerfile' },
  { id: 'builtin:bandit', name: 'Bandit Parser (JSON)', kind: 'parser', version: '1.7.0', support_level: 'builtin', description: 'Bandit Python SAST vulnerability and security flaw report' },
  { id: 'builtin:nuclei', name: 'Nuclei Parser (JSONL)', kind: 'parser', version: '3.0.0', support_level: 'builtin', description: 'Nuclei template-based vulnerability scan results' },
  { id: 'builtin:zap', name: 'OWASP ZAP Parser (JSON)', kind: 'parser', version: '2.14.0', support_level: 'builtin', description: 'OWASP ZAP DAST web application security report' },
  { id: 'builtin:dependencycheck', name: 'OWASP Dependency-Check Parser (JSON)', kind: 'parser', version: '8.4.0', support_level: 'builtin', description: 'OWASP Dependency-Check SCA vulnerability report' },
  { id: 'builtin:snyk', name: 'Snyk Parser (JSON)', kind: 'parser', version: '1.0.0', support_level: 'builtin', description: 'Snyk open source and container vulnerability report' },
  { id: 'builtin:kubebench', name: 'kube-bench Parser (JSON)', kind: 'parser', version: '0.6.0', support_level: 'builtin', description: 'Aqua Security kube-bench CIS Kubernetes benchmark report' },
  { id: 'builtin:prowler', name: 'Prowler Parser (JSON)', kind: 'parser', version: '4.0.0', support_level: 'builtin', description: 'Prowler AWS/Azure/GCP cloud security and compliance report' },
];

function categorizeParser(id: string): string {
  if (['builtin:sarif', 'builtin:semgrep', 'builtin:bandit'].includes(id)) return 'SAST';
  if (['builtin:cyclonedx', 'builtin:spdx', 'builtin:syft', 'builtin:dependencytrack', 'builtin:dependencycheck', 'builtin:grype', 'builtin:snyk'].includes(id)) return 'SCA & SBOM';
  if (['builtin:gitleaks', 'builtin:trufflehog'].includes(id)) return 'Secrets';
  if (['builtin:checkov', 'builtin:kubebench', 'builtin:prowler'].includes(id)) return 'IaC & Cloud';
  if (['builtin:openvex'].includes(id)) return 'VEX';
  if (['builtin:zap', 'builtin:nuclei'].includes(id)) return 'DAST';
  return 'General';
}

function parserFormat(id: string): string {
  if (id === 'builtin:cyclonedx') return 'JSON / XML';
  if (id === 'builtin:spdx') return 'JSON / Tag-Value';
  if (['builtin:trufflehog', 'builtin:nuclei'].includes(id)) return 'JSON Lines (.jsonl)';
  return 'JSON';
}

const SAMPLE_CEL_MAPPING_YAML = `apiVersion: rampart.aspm.dev/v1alpha1
kind: IntegrationPackage
metadata:
  name: custom-scanner-mapping
spec:
  kind: parser
  runtime: mapping
  version: 1.0.0
  family: custom-scanner
  category: sast
  detect:
    filenames: ["*.custom.json"]
    probes:
      - jsonHasKeys: ["vulnerabilities", "tool_info"]
  input:
    format: json
    records: "$.vulnerabilities[*]"
  map:
    ruleId: "rec.id"
    title: "rec.name"
    description: "rec.description"
    severity: "rec.severity"
    vulnIds: "[rec.cve_id]"
    location:
      file: "rec.file_path"
      startLine: "string(rec.line_number)"
  limits:
    maxRecords: 500000
    maxDepth: 64`;

export function ParsersView({ onUploadClick }: ParsersViewProps) {
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>('all');
  const [selectedParser, setSelectedParser] = useState<ParserDescriptor | null>(null);
  const [celModalOpen, setCelModalOpen] = useState(false);

  const query = useQuery({
    queryKey: qk.parsers.list(),
    queryFn: async ({ signal }) => {
      try {
        const res = await listParsers(signal);
        return res.length > 0 ? res : FALLBACK_PARSERS;
      } catch {
        return FALLBACK_PARSERS;
      }
    },
  });

  const parsers = query.data ?? FALLBACK_PARSERS;

  const filtered = useMemo(() => {
    return parsers.filter((p) => {
      const cat = categorizeParser(p.id);
      if (category !== 'all' && cat !== category) return false;
      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return (
        p.name.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        cat.toLowerCase().includes(q)
      );
    });
  }, [parsers, category, search]);

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto p-4 tablet:p-6">
      {/* Header */}
      <div className="mb-4 flex flex-col justify-between gap-3 tablet:flex-row tablet:items-center">
        <div>
          <div className="flex items-center gap-2.5">
            <h2 className="display text-18 font-semibold text-ink">Supported Parsers & Formats</h2>
            <span className="rounded-full bg-accent/15 px-2.5 py-0.5 text-11 font-medium text-accent">
              {parsers.length} Built-in Engines
            </span>
          </div>
          <p className="mt-1 text-13 text-ink-2">
            Streaming high-performance parsers with automatic format detection, plus runtime declarative CEL mapping.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start tablet:self-auto">
          <Button variant="secondary" onClick={() => setCelModalOpen(true)}>
            + Custom CEL Parser
          </Button>
          {onUploadClick && (
            <Button variant="primary" onClick={onUploadClick}>
              Upload Scan Report
            </Button>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-rule pb-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {['all', 'SAST', 'SCA & SBOM', 'Secrets', 'IaC & Cloud', 'DAST', 'VEX'].map((cat) => (
            <button
              key={cat}
              type="button"
              onClick={() => setCategory(cat)}
              className={cn(
                'rounded-ctl px-2.5 py-1 text-12 font-medium transition-colors',
                category === cat
                  ? 'bg-surface font-semibold text-ink shadow-sm'
                  : 'text-ink-2 hover:bg-chrome hover:text-ink'
              )}
            >
              {cat === 'all' ? 'All Categories' : cat}
            </button>
          ))}
        </div>

        <div className="w-full max-w-xs">
          <Input
            placeholder="Search parser by name or format..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Parsers Table */}
      {query.isLoading ? (
        <div className="flex h-48 items-center justify-center">
          <Spinner />
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState title="No matching parsers found">
          Try adjusting your search criteria or category filter.
        </EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-ctl border border-rule bg-surface">
          <Table aria-label="Supported parsers table">
            <THead>
              <tr>
                <Th className="w-[260px]">Parser Name</Th>
                <Th className="w-[120px]">Category</Th>
                <Th className="w-[160px]">Input Format</Th>
                <Th className="w-[110px]">Tier</Th>
                <Th className="w-[130px]">Engine Status</Th>
                <Th>Description</Th>
                <Th align="end" className="w-[90px]">Action</Th>
              </tr>
            </THead>
            <TBody>
              {filtered.map((p) => {
                const cat = categorizeParser(p.id);
                const format = parserFormat(p.id);
                return (
                  <Tr
                    key={p.id}
                    className="h-12 cursor-pointer hover:bg-chrome/60"
                    onClick={() => setSelectedParser(p)}
                  >
                    <Td className="font-medium text-ink">
                      <div className="flex flex-col">
                        <span>{p.name}</span>
                        <span className="font-mono text-11 text-ink-2">{p.id}</span>
                      </div>
                    </Td>
                    <Td>
                      <span className="rounded bg-chrome px-1.5 py-0.5 text-11 font-medium text-ink-2">
                        {cat}
                      </span>
                    </Td>
                    <Td className="font-mono text-12 text-ink-2">{format}</Td>
                    <Td>
                      <span className="inline-flex rounded-ctl bg-ink-3/15 px-2 py-0.5 text-11 font-medium capitalize text-ink-2">
                        Tier {p.support_level === 'builtin' ? '1' : '2'}
                      </span>
                    </Td>
                    <Td>
                      <span className="inline-flex items-center gap-1.5 rounded-full bg-success/15 px-2 py-0.5 text-11 font-medium text-success">
                        <span className="size-1.5 rounded-full bg-success animate-pulse" />
                        Active
                      </span>
                    </Td>
                    <Td className="max-w-[340px] truncate text-12 text-ink-2" title={p.description}>
                      {p.description}
                    </Td>
                    <Td align="end">
                      <Button
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedParser(p);
                        }}
                      >
                        Details
                      </Button>
                    </Td>
                  </Tr>
                );
              })}
            </TBody>
          </Table>
        </div>
      )}

      {/* Parser Details Dialog */}
      {selectedParser && (
        <Dialog open={!!selectedParser} onOpenChange={(open) => !open && setSelectedParser(null)}>
          <DialogContent
            title={selectedParser.name}
            description={selectedParser.description}
          >
            <div className="flex flex-col gap-4 p-4 text-13">
              <dl className="m-0 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5">
                <dt className="text-ink-2">Engine ID:</dt>
                <dd className="m-0 font-mono text-12">{selectedParser.id}</dd>
                <dt className="text-ink-2">Category:</dt>
                <dd className="m-0 font-medium">{categorizeParser(selectedParser.id)}</dd>
                <dt className="text-ink-2">Format:</dt>
                <dd className="m-0 font-mono text-12">{parserFormat(selectedParser.id)}</dd>
                <dt className="text-ink-2">Version:</dt>
                <dd className="m-0 font-mono text-12">{selectedParser.version}</dd>
                <dt className="text-ink-2">Execution:</dt>
                <dd className="m-0">Streaming Zero-Copy JIT Parser</dd>
              </dl>

              <div className="border-t border-rule pt-3">
                <h4 className="mb-1 text-12 font-semibold text-ink">Upload via CLI:</h4>
                <CommandLine
                  command={`rampart upload --source default report.${parserFormat(selectedParser.id).toLowerCase().includes('xml') ? 'xml' : 'json'}`}
                />
              </div>

              <div className="flex justify-end pt-2 border-t border-rule">
                <Button type="button" onClick={() => setSelectedParser(null)}>
                  Close
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Custom CEL Parser Dialog */}
      <Dialog open={celModalOpen} onOpenChange={setCelModalOpen}>
        <DialogContent
          title="Declarative CEL Mapping Engine"
          description="Add custom scanner formats at runtime using Google Common Expression Language (CEL) without rebuilding Rampart."
        >
          <div className="flex flex-col gap-3 p-4 text-13">
            <p className="text-12 text-ink-2">
              Rampart's Tier 1 declarative engine compiles YAML definitions dynamically at runtime. You define the JSON/JSONL record path and CEL expressions for fields:
            </p>

            <div className="relative">
              <div className="flex items-center justify-between pb-1 text-11 font-medium text-ink-2">
                <span>IntegrationPackage Manifest (docs/19 §4):</span>
                <button
                  type="button"
                  onClick={() => {
                    if (typeof navigator !== 'undefined' && navigator.clipboard) {
                      void navigator.clipboard.writeText(SAMPLE_CEL_MAPPING_YAML);
                      toast.info('Template copied to clipboard');
                    }
                  }}
                  className="text-accent hover:underline"
                >
                  Copy YAML
                </button>
              </div>
              <pre className="max-h-56 overflow-auto rounded-ctl border border-rule bg-chrome p-3 font-mono text-11 text-ink">
                {SAMPLE_CEL_MAPPING_YAML}
              </pre>
            </div>

            <div className="flex justify-end pt-2 border-t border-rule">
              <Button type="button" onClick={() => setCelModalOpen(false)}>
                Done
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
