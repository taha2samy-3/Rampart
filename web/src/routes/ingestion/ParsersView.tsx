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

function categorizeParser(id: string, name?: string, desc?: string): string {
  const lower = (id + ' ' + (name || '') + ' ' + (desc || '')).toLowerCase();
  if (lower.includes('sbom')) return 'SBOM';
  if (lower.includes('sarif') || lower.includes('semgrep') || lower.includes('bandit') || lower.includes('sast')) return 'SAST';
  if (lower.includes('gitleaks') || lower.includes('trufflehog') || lower.includes('secret')) return 'Secrets';
  if (lower.includes('checkov') || lower.includes('kubebench') || lower.includes('prowler') || lower.includes('iac') || lower.includes('cloud')) return 'IaC & Cloud';
  if (lower.includes('openvex') || lower.includes('vex')) return 'VEX';
  if (lower.includes('zap') || lower.includes('nuclei') || lower.includes('dast')) return 'DAST';
  if (lower.includes('sca') || lower.includes('trivy') || lower.includes('grype') || lower.includes('snyk') || lower.includes('dependency')) return 'SCA';
  return 'General';
}

function parserFormat(id: string, name?: string): string {
  const lower = (id + ' ' + (name || '')).toLowerCase();
  if (lower.includes('cyclonedx')) return 'JSON / XML';
  if (lower.includes('spdx')) return 'JSON / Tag-Value';
  if (lower.includes('jsonl') || lower.includes('trufflehog') || lower.includes('nuclei')) return 'JSON Lines (.jsonl)';
  if (lower.includes('sarif')) return 'SARIF / JSON';
  return 'JSON';
}

const SAMPLE_CEL_MAPPING_YAML = `apiVersion: rampart.aspm.dev/v1alpha1
kind: ClusterParser
metadata:
  name: custom-scanner-mapping
spec:
  runtime: mapping
  version: 1.0.0
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
      startLine: "rec.line_number"
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
    // No fallback list: what is shown is what this server reads, including this tenant's parser packages (D98).
    queryFn: ({ signal }) => listParsers(signal),
  });

  const parsers = useMemo(() => query.data ?? [], [query.data]);
  const installed = parsers.filter((p) => p.support_level !== 'builtin').length;

  const filtered = useMemo(() => {
    return parsers.filter((p) => {
      const cat = categorizeParser(p.id, p.name, p.description);
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
            <h2 className="display text-16 font-semibold text-ink">Parsers and formats</h2>
            <span className="text-13 text-ink-2">
              {parsers.length - installed} built in{installed > 0 ? `, ${installed} installed as ${installed === 1 ? 'a package' : 'packages'}` : ''}
            </span>
          </div>
          <p className="mt-1 text-13 text-ink-2">
            Each upload is read by the parser it names, or by the one that recognises the file. A format Rampart does not
            read can be added as a parser package, with no release.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start tablet:self-auto">
          <Button variant="secondary" onClick={() => setCelModalOpen(true)}>
            Add a parser package
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
                  ? 'bg-surface font-semibold text-ink'
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
      {query.isError ? (
        <p role="alert" className="text-13 text-ink-2">
          The parsers could not be loaded.
        </p>
      ) : query.isLoading ? (
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
                <Th className="w-[150px]">Source</Th>
                <Th>Description</Th>
                <Th align="end" className="w-[90px]">Action</Th>
              </tr>
            </THead>
            <TBody>
              {filtered.map((p) => {
                const cat = categorizeParser(p.id, p.name, p.description);
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
                        <span className="font-mono text-12 text-ink-2">{p.id}</span>
                      </div>
                    </Td>
                    <Td className="text-12 text-ink-2">{cat}</Td>
                    <Td className="font-mono text-12 text-ink-2">{format}</Td>
                    <Td className="text-12 text-ink-2">
                      {/* plain words, no pill: colour is for risk (docs/13 §6) */}
                      {p.support_level === 'builtin' ? 'Built in' : 'Installed package'}
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
                <dd className="m-0 font-medium">{categorizeParser(selectedParser.id, selectedParser.name, selectedParser.description)}</dd>
                <dt className="text-ink-2">Format:</dt>
                <dd className="m-0 font-mono text-12">{parserFormat(selectedParser.id, selectedParser.name)}</dd>
                <dt className="text-ink-2">Version:</dt>
                <dd className="m-0 font-mono text-12">{selectedParser.version}</dd>
                <dt className="text-ink-2">Execution:</dt>
                <dd className="m-0">Streaming Zero-Copy JIT Parser</dd>
              </dl>

              <div className="border-t border-rule pt-3">
                <h4 className="mb-1 text-12 font-semibold text-ink">Upload via CLI:</h4>
                <CommandLine
                  command={`rampart upload --parser ${selectedParser.id.replace(/^builtin:/, '')} --app <application> --source default report.${parserFormat(selectedParser.id).toLowerCase().includes('xml') ? 'xml' : 'json'}`}
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
              <div className="flex items-center justify-between pb-1 text-12 font-medium text-ink-2">
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
              <pre className="max-h-56 overflow-auto rounded-ctl border border-rule bg-chrome p-3 font-mono text-12 text-ink">
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
