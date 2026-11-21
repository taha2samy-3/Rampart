import { useState, useRef, useId } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Dialog, DialogContent, Button, useToast, Spinner, IconWarning } from '@/components';
import { post, toProblem } from '@/api';

export interface VEXRejection {
  vulnerability: string;
  packages?: string[];
  reason: string;
}

export interface VEXReport {
  format: string;
  dry_run: boolean;
  statements: number;
  matched: number;
  applied: number;
  unchanged: number;
  stale: number;
  rejected?: VEXRejection[];
  unmatched?: VEXRejection[];
  failed?: Array<{ id: string; error: string }>;
}

export function VEXUploadModal({
  open,
  onOpenChange,
  applicationId,
  applicationName,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  applicationId: string;
  applicationName: string;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [fileContent, setFileContent] = useState<string>('');
  const [analyzing, setAnalyzing] = useState(false);
  const [applying, setApplying] = useState(false);
  const [report, setReport] = useState<VEXReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const toast = useToast();
  const queryClient = useQueryClient();
  const fileInputId = useId();

  const handleFileChange = (selectedFile: File) => {
    setFile(selectedFile);
    setError(null);
    setReport(null);

    const reader = new FileReader();
    reader.onload = async (e) => {
      const content = e.target?.result as string;
      setFileContent(content);
      // Run dry-run preview immediately
      setAnalyzing(true);
      try {
        let parsed: unknown;
        try {
          parsed = JSON.parse(content);
        } catch {
          throw new Error('File is not a valid JSON document');
        }
        const rep = await post<VEXReport>('/api/v1/vex', parsed, {
          query: { application: applicationId, dryRun: true },
        });
        setReport(rep);
      } catch (err: unknown) {
        const prob = toProblem(err);
        setError(prob.detail || prob.title || 'Failed to analyze VEX document');
      } finally {
        setAnalyzing(false);
      }
    };
    reader.onerror = () => {
      setError('Could not read the selected file');
    };
    reader.readAsText(selectedFile);
  };

  const handleApply = async () => {
    if (!fileContent) return;
    setApplying(true);
    setError(null);
    try {
      let parsed: unknown;
      try {
        parsed = JSON.parse(fileContent);
      } catch {
        throw new Error('File is not a valid JSON document');
      }
      const rep = await post<VEXReport>('/api/v1/vex', parsed, {
        query: { application: applicationId, dryRun: false },
      });
      toast.info(`VEX applied: ${rep.applied} updated, ${rep.unchanged} unchanged, ${rep.stale} protected by prior human triage.`);
      void queryClient.invalidateQueries({ queryKey: ['applications', applicationId] });
      void queryClient.invalidateQueries({ queryKey: ['findings'] });
      void queryClient.invalidateQueries({ queryKey: ['applications', applicationId, 'components'] });
      onOpenChange(false);
    } catch (err: unknown) {
      const prob = toProblem(err);
      setError(prob.detail || prob.title || 'Failed to apply VEX decisions');
    } finally {
      setApplying(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setFileContent('');
    setReport(null);
    setError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open && (
        <DialogContent
          title="Apply VEX Document"
          description={`Upload and apply an authoritative VEX document (OpenVEX, CycloneDX VEX, or CSAF) to "${applicationName}". Decisions will update existing findings without creating duplicate alerts.`}
          closeLabel="Cancel"
          className="max-w-xl"
        >
          <div className="space-y-4">
            {!file ? (
              <div
                className="flex flex-col items-center justify-center rounded-ctl border-2 border-dashed border-rule p-6 text-center hover:border-accent cursor-pointer transition-colors"
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  id={fileInputId}
                  ref={fileInputRef}
                  type="file"
                  accept=".json,.vex,.vex.json,.cdx.json"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) handleFileChange(f);
                  }}
                />
                <div className="text-28 opacity-60">📄</div>
                <p className="mt-2 text-13 font-medium text-ink">Choose a VEX document or drop it here</p>
                <p className="m-0 text-12 text-ink-2">Supports OpenVEX (.json) and CycloneDX VEX / VDR (up to 16 MiB)</p>
                <Button variant="secondary" className="mt-3 h-8 text-12">
                  Browse file
                </Button>
              </div>
            ) : (
              <div className="rounded-ctl border border-rule p-3 bg-canvas-subtle">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-16">📄</span>
                    <div>
                      <p className="m-0 text-13 font-semibold text-ink">{file.name}</p>
                      <p className="m-0 text-11 text-ink-2">{(file.size / 1024).toFixed(1)} KB</p>
                    </div>
                  </div>
                  <Button variant="ghost" className="h-7 px-2 text-11" onClick={handleReset} disabled={analyzing || applying}>
                    Change file
                  </Button>
                </div>
              </div>
            )}

            {analyzing && (
              <div className="flex items-center justify-center gap-2 py-4 text-12 text-ink-2">
                <Spinner size={16} />
                <span>Simulating dry-run impact against application inventory...</span>
              </div>
            )}

            {error && (
              <div className="flex items-start gap-2 rounded-ctl border border-critical/30 bg-critical/10 p-3 text-12 text-critical">
                <IconWarning className="size-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            {report && !analyzing && (
              <div className="rounded-ctl border border-rule p-3.5 space-y-3 bg-canvas">
                <div className="flex items-center justify-between border-b border-rule pb-2">
                  <span className="text-12 font-medium text-ink">Dry-Run Preview Result</span>
                  <span className="rounded-full bg-accent/10 px-2 py-0.5 text-11 font-mono font-medium text-accent">
                    Format: {report.format}
                  </span>
                </div>

                <div className="grid grid-cols-4 gap-2 text-center">
                  <div className="rounded-ctl border border-rule p-2 bg-canvas-subtle">
                    <div className="text-16 font-semibold text-ink">{report.statements}</div>
                    <div className="text-11 text-ink-2">Statements</div>
                  </div>
                  <div className="rounded-ctl border border-rule p-2 bg-canvas-subtle">
                    <div className="text-16 font-semibold text-accent">{report.matched}</div>
                    <div className="text-11 text-ink-2">Matched</div>
                  </div>
                  <div className="rounded-ctl border border-rule p-2 bg-canvas-subtle">
                    <div className="text-16 font-semibold text-resolved">{report.applied}</div>
                    <div className="text-11 text-ink-2">To Apply</div>
                  </div>
                  <div className="rounded-ctl border border-rule p-2 bg-canvas-subtle">
                    <div className="text-16 font-semibold text-ink-2">{report.unchanged}</div>
                    <div className="text-11 text-ink-2">Unchanged</div>
                  </div>
                </div>

                {report.stale > 0 && (
                  <p className="m-0 text-11 text-ink-2">
                    ℹ️ <strong>{report.stale}</strong> statement{report.stale > 1 ? 's are' : ' is'} older than a manual human triage on the same finding and will not override it.
                  </p>
                )}

                {report.unmatched && report.unmatched.length > 0 && (
                  <div className="text-11 text-ink-2 border-t border-rule pt-2">
                    <span className="font-medium text-ink">Unmatched in this app: </span>
                    {report.unmatched.length} statement{report.unmatched.length > 1 ? 's name' : ' names'} packages not found in current inventory.
                  </div>
                )}

                {report.rejected && report.rejected.length > 0 && (
                  <div className="text-11 text-critical border-t border-rule pt-2">
                    <span className="font-medium">Rejected statements: </span>
                    {report.rejected.length} (e.g. {report.rejected[0]?.reason})
                  </div>
                )}
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-rule">
              <Button variant="secondary" onClick={() => onOpenChange(false)} disabled={applying}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={() => void handleApply()}
                disabled={!report || analyzing || applying || report.matched === 0}
                loading={applying}
              >
                {report && report.applied > 0 ? `Apply Decisions (${report.applied})` : 'Confirm & Apply'}
              </Button>
            </div>
          </div>
        </DialogContent>
      )}
    </Dialog>
  );
}
