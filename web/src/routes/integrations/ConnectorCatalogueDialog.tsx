import { useId, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { get, post, qk } from '@/api';
import { ProblemError } from '@/api/client';
import { Button, Dialog, DialogContent, Spinner } from '@/components';

/** One connector type, as GET /api/v1/connectors/catalogue describes it (D82). */
export interface CatalogueEntry {
  type: string;
  name: string;
  kind: 'tracker' | 'notifier' | 'source';
  directions: string[];
  description: string;
  config_key: string;
  config_schema: Record<string, unknown>;
  secrets: { field: string; holds: string; purpose: string }[];
  example: string;
}

interface ValidateResult {
  valid: boolean;
  reason?: string;
  error?: string;
}

/**
 * The connector catalogue (D82). Connectors are Kubernetes resources: this dialog helps write one and checks it
 * against the server's own validation, then the user applies it with kubectl, GitOps or `rampart apply -f`.
 * It never creates a connector and never asks for a secret value: those go in the Secret, applied the same way.
 */
export function ConnectorCatalogueDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [selected, setSelected] = useState<CatalogueEntry | null>(null);
  const [yaml, setYaml] = useState('');
  const [result, setResult] = useState<ValidateResult | null>(null);
  const [checking, setChecking] = useState(false);
  const yamlId = useId();

  const catalogue = useQuery({
    queryKey: [...qk.connectors.all(), 'catalogue'],
    queryFn: ({ signal }) => get<{ items: CatalogueEntry[] }>('/api/v1/connectors/catalogue', { signal }),
    enabled: open,
  });

  const close = (next: boolean) => {
    if (!next) {
      setSelected(null);
      setResult(null);
    }
    onOpenChange(next);
  };

  const choose = (e: CatalogueEntry) => {
    setSelected(e);
    setYaml(e.example);
    setResult(null);
  };

  const validate = async () => {
    setChecking(true);
    setResult(null);
    try {
      setResult(await post<ValidateResult>('/api/v1/connectors/validate', { resource: yaml }));
    } catch (err) {
      setResult({ valid: false, error: err instanceof ProblemError ? err.problem.title : 'The server could not check the resource.' });
    } finally {
      setChecking(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent
        title={selected ? `Configure ${selected.name}` : 'Integration Catalogue'}
        description={
          selected
            ? selected.description
            : 'Connectors are Kubernetes resources. Pick a type to get a resource the server accepts, check it here, then apply it.'
        }
      >
        {!selected ? (
          catalogue.isLoading ? (
            <Spinner label="Loading connector types" />
          ) : catalogue.isError ? (
            <p role="alert" className="text-13 text-ink-2">
              The connector catalogue could not be loaded.
            </p>
          ) : (
            <ul className="flex flex-col divide-y divide-rule" aria-label="Connector types">
              {(catalogue.data?.items ?? []).map((e) => (
                <li key={e.type}>
                  <button
                    type="button"
                    onClick={() => choose(e)}
                    className="flex w-full flex-col items-start gap-0.5 px-1 py-2.5 text-start hover:bg-surface-2 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
                  >
                    <span className="text-13 font-medium text-ink">{e.name}</span>
                    <span className="text-12 text-ink-2">
                      {e.kind} · {e.directions.join(' or ')}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )
        ) : (
          <div className="flex flex-col gap-3">
            <div>
              <h3 className="mb-1 text-12 font-medium text-ink">Secrets it reads</h3>
              <ul className="flex flex-col gap-1 text-12 text-ink-2">
                {selected.secrets.map((s) => (
                  <li key={s.field}>
                    <code>{s.field}</code>: {s.holds} ({s.purpose})
                  </li>
                ))}
              </ul>
              <p className="mt-1 text-12 text-ink-2">
                Put the values in the Secret and apply it yourself. This page never asks for them.
              </p>
            </div>

            <div className="flex flex-col gap-1">
              <label htmlFor={yamlId} className="text-12 font-medium text-ink">
                Connector resource (YAML)
              </label>
              <textarea
                id={yamlId}
                rows={14}
                spellCheck={false}
                value={yaml}
                onChange={(ev) => {
                  setYaml(ev.target.value);
                  setResult(null);
                }}
                className="resize-y rounded-ctl border border-rule bg-surface px-3 py-2 font-mono text-12 text-ink focus:outline-none focus:ring-1 focus:ring-accent"
              />
            </div>

            {result && (
              <p role="status" className="text-13 text-ink">
                {result.valid
                  ? 'The server accepts this resource. Replace the placeholders, then apply it: kubectl apply -f connector.yaml'
                  : `Not accepted${result.reason ? ` (${result.reason})` : ''}: ${result.error ?? ''}`}
              </p>
            )}

            <div className="flex justify-between gap-2">
              <Button variant="ghost" onClick={() => setSelected(null)}>
                Back
              </Button>
              <div className="flex gap-2">
                <Button
                  variant="secondary"
                  onClick={() => {
                    void navigator.clipboard?.writeText(yaml);
                  }}
                >
                  Copy YAML
                </Button>
                <Button variant="primary" onClick={() => void validate()} disabled={checking}>
                  {checking ? 'Checking…' : 'Validate'}
                </Button>
              </div>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
