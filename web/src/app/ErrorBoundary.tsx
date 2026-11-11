import { Component, type ErrorInfo, type ReactNode } from 'react';
import i18n from '@/lib/i18n';
import { Button } from '@/components/Button';
import { IconWarning } from '@/components/icons';

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<{ children: ReactNode; scope?: string }, State> {
  state: State = { error: null };
  static getDerivedStateFromError(error: Error): State {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('render error', error, info.componentStack);
  }
  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    return <ErrorView error={error} />;
  }
}

export function ErrorView({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="max-w-[56ch] p-6 text-13">
      <h2 className="flex items-center gap-1.5 text-16 font-semibold">
        <IconWarning className="text-critical" />
        {i18n.t('error.boundaryTitle')}
      </h2>
      <p className="mt-1 text-ink-2">{i18n.t('error.boundaryNext')}</p>
      <pre className="mt-2 overflow-x-auto border border-rule bg-chrome p-2 font-mono text-12">{message}</pre>
      <Button className="mt-3" onClick={() => window.location.reload()}>
        {i18n.t('error.reload')}
      </Button>
    </div>
  );
}
