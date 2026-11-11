import { useState } from 'react';
import { QueryCache, QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { RouterProvider, type RouterHistory } from '@tanstack/react-router';
import { ProblemError, qk } from '@/api';
import { ToastProvider, TooltipProvider } from '@/components';
import { ThemeProvider } from '@/lib/theme';
import { ErrorBoundary } from './ErrorBoundary';
import { makeRouter } from './router';

export function makeQueryClient(): QueryClient {
  const client: QueryClient = new QueryClient({
    queryCache: new QueryCache({
      // A 401 from any call means the session ended: fall back to the login screen.
      onError: (error, query) => {
        if (error instanceof ProblemError && error.status === 401 && query.queryKey[0] !== 'session') {
          client.setQueryData(qk.session(), null);
        }
      },
    }),
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        refetchOnWindowFocus: false,
        retry: (count, err) => !(err instanceof ProblemError && err.status >= 400 && err.status < 500) && count < 2,
      },
    },
  });
  return client;
}

export function Providers({ client, children }: { client: QueryClient; children: React.ReactNode }) {
  return (
    <ThemeProvider>
      <QueryClientProvider client={client}>
        <TooltipProvider delayDuration={400}>
          <ToastProvider>{children}</ToastProvider>
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}

export function App({ history }: { history?: RouterHistory } = {}) {
  const [client] = useState(makeQueryClient);
  const [router] = useState(() => makeRouter(history));
  return (
    <ErrorBoundary>
      <Providers client={client}>
        <RouterProvider router={router} />
      </Providers>
    </ErrorBoundary>
  );
}
