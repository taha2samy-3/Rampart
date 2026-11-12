import {
  createRootRoute, createRoute, createRouter, createMemoryHistory, Outlet, redirect,
  useLocation, useNavigate, type RouterHistory,
} from '@tanstack/react-router';
import { lazy, Suspense, useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { EmptyState } from '@/components';
import { FindingsRoute, type FindingsSearch } from '@/routes/findings/FindingsRoute';
import { IngestionRoute, type IngestionSearch } from '@/routes/ingestion/IngestionRoute';
import { LoginPage, type LoginSearch } from '@/routes/login/LoginPage';
import { WorkflowRoute, type WorkflowSearch } from '@/routes/workflow/WorkflowRoute';
import type { AcceptanceStatus } from '@/api/types';
import { NotBuilt } from '@/routes/NotBuilt';
import { Bootstrap } from './Bootstrap';
import { ErrorView } from './ErrorBoundary';
import { NAV_ITEMS } from './nav';
import { useApp } from './session';
import { Shell } from './Shell';

const str = (v: unknown) => (typeof v === 'string' && v ? v : undefined);

const rootRoute = createRootRoute({
  component: () => (
    <Bootstrap>
      <Outlet />
    </Bootstrap>
  ),
  errorComponent: ({ error }) => <ErrorView error={error} />,
  notFoundComponent: NotFound,
});

function NotFound() {
  const { t } = useTranslation();
  return (
    <div className="p-6">
      <EmptyState title={t('notFound.title')}>{t('notFound.body')}</EmptyState>
    </div>
  );
}

/** Behind sign-in: without a session, go to the login screen and remember where we were. */
function Guard() {
  const { session } = useApp();
  const loc = useLocation();
  const navigate = useNavigate();
  const href = loc.href;
  const sent = useRef(false);
  useEffect(() => {
    if (session || sent.current) return;
    sent.current = true;
    void navigate({ to: '/login', search: { return_to: href }, replace: true });
  }, [session, href, navigate]);
  if (!session) return null;
  return <Shell />;
}

const validateLogin = (s: Record<string, unknown>): LoginSearch => ({
  return_to: str(s.return_to),
  error: str(s.error),
  request_id: str(s.request_id),
});

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  validateSearch: validateLogin,
  component: function Login() {
    return <LoginPage search={loginRoute.useSearch()} />;
  },
});
const tenantLoginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/t/$tenant/login',
  validateSearch: validateLogin,
  component: function TenantLogin() {
    return <LoginPage tenant={tenantLoginRoute.useParams().tenant} search={tenantLoginRoute.useSearch()} />;
  },
});

const appRoute = createRoute({ getParentRoute: () => rootRoute, id: 'app', component: Guard });

const validateFindings = (s: Record<string, unknown>): FindingsSearch => ({
  q: str(s.q),
  sel: str(s.sel),
  sort: str(s.sort),
  density: s.density === 'compact' ? 'compact' : undefined,
});

const indexRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/findings' });
  },
});
const findingsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/findings',
  validateSearch: validateFindings,
  component: function Findings() {
    return <FindingsRoute search={findingsRoute.useSearch()} />;
  },
});
/** Deep link used in tickets and chat: /t/<tenant>/findings/<id>. */
const deepFindingRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/t/$tenant/findings/$id',
  validateSearch: validateFindings,
  component: function DeepFinding() {
    return <FindingsRoute search={deepFindingRoute.useSearch()} deepLinkId={deepFindingRoute.useParams().id} />;
  },
});

const ingestionRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/ingestion',
  validateSearch: (s: Record<string, unknown>): IngestionSearch => ({ sel: str(s.sel) }),
  component: function Ingestion() {
    return <IngestionRoute search={ingestionRoute.useSearch()} />;
  },
});

const workflowRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/workflow',
  validateSearch: (s: Record<string, unknown>): WorkflowSearch => ({
    sel: str(s.sel),
    status: ['pending', 'approved', 'rejected', 'expired', 'revoked'].includes(s.status as string) ? (s.status as AcceptanceStatus) : undefined,
  }),
  component: function Workflow() {
    return <WorkflowRoute search={workflowRoute.useSearch()} />;
  },
});

const placeholderRoutes = NAV_ITEMS.filter((n) => n.id !== 'findings' && n.id !== 'ingestion' && n.id !== 'workflow').map((item) =>
  createRoute({ getParentRoute: () => appRoute, path: item.path, component: () => <NotBuilt item={item} /> }),
);

// Dev only: the style guide is a lazy chunk and is not registered in production builds.
const Styleguide = lazy(() => import('@/routes/styleguide/Styleguide').then((m) => ({ default: m.Styleguide })));
const styleguideRoute = createRoute({ getParentRoute: () => rootRoute, path: '/styleguide', component: () => <Suspense fallback={null}><Styleguide /></Suspense> });

const routeTree = rootRoute.addChildren([
  loginRoute,
  ...(import.meta.env.DEV ? [styleguideRoute] : []),
  tenantLoginRoute,
  appRoute.addChildren([indexRoute, findingsRoute, deepFindingRoute, ingestionRoute, workflowRoute, ...placeholderRoutes]),
]);

export function makeRouter(history?: RouterHistory) {
  return createRouter({ routeTree, history, defaultPreload: false });
}
export { createMemoryHistory };

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof makeRouter>;
  }
}
