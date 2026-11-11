import type { ComponentType, SVGProps } from 'react';
import {
  IconAdmin, IconApplications, IconCompliance, IconFindings, IconIngestion, IconIntegrations,
  IconInventory, IconOverview, IconPolicies, IconVulnerabilities, IconWorkflow,
} from '@/components/icons';

export interface NavItem {
  id: string;
  path: string;
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  /** Phase that ships the section (docs/13 section 9) and what lands there. */
  phase: number;
  what: string;
}

/** Three unlabeled groups: what you look at, what you act on, what you configure. */
export const NAV_GROUPS: NavItem[][] = [
  [
    { id: 'overview', path: '/overview', icon: IconOverview, phase: 2, what: 'It opens with what changed since yesterday and the overdue queue.' },
    { id: 'findings', path: '/findings', icon: IconFindings, phase: 1, what: '' },
    { id: 'applications', path: '/applications', icon: IconApplications, phase: 2, what: 'Application pages with findings, assets and coverage.' },
    { id: 'inventory', path: '/inventory', icon: IconInventory, phase: 3, what: 'Assets and components; the asset graph follows in Phase 4.' },
    { id: 'vulnerabilities', path: '/vulnerabilities', icon: IconVulnerabilities, phase: 3, what: 'Vulnerabilities by CVE with tenant-wide impact.' },
  ],
  [
    { id: 'workflow', path: '/workflow', icon: IconWorkflow, phase: 2, what: 'Triage, risk acceptance and your assigned work; tickets follow in Phase 3.' },
    { id: 'compliance', path: '/compliance', icon: IconCompliance, phase: 2, what: 'Framework views with per-control status.' },
    { id: 'ingestion', path: '/ingestion', icon: IconIngestion, phase: 1, what: 'Ingest runs arrive in Phase 1; sources and the Dependency-Track page in Phase 3.' },
  ],
  [
    { id: 'policies', path: '/policies', icon: IconPolicies, phase: 2, what: 'Risk and SLA policies; automation rules and exceptions follow in Phase 5.' },
    { id: 'integrations', path: '/integrations', icon: IconIntegrations, phase: 3, what: 'The catalogue, connectors, webhooks and API tokens.' },
    { id: 'administration', path: '/administration', icon: IconAdmin, phase: 2, what: 'Users, teams, access bindings and the audit log; identity providers follow in Phase 4.' },
  ],
];
export const NAV_ITEMS = NAV_GROUPS.flat();
