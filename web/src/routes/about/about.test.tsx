import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const mockScoring = {
  product: 'Rampart',
  version: '0.3.0',
  customised: true,
  risk: {
    base: { critical: 100, high: 70, medium: 40, low: 10, info: 0 },
    bands: { critical: 800, high: 500, medium: 200 },
    factors: [
      {
        name: 'IN_KEV',
        when: 'finding.in_kev == true',
        points: 300,
        reason: 'Known exploited in the wild',
        group: 'threat',
      },
      {
        name: 'PRODUCTION_ENV',
        when: "app.environment == 'production'",
        points: 60,
        reason: 'Running in live production',
        group: 'context',
      },
      {
        name: 'HAS_VPN_REDUCTION',
        when: 'has(app.attributes.has_vpn) && app.attributes.has_vpn == true',
        points: -80,
        reason: 'Protected by enterprise VPN perimeter',
        group: 'reduction',
      },
    ],
  },
  sla: {
    matrix: {
      critical: { critical: 7, high: 14, medium: 30, low: 60 },
      high: { critical: 14, high: 30, medium: 60, low: 90 },
      medium: { critical: 30, high: 60, medium: 90, low: 180 },
      low: { critical: 60, high: 90, medium: 180, low: 365 },
    },
    kevDueDate: true,
    maxDays: 365,
    startFrom: 'firstSeen',
    restartOnReactivation: true,
    pauseDuringRiskAcceptance: true,
  },
  environments: ['production', 'staging'],
  application_types: ['repo', 'service'],
};

describe('About and Scoring Rules Route', () => {
  it('renders the policy version, dynamic factors, and attribute badges', async () => {
    mockFetch({ loggedIn: true, scoring: mockScoring });

    renderApp('/about');

    // Policy info & factors
    expect(await screen.findByText('Version 0.3.0')).toBeInTheDocument();
    expect(screen.getByText('IN_KEV')).toBeInTheDocument();
    expect(screen.getByText('PRODUCTION_ENV')).toBeInTheDocument();
    expect(screen.getByText('HAS_VPN_REDUCTION')).toBeInTheDocument();

    // What each rule reads, in words (no coloured pills: docs/13)
    expect(screen.getByText('threat intelligence')).toBeInTheDocument();
    expect(screen.getByText('reads the environment')).toBeInTheDocument();
    expect(screen.getByText('reads application attributes, lowers the score')).toBeInTheDocument();

    // Points display
    expect(screen.getByText('+300')).toBeInTheDocument();
    expect(screen.getByText('+60')).toBeInTheDocument();
    expect(screen.getByText('−80')).toBeInTheDocument();
  });

  it('allows expanding rules and filtering by group', async () => {
    const user = userEvent.setup();
    mockFetch({ loggedIn: true, scoring: mockScoring });

    renderApp('/about');

    // Click "Expand all rules"
    const expandBtn = await screen.findByRole('button', { name: /expand all rules/i });
    await user.click(expandBtn);

    // CEL rules should now be visible
    expect(screen.getByText('has(app.attributes.has_vpn) && app.attributes.has_vpn == true')).toBeInTheDocument();
    expect(screen.getByText("app.environment == 'production'")).toBeInTheDocument();

    // Filter by Threat group
    const threatFilterBtn = screen.getByRole('button', { name: /is it being exploited/i });
    await user.click(threatFilterBtn);

    // Only threat should remain
    expect(screen.getByText('IN_KEV')).toBeInTheDocument();
    expect(screen.queryByText('HAS_VPN_REDUCTION')).not.toBeInTheDocument();
  });
});
