import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { ApplicationScoreCard } from './ApplicationScoreCard';
import type { ApplicationPage } from '@/api/types';

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, to, search, className, ...props }: any) => (
    <a href={`${to}?${new URLSearchParams(search as any).toString()}`} className={className} {...props}>
      {children}
    </a>
  ),
}));

const mockApp: ApplicationPage = {
  id: 'app_payments',
  name: 'Payments Service',
  slug: 'payments-service',
  business_criticality: 'high',
  internet_facing: true,
  risk_score: 742,
  exposure_count: 5,
  open: {
    critical: 2,
    high: 8,
    medium: 14,
    low: 3,
  },
  sla: {
    within: 20,
    late: 4,
    breached: 3,
    adherence: 0.74,
  },
  sla_breached: 3,
  mttr: [],
  coverage: [],
  top_findings: [],
};

describe('ApplicationScoreCard', () => {
  it('renders calibrated posture score and semantic band glyph', () => {
    const { container } = render(
      <ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" />,
    );

    expect(screen.getByText('742')).toBeInTheDocument();
    expect(screen.getByText('/ 1000')).toBeInTheDocument();
    expect(screen.getByText(/High Risk/i)).toBeInTheDocument();

    const progressbar = screen.getByRole('progressbar');
    expect(progressbar).toHaveAttribute('aria-valuenow', '742');
    expect(progressbar).toHaveAttribute('aria-valuemin', '0');
    expect(progressbar).toHaveAttribute('aria-valuemax', '1000');
    expect(progressbar).toHaveAttribute('aria-valuetext', '742 of 1000, High risk posture');

    // Threshold indicators
    expect(screen.getByText('Low 100')).toBeInTheDocument();
    expect(screen.getByText('Med 400')).toBeInTheDocument();
    expect(screen.getByText('High 600')).toBeInTheDocument();
    expect(screen.getByText('Crit 800')).toBeInTheDocument();

    // Verify SVG BandShape rendered
    const svgs = container.querySelectorAll('svg');
    expect(svgs.length).toBeGreaterThan(0);
  });

  it('renders operational stats: exposure, findings, and SLA adherence', () => {
    render(<ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" />);

    expect(screen.getByText('5')).toBeInTheDocument(); // active exposures
    expect(screen.getByText('27')).toBeInTheDocument(); // total open findings (2+8+14+3)
    expect(screen.getByText('74%')).toBeInTheDocument(); // adherence
    expect(screen.getByText('3 breached')).toBeInTheDocument(); // breached badge
  });

  it('renders severity breakdown links to filtered findings view', () => {
    render(<ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" />);

    expect(screen.getByRole('link', { name: /2.*Critical/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /8.*High/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /14.*Medium/i })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /3.*Low/i })).toBeInTheDocument();
  });

  it('handles clean / zero-risk applications gracefully', () => {
    const cleanApp: ApplicationPage = {
      ...mockApp,
      risk_score: 0,
      exposure_count: 0,
      open: { critical: 0, high: 0, medium: 0, low: 0 },
      sla: { adherence: 1.0, within: 10, late: 0, breached: 0 },
    };

    render(<ApplicationScoreCard app={cleanApp} appQuerySlug="payments-service" />);

    const zeros = screen.getAllByText('0');
    expect(zeros.length).toBeGreaterThan(0);
    expect(screen.getByText(/Info Risk/i)).toBeInTheDocument();
    expect(screen.getByText('100%')).toBeInTheDocument();
  });

  it('passes automated accessibility (axe) testing', async () => {
    const { container } = render(
      <main>
        <ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" />
      </main>,
    );
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
