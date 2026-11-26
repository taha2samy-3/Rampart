import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { ApplicationScoreCard } from './ApplicationScoreCard';
import type { ApplicationPage } from '@/api/types';

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, to, search, className, ...props }: { children?: React.ReactNode; to?: string; search?: Record<string, string>; className?: string; [key: string]: unknown }) => (
    <a href={`${to}?${new URLSearchParams((search ?? {}) as Record<string, string>).toString()}`} className={className} {...props}>
      {children}
    </a>
  ),
}));

// Consistent with the server: the score is the highest of the open findings, and none is critical, so under the
// built-in policy (critical 800, high 600, medium 300) the band is high.
const mockApp: ApplicationPage = {
  id: 'app_payments',
  name: 'Payments Service',
  slug: 'payments-service',
  business_criticality: 'high',
  internet_facing: true,
  risk_score: 742,
  exposure_count: 8,
  open: { critical: 0, high: 8, medium: 14, low: 3 },
  sla: { within: 20, late: 4, breached: 3, adherence: 0.74 },
  sla_breached: 3,
  mttr: [],
  coverage: [],
  top_findings: [],
};

const BUILTIN = { critical: 800, high: 600, medium: 300 };

describe('ApplicationScoreCard', () => {
  it('shows the score and the band the server gave (the worst open band), not one worked out from the score', () => {
    render(<ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" thresholds={BUILTIN} />);
    expect(screen.getByText('742')).toBeInTheDocument();
    expect(screen.getByText('High')).toBeInTheDocument();
    const meter = screen.getByRole('meter');
    expect(meter).toHaveAttribute('aria-valuenow', '742');
    expect(meter).toHaveAttribute('aria-valuetext', '742 of 1000, High');
  });

  it('draws the markers at the bounds the server sent, whatever they are', () => {
    const { rerender } = render(<ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" thresholds={BUILTIN} />);
    expect(screen.getByTestId('band-marker-medium').style.insetInlineStart).toBe('30%');
    expect(screen.getByTestId('band-marker-critical').style.insetInlineStart).toBe('80%');
    expect(screen.getByText(/Medium from 300, high from 600, critical from 800/)).toBeInTheDocument();

    rerender(<ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" thresholds={{ critical: 900, high: 700, medium: 450 }} />);
    expect(screen.getByTestId('band-marker-medium').style.insetInlineStart).toBe('45%');
    expect(screen.getByTestId('band-marker-high').style.insetInlineStart).toBe('70%');
  });

  it('draws no marker and says so when the bounds are not loaded', () => {
    render(<ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" thresholds={null} />);
    expect(screen.queryByTestId('band-marker-medium')).toBeNull();
    expect(screen.getByText(/band bounds could not be loaded/)).toBeInTheDocument();
  });

  it('has no KPI tiles, no "% of scale" and no "In policy"', () => {
    const { container } = render(<ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" thresholds={BUILTIN} />);
    expect(container.textContent).not.toMatch(/% of scale|In policy|Exposures|SLA Adherence/);
  });

  it('links each band to the findings it counts', () => {
    render(<ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" thresholds={BUILTIN} />);
    expect(screen.getByRole('link', { name: /8 high/ })).toHaveAttribute('href', expect.stringContaining('risk%3Ahigh'));
    expect(screen.getByRole('link', { name: /14 medium/ })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /0 critical/ })).toBeInTheDocument();
  });

  it('shows no band, and no info band, for an application with nothing open', () => {
    const cleanApp: ApplicationPage = { ...mockApp, risk_score: 0, exposure_count: 0, open: { critical: 0, high: 0, medium: 0, low: 0 } };
    const { container } = render(<ApplicationScoreCard app={cleanApp} appQuerySlug="payments-service" thresholds={BUILTIN} />);
    expect(screen.getByText('No open finding')).toBeInTheDocument();
    expect(container.querySelector('[data-band="info"]')).toBeNull();
    expect(container.textContent).not.toMatch(/Info/);
  });

  it('passes axe', async () => {
    const { container } = render(
      <main>
        <ApplicationScoreCard app={mockApp} appQuerySlug="payments-service" thresholds={BUILTIN} />
      </main>,
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});
