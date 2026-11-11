import { render, screen } from '@testing-library/react';
import { axe } from 'vitest-axe';
import { describe, expect, it } from 'vitest';
import { BandShape } from './BandShape';
import { ScoreBar } from './ScoreBar';
import { Button } from './Button';
import { CommandLine, EmptyState } from './EmptyState';
import { ProblemMessage } from './Problem';
import { BANDS } from '@/lib/band';

describe('BandShape', () => {
  it('draws a different shape for every band', () => {
    const shapes = BANDS.map((band) => {
      const { container, unmount } = render(<BandShape band={band} />);
      const el = container.querySelector('svg')!;
      const sig = [...el.children].map((c) => c.tagName + (c.getAttribute('d') ?? c.getAttribute('r') ?? '') + c.getAttribute('fill')).join();
      unmount();
      return sig;
    });
    expect(new Set(shapes).size).toBe(5);
  });
  it('is decorative by default and named when asked', () => {
    const { container, rerender } = render(<BandShape band="critical" />);
    expect(container.querySelector('svg')).toHaveAttribute('aria-hidden', 'true');
    rerender(<BandShape band="critical" label />);
    expect(screen.getByRole('img', { name: 'Critical' })).toBeInTheDocument();
  });
});

describe('ScoreBar', () => {
  const b = { base_severity: 'high' as const, base_points: 400, total_score: 500, band: 'high' as const, factors: [{ name: 'KEV', points: 100, reason: '' }] };
  it('renders a segment per group with its length and a text alternative', () => {
    const { container } = render(<ScoreBar breakdown={b} score={500} />);
    expect(screen.getByRole('img')).toHaveAttribute('aria-label', 'Score 500 of 1000: 400 scanner severity, 100 threat intelligence.');
    const seg = container.querySelectorAll<HTMLElement>('[data-segment]');
    expect([...seg].map((s) => s.dataset.segment)).toEqual(['severity', 'threat']);
    expect(seg[0]!.style.inlineSize).toBe('40.00%');
  });
});

describe('base components pass axe', () => {
  it('buttons, empty state, command line and problem message', async () => {
    const { container } = render(
      <main>
        <Button variant="primary">Continue</Button>
        <EmptyState title="No findings yet" action={<CommandLine command="rampart upload --source default semgrep.sarif" />}>Upload a report.</EmptyState>
        <ProblemMessage problem={{ type: 't', title: 'Failed', status: 500, request_id: 'req_1' }} />
      </main>,
    );
    expect(await axe(container)).toHaveNoViolations();
    expect(screen.getByText('req_1')).toBeInTheDocument();
  });
});
