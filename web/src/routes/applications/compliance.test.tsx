import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { app, appPage, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const fw = (over: Record<string, unknown>) => ({ id: 'x', name: 'X', version: '1', origin: 'builtin', verdict: 'meets', controls: 10, clear: 10, open: 0, at_risk: 0, not_assessed: 0, open_findings: 0, overdue_findings: 0, accepted_findings: 0, window_days: 30, ...over });

async function open(appCompliance: unknown) {
  mockFetch({ loggedIn: true, apps: [app(1)], appPages: { 'app-1': appPage(1) }, appCompliance });
  renderApp('/applications/app-1');
  return (await screen.findByRole('heading', { name: 'Compliance', level: 2 })).closest('section')!;
}

describe('Application page: compliance', () => {
  it('says which frameworks the application meets today, and why not where it does not', async () => {
    const section = await open({
      application: 'app-1', evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: ['PCI DSS 4.0.1 requirement 6'],
      frameworks: [
        fw({ id: 'cwe-top25', name: 'CWE Top 25', version: '2024', verdict: 'meets', controls: 25, clear: 25 }),
        fw({ id: 'owasp-top10-2021', name: 'OWASP Top 10', version: '2021', verdict: 'gaps', controls: 10, clear: 7, open: 2, not_assessed: 1, open_findings: 5, overdue_findings: 3 }),
        fw({ id: 'acme-policy', name: 'ACME secure coding', version: '2026.1', origin: 'tenant', verdict: 'partial', controls: 4, clear: 1, not_assessed: 3, logo: '/api/v1/taxonomies/acme-policy/logo?v=1' }),
      ],
    });
    expect(await within(section).findByText('Meets all 25 controls.')).toBeInTheDocument();
    expect(within(section).getByText('2 of 10 controls are out of compliance: 3 findings are past their deadline, 5 are open in all.')).toBeInTheDocument();
    expect(within(section).getByText(/1 of 4 controls clear; 3 cannot be read yet/)).toBeInTheDocument();
    expect(within(section).getByText(/PCI DSS 4.0.1 requirement 6/)).toBeInTheDocument();
    // each row opens the Compliance page on that framework, for this application
    const link = within(section).getByRole('link', { name: /OWASP Top 10/ });
    expect(link.getAttribute('href')).toContain('framework=owasp-top10-2021');
    expect(link.getAttribute('href')).toContain('application=app-1');
    // the bar says its numbers to a screen reader, and the installed framework shows its own logo
    expect(within(section).getByRole('img', { name: '7 controls clear, 0 at risk, 2 out of compliance, 1 not read' })).toBeInTheDocument();
    expect(section.querySelector('img[src="/api/v1/taxonomies/acme-policy/logo?v=1"]')).not.toBeNull();
  });

  it('says when no framework reads the application', async () => {
    const section = await open({ application: 'app-1', evaluated_at: '2026-11-17T00:00:00Z', frameworks: [], not_in_scope: [] });
    expect(await within(section).findByText('No framework reads this application yet.')).toBeInTheDocument();
  });

  it('reports a failed reading instead of an empty list', async () => {
    const section = await open('error');
    expect(await within(section).findByText('The compliance reading could not be loaded.', undefined, { timeout: 4000 })).toBeInTheDocument();
  });

  it('has no accessibility violations', async () => {
    const section = await open({ application: 'app-1', evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: [], frameworks: [fw({ id: 'cwe-top25', name: 'CWE Top 25', version: '2024' })] });
    await within(section).findByText('Meets all 10 controls.');
    expect(await axe(section)).toHaveNoViolations();
  });

  // PCI DSS 6.3.3 gives a month for a critical patch; Vanta and Drata count an item overdue only past its SLA. Open is not
  // out of compliance: it is at risk, with a date to meet.
  it('says a control is at risk while its findings are open but inside their deadline, and gives the date', async () => {
    const section = await open({
      application: 'app-1', evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: [],
      frameworks: [fw({ id: 'owasp-top10-2021', name: 'OWASP Top 10', version: '2021', verdict: 'at_risk', controls: 10, clear: 8, at_risk: 2, open_findings: 4, earliest_due: '2026-12-01T00:00:00Z' })],
    });
    expect(await within(section).findByText(/2 of 10 controls have open findings, none past their deadline\. The first falls due .*Dec.*2026\./)).toBeInTheDocument();
    expect(within(section).getByRole('img', { name: '8 controls clear, 2 at risk, 0 out of compliance, 0 not read' })).toBeInTheDocument();
  });

  describe('many frameworks', () => {
    const many = [
      fw({ id: 'a-meets', name: 'A meets', verdict: 'meets' }),
      fw({ id: 'b-risk-late', name: 'B risk late', verdict: 'at_risk', at_risk: 1, clear: 9, earliest_due: '2026-12-20T00:00:00Z' }),
      fw({ id: 'c-gaps', name: 'C gaps', verdict: 'gaps', open: 1, clear: 9, open_findings: 2, overdue_findings: 1 }),
      fw({ id: 'd-risk-soon', name: 'D risk soon', verdict: 'at_risk', at_risk: 1, clear: 9, earliest_due: '2026-11-25T00:00:00Z' }),
      fw({ id: 'e-partial', name: 'E partial', verdict: 'partial', not_assessed: 2, clear: 8 }),
    ];
    const names = (section: HTMLElement) => within(section).getAllByRole('link').map((l) => l.textContent?.replace(/\s+\d.*$/, '').trim());
    const payload = { application: 'app-1', evaluated_at: '2026-11-17T00:00:00Z', not_in_scope: [], frameworks: many };

    it('puts what needs action first: out of compliance, then at risk by the nearest date, then the rest, and folds the others', async () => {
      localStorage.removeItem('rampart.pinnedFrameworks');
      const section = await open(payload);
      await within(section).findByText(/C gaps/);
      expect(names(section)).toEqual(['C gaps', 'D risk soon', 'B risk late']); // three show
      await userEvent.click(within(section).getByRole('button', { name: 'Show 2 more' }));
      expect(names(section)).toEqual(['C gaps', 'D risk soon', 'B risk late', 'E partial', 'A meets']);
      await userEvent.click(within(section).getByRole('button', { name: 'Show fewer' }));
      expect(names(section)).toHaveLength(3);
    });

    it('pins a framework to the top, keeps it after a reload, and unpins it', async () => {
      localStorage.removeItem('rampart.pinnedFrameworks');
      const section = await open(payload);
      await within(section).findByText(/C gaps/);
      await userEvent.click(within(section).getByRole('button', { name: 'Show 2 more' }));
      await userEvent.click(within(section).getByRole('button', { name: 'Pin A meets to the top' }));
      expect(names(section)[0]).toBe('A meets');
      expect(within(section).getByRole('button', { name: 'Unpin A meets' })).toHaveAttribute('aria-pressed', 'true');
      expect(JSON.parse(localStorage.getItem('rampart.pinnedFrameworks')!)).toEqual(['a-meets']);

      // the next visit starts with it on top, even folded
      const again = await open(payload);
      await within(again).findAllByText(/A meets/);
      expect(names(again)[0]).toBe('A meets');
      await userEvent.click(within(again).getAllByRole('button', { name: 'Unpin A meets' })[0]!);
      expect(JSON.parse(localStorage.getItem('rampart.pinnedFrameworks')!)).toEqual([]);
    });

    it('survives a damaged saved list', async () => {
      localStorage.setItem('rampart.pinnedFrameworks', '{not json');
      const section = await open(payload);
      await within(section).findByText(/C gaps/);
      expect(names(section)[0]).toBe('C gaps');
    });
  });
});
