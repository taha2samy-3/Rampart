import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const day = (n: number) => new Date(Date.now() + n * 86_400_000).toISOString();
const ctl = (over: Record<string, unknown> = {}) => ({ framework_id: 'pci-dss-4.0.1-req6', framework: 'PCI DSS 4.0.1 requirement 6', version: '4.0.1', control_id: '6.2.4', control: 'Software engineering techniques prevent common attacks', due: day(4), overdue: false, ...over });

async function open(sc: Parameters<typeof mockFetch>[0], state?: string) {
  const row = finding(1, 'high');
  if (state) (row.finding as Record<string, unknown>).state = state;
  const calls = mockFetch({ loggedIn: true, findings: [row], ...sc });
  renderApp('/findings?sel=f-1');
  const insp = await screen.findByRole('complementary', { name: 'Finding details' });
  return { calls, insp };
}

// "If I open a vulnerability I want to see that it is against a deadline, so I fix it before the control goes out of
// compliance." A finding is a problem for a framework only once it is past its deadline.
describe('Finding: the controls it counts against', () => {
  it('says which controls, and the date to meet', async () => {
    const { insp } = await open({ findingControls: [ctl(), ctl({ framework_id: 'owasp-top10-2021', framework: 'OWASP Top 10', version: '2021', control_id: 'A03:2021', control: 'Injection' })] });
    const section = (await within(insp).findByRole('heading', { name: 'Compliance' })).closest('section')!;
    expect(within(section).getByText(/Due in 4 days \(.*\)\./)).toBeInTheDocument();
    expect(within(section).getByText('6.2.4: Software engineering techniques prevent common attacks')).toBeInTheDocument();
    expect(within(section).getByText('A03:2021: Injection')).toBeInTheDocument();
    const link = within(section).getByRole('link', { name: /OWASP Top 10/ });
    expect(link.getAttribute('href')).toContain('framework=owasp-top10-2021');
    expect(link.getAttribute('href')).toContain('application=b7e1c9a2-0000'); // the finding's application
  });

  it('says so, in bold, when the deadline has passed: the control is out of compliance until it is dealt with', async () => {
    const { insp } = await open({ findingControls: [ctl({ due: day(-3), overdue: true })] });
    const text = await within(insp).findByText(/Overdue by 3 days: the control is out of compliance/);
    expect(text.className).toContain('font-semibold');
  });

  it('says when no deadline is set', async () => {
    const { insp } = await open({ findingControls: [ctl({ due: undefined })] });
    expect(await within(insp).findByText('No deadline is set.')).toBeInTheDocument();
  });

  it('shows nothing for a finding that counts against no control', async () => {
    const { insp } = await open({ findingControls: [] });
    await within(insp).findByRole('heading', { name: 'Reported by' }); // the panel has loaded
    expect(within(insp).queryByRole('heading', { name: 'Compliance' })).toBeNull();
  });

  it('does not ask for a finding that is not open', async () => {
    const { calls, insp } = await open({ findingControls: [ctl()] }, 'fixed');
    await within(insp).findByRole('heading', { name: 'Reported by' });
    expect(within(insp).queryByRole('heading', { name: 'Compliance' })).toBeNull();
    expect(calls.filter((c) => /\/api\/v1\/findings\/f-1$/.test(c.url.split('?')[0]!) && c.method === 'GET').length).toBeGreaterThan(0); // the other sections still read it
  });

  it('has no accessibility violations', async () => {
    const { insp } = await open({ findingControls: [ctl()] });
    await within(insp).findByText(/Due in 4 days/);
    expect(await axe(insp)).toHaveNoViolations();
  });
});
