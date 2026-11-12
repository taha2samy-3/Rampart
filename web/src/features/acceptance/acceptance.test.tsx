import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { acceptance, finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

async function openInspector(sc: Parameters<typeof mockFetch>[0]) {
  const calls = mockFetch({ loggedIn: true, findings: [finding(1)], ...sc });
  renderApp('/findings?sel=f-1');
  const insp = await screen.findByRole('complementary', { name: 'Finding details' });
  await within(insp).findByRole('heading', { name: 'Finding 1' });
  return { calls, insp };
}
const post = (calls: ReturnType<typeof mockFetch>) => calls.find((c) => c.method === 'POST' && c.url === '/api/v1/risk-acceptances');

describe('requesting a risk acceptance', () => {
  it('a viewer is not offered it', async () => {
    const { insp } = await openInspector({ role: 'viewer' });
    expect(within(insp).queryByRole('button', { name: 'Request risk acceptance' })).toBeNull();
  });

  it('asks for a reason and an end date, caps the date by the tenant maximum, and sends the request', async () => {
    const { calls, insp } = await openInspector({});
    await userEvent.click(within(insp).getByRole('button', { name: 'Request risk acceptance' }));
    const dialog = await screen.findByRole('dialog', { name: 'Request risk acceptance' });
    const until = within(dialog).getByLabelText('Accepted until') as HTMLInputElement;
    expect(until.max).toMatch(/^\d{4}-\d\d-\d\d$/);
    const days = (Date.parse(until.max) - Date.now()) / 86_400_000;
    await waitFor(() => expect(Math.round(days)).toBeLessThanOrEqual(91)); // the tenant maximum is 90
    expect(within(dialog).getByText('At most 90 days from today. An acceptance has to end.')).toBeInTheDocument();

    const submit = within(dialog).getByRole('button', { name: 'Request acceptance' });
    expect(submit).toBeDisabled(); // no reason yet
    await userEvent.type(within(dialog).getByLabelText('Why is this risk acceptable?'), 'internal service, behind the VPN');
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'When it ends' }), 'notify_only');
    await userEvent.click(submit);
    await waitFor(() => expect(post(calls)).toBeDefined());
    const body = JSON.parse(post(calls)!.body!);
    expect(body).toMatchObject({ findingIds: ['f-1'], justification: 'internal service, behind the VPN', onExpiry: 'notify_only' });
    expect(new Date(body.expiresAt).getTime()).toBeGreaterThan(Date.now());
    expect(post(calls)!.headers['X-CSRF-Token']).toBe('csrf-1');
    expect(await screen.findByRole('status')).toHaveTextContent('Risk accepted'); // the confirmation toast
  });

  it('says the request waits when the tenant needs approval', async () => {
    const { insp } = await openInspector({ accept: 'pending' });
    await userEvent.click(within(insp).getByRole('button', { name: 'Request risk acceptance' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Why is this risk acceptable?'), 'because');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Request acceptance' }));
    expect(await screen.findByText('Request sent for approval')).toBeInTheDocument();
  });

  it('shows the server reason when it is refused, and keeps what was typed', async () => {
    const { insp } = await openInspector({ accept: 400 });
    await userEvent.click(within(insp).getByRole('button', { name: 'Request risk acceptance' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Why is this risk acceptable?'), 'my reasoning');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Request acceptance' }));
    expect(await within(dialog).findByText('The request was not sent')).toBeInTheDocument();
    expect(within(dialog).getByText(/at most 90 days/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Why is this risk acceptable?')).toHaveValue('my reasoning');
  });

  it('"e" opens it, but only for a finding that can still be accepted', async () => {
    await openInspector({});
    await userEvent.keyboard('e');
    expect(await screen.findByRole('dialog', { name: 'Request risk acceptance' })).toBeInTheDocument();
  });

  it('a fixed finding has nothing to accept', async () => {
    const fixed = finding(1);
    fixed.finding.state = 'fixed';
    const { insp } = await openInspector({ findings: [fixed] });
    expect(within(insp).queryByRole('button', { name: 'Request risk acceptance' })).toBeNull();
    await userEvent.keyboard('e');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('while a finding is accepted, the inspector says until when and who owns it', async () => {
    const accepted = finding(1);
    accepted.finding.state = 'risk_accepted';
    (accepted.finding as Record<string, unknown>).risk_acceptance_id = 'acc-1';
    const { insp } = await openInspector({ findings: [accepted], acceptances: [acceptance(1, { status: 'approved', owner: 'user:omar@acme.example' })] });
    expect(await within(insp).findByText(/Risk accepted until/)).toBeInTheDocument();
    expect(within(insp).getByText(/Owner: omar@acme.example/)).toBeInTheDocument();
  });

  it('the dialog has no accessibility violations', async () => {
    const { insp } = await openInspector({});
    await userEvent.click(within(insp).getByRole('button', { name: 'Request risk acceptance' }));
    expect(await axe(await screen.findByRole('dialog'))).toHaveNoViolations();
  });
});

describe('the workflow page', () => {
  const pending = acceptance(1, { requester: 'user:sara@acme.example', owner: 'user:sara@acme.example' });
  const approved = acceptance(2, { status: 'approved', approver: 'user:boss@acme.example' });
  const theirs = acceptance(3, { requester: 'user:omar@acme.example', owner: 'user:omar@acme.example' });

  it('lists acceptances, filters by status, and shows who asked and why', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'admin', acceptances: [pending, approved, theirs] });
    const { container } = renderApp('/workflow');
    const grid = await screen.findByRole('grid', { name: 'Risk acceptances' });
    expect(within(grid).getAllByRole('row').filter((r) => r.hasAttribute('data-row-id'))).toHaveLength(3);
    expect(await axe(container)).toHaveNoViolations();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Show' }), 'approved');
    await waitFor(() => expect(calls.some((c) => c.url.includes('status=approved'))).toBe(true));
    await waitFor(() => expect(within(screen.getByRole('grid', { name: 'Risk acceptances' })).getAllByRole('row').filter((r) => r.hasAttribute('data-row-id'))).toHaveLength(1));
  });

  it('an admin approves a request somebody else made', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'admin', acceptances: [theirs] });
    renderApp('/workflow?sel=acc-3');
    const detail = await screen.findByRole('complementary', { name: 'Risk acceptance details' });
    await userEvent.click(await within(detail).findByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.url === '/api/v1/risk-acceptances/acc-3/approve')).toBe(true));
    expect(await screen.findByText('Risk accepted')).toBeInTheDocument();
  });

  it('you cannot approve your own request, and are told why', async () => {
    mockFetch({ loggedIn: true, role: 'admin', acceptances: [acceptance(1, { requester: 'user:sara@acme.example' })] });
    renderApp('/workflow?sel=acc-1');
    const detail = await screen.findByRole('complementary', { name: 'Risk acceptance details' });
    expect(await within(detail).findByText('You asked for this, so someone else has to approve it.')).toBeInTheDocument();
    expect(within(detail).queryByRole('button', { name: 'Approve' })).toBeNull();
    expect(within(detail).getByRole('button', { name: 'Withdraw' })).toBeInTheDocument();
  });

  it('a triager cannot approve or reject', async () => {
    mockFetch({ loggedIn: true, role: 'triager', acceptances: [theirs] });
    renderApp('/workflow?sel=acc-3');
    const detail = await screen.findByRole('complementary', { name: 'Risk acceptance details' });
    await within(detail).findByRole('heading');
    expect(within(detail).queryByRole('button', { name: 'Approve' })).toBeNull();
    expect(within(detail).queryByRole('button', { name: 'Reject' })).toBeNull();
    expect(within(detail).queryByRole('button', { name: 'Revoke' })).toBeNull(); // not theirs
  });

  it('rejecting needs a reason', async () => {
    const calls = mockFetch({ loggedIn: true, role: 'admin', acceptances: [theirs] });
    renderApp('/workflow?sel=acc-3');
    const detail = await screen.findByRole('complementary', { name: 'Risk acceptance details' });
    await userEvent.click(await within(detail).findByRole('button', { name: 'Reject' }));
    const confirm = within(detail).getByRole('button', { name: 'Reject request' });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(detail).getByLabelText('Reason'), 'the VPN claim is wrong');
    await userEvent.click(confirm);
    await waitFor(() => expect(calls.find((c) => c.url.endsWith('/reject'))).toBeDefined());
    expect(JSON.parse(calls.find((c) => c.url.endsWith('/reject'))!.body!)).toEqual({ note: 'the VPN claim is wrong' });
  });

  it('the owner can revoke an approved acceptance', async () => {
    const mine = acceptance(2, { status: 'approved', owner: 'user:sara@acme.example', requester: 'user:omar@acme.example' });
    const calls = mockFetch({ loggedIn: true, role: 'triager', acceptances: [mine] });
    renderApp('/workflow?sel=acc-2');
    const detail = await screen.findByRole('complementary', { name: 'Risk acceptance details' });
    await userEvent.click(await within(detail).findByRole('button', { name: 'Revoke' }));
    await userEvent.click(within(detail).getByRole('button', { name: 'Revoke acceptance' }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith('/revoke'))).toBe(true));
  });

  it('a refused decision says why', async () => {
    mockFetch({ loggedIn: true, role: 'admin', decide: 400, acceptances: [theirs] });
    renderApp('/workflow?sel=acc-3');
    const detail = await screen.findByRole('complementary', { name: 'Risk acceptance details' });
    await userEvent.click(await within(detail).findByRole('button', { name: 'Approve' }));
    expect(await within(detail).findByText('The decision was not saved')).toBeInTheDocument();
    expect(within(detail).getByText(/cannot approve their own/)).toBeInTheDocument();
  });

  it('an empty page says how to start', async () => {
    mockFetch({ loggedIn: true, acceptances: [] });
    renderApp('/workflow');
    expect(await screen.findByText('No risk acceptances')).toBeInTheDocument();
  });
});
