import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const bodyOf = (calls: ReturnType<typeof mockFetch>, method: string, path: string) =>
  JSON.parse(calls.find((c) => c.method === method && c.url.startsWith(path))?.body ?? 'null');

describe('bulk changes and editing (docs/13 section 5, docs/16 D59)', () => {
  it('x selects the focused row, a box selects another, and the bar changes both, reporting the one it refused', async () => {
    const calls = mockFetch({ loggedIn: true, findings: [finding(1), finding(2), finding(3)] });
    renderApp('/findings?sel=f-1');
    const grid = await screen.findByRole('grid');
    const first = await within(grid).findByText('Finding 1');
    first.closest('tr')!.focus();
    await userEvent.keyboard('x');
    expect(await screen.findByText('1 selected')).toBeInTheDocument();
    await userEvent.click(within(grid).getByRole('checkbox', { name: 'Select Finding 2' }));
    expect(screen.getByText('2 selected')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Change selected' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change 2 findings' });
    expect(await axe(dialog)).toHaveNoViolations();
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'State' }), 'not_affected');
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'Justification' }), 'vulnerable_code_not_present');
    await userEvent.type(within(dialog).getByLabelText('Owner'), 'mona@acme.example');
    await userEvent.type(within(dialog).getByLabelText('Add tags'), 'sprint-12, auth');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Apply' }));

    await waitFor(() => expect(bodyOf(calls, 'POST', '/api/v1/findings/bulk')).not.toBeNull());
    expect(bodyOf(calls, 'POST', '/api/v1/findings/bulk')).toEqual({
      ids: ['f-1', 'f-2'],
      patch: { state: 'not_affected', justification: 'vulnerable_code_not_present', owner: 'mona@acme.example', addTags: ['sprint-12', 'auth'] },
    });
    expect(await within(dialog).findByRole('status')).toHaveTextContent('1 changed, 0 already that way, 1 not changed');
    expect(within(dialog).getByText(/your role does not allow this/)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Done' }));
    expect(screen.queryByText('2 selected')).toBeNull();
  });

  it('"select all matching" sends the filter instead of ids, and "nobody" unassigns', async () => {
    const calls = mockFetch({ loggedIn: true, findings: [finding(1), finding(2), finding(3)] });
    renderApp('/findings?q=severity%3Ahigh&sel=f-1');
    const grid = await screen.findByRole('grid');
    await userEvent.click(await within(grid).findByRole('checkbox', { name: 'Select Finding 1' }));
    await userEvent.click(screen.getByRole('button', { name: 'Select all 3 matching' }));
    expect(screen.getByText('All 3 matching findings selected')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Change selected' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change every finding that matches the filter' });
    await userEvent.type(within(dialog).getByLabelText('Owner'), 'nobody');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Apply' }));
    await waitFor(() => expect(bodyOf(calls, 'POST', '/api/v1/findings/bulk')).toEqual({ q: 'severity:high', patch: { owner: '' } }));
  });

  it('a viewer gets no selection', async () => {
    mockFetch({ loggedIn: true, role: 'viewer', findings: [finding(1)] });
    renderApp('/findings');
    const grid = await screen.findByRole('grid');
    await within(grid).findByText('Finding 1');
    expect(within(grid).queryByRole('checkbox')).toBeNull();
  });

  it('a edits owner, severity and tags; a new severity needs a reason; only what changed is sent, with the version', async () => {
    const calls = mockFetch({ loggedIn: true, findings: [finding(1)] });
    renderApp('/findings?sel=f-1');
    const insp = await screen.findByRole('complementary', { name: 'Finding details' });
    await within(insp).findByRole('heading', { name: 'Finding 1' });
    await userEvent.keyboard('a');
    const dialog = await screen.findByRole('dialog', { name: 'Edit finding' });
    expect(await axe(dialog)).toHaveNoViolations();
    const save = within(dialog).getByRole('button', { name: 'Save' });
    expect(save).toBeDisabled(); // nothing changed yet
    await userEvent.type(within(dialog).getByLabelText('Owner'), 'mona@acme.example');
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'Severity' }), 'critical');
    expect(save).toBeDisabled(); // a new severity needs its reason
    await userEvent.type(within(dialog).getByLabelText('Why the severity is different'), 'reachable from the login page');
    await userEvent.click(save);
    await waitFor(() => expect(calls.find((c) => c.method === 'PATCH')).toBeDefined());
    const patchCall = calls.find((c) => c.method === 'PATCH')!;
    expect(JSON.parse(patchCall.body!)).toEqual({ owner: 'mona@acme.example', severity: 'critical', severityReason: 'reachable from the login page' });
    expect(patchCall.headers['If-Match']).toBe('"3"');
  });
});
