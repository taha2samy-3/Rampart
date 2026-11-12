import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { axe } from 'vitest-axe';
import { finding, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

async function openDialog(sc: Parameters<typeof mockFetch>[0]) {
  const calls = mockFetch({ loggedIn: true, findings: [finding(1)], ...sc });
  renderApp('/findings?sel=f-1');
  const insp = await screen.findByRole('complementary', { name: 'Finding details' });
  await within(insp).findByRole('heading', { name: 'Finding 1' });
  return { calls, insp };
}
const patchCall = (calls: ReturnType<typeof mockFetch>) => calls.find((c) => c.method === 'PATCH');

describe('triage', () => {
  it('a viewer reads but is not offered a way to change anything', async () => {
    const { insp } = await openDialog({ role: 'viewer' });
    expect(within(insp).queryByRole('button', { name: 'Change state' })).toBeNull();
    await userEvent.keyboard('s');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('a triager changes the state: sends the version, the justification and the note, then confirms', async () => {
    const { calls, insp } = await openDialog({});
    await userEvent.click(within(insp).getByRole('button', { name: 'Change state' }));
    const dialog = await screen.findByRole('dialog', { name: 'Change state' });
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'New state' }), 'not_affected');
    // A not_affected decision must carry a justification, and offers an impact statement.
    expect(within(dialog).getByRole('combobox', { name: 'Justification' })).toBeInTheDocument();
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'Justification' }), 'vulnerable_code_not_in_execute_path');
    await userEvent.type(within(dialog).getByLabelText('Impact statement'), 'never routed');
    await userEvent.type(within(dialog).getByLabelText('Note'), 'checked with the owner');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Change state' }));
    await waitFor(() => expect(patchCall(calls)).toBeDefined());
    const call = patchCall(calls)!;
    expect(call.url).toBe('/api/v1/findings/f-1');
    expect(call.headers['If-Match']).toBe('"3"');
    expect(call.headers['X-CSRF-Token']).toBe('csrf-1');
    expect(JSON.parse(call.body!)).toEqual({ state: 'not_affected', justification: 'vulnerable_code_not_in_execute_path', impactStatement: 'never routed', note: 'checked with the owner' });
    expect(await screen.findByText('State changed')).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  });

  it('offers only the moves the server allows, and never accepts a risk', async () => {
    const fixed = finding(1);
    fixed.finding.state = 'fixed';
    const { insp } = await openDialog({ findings: [fixed] });
    await userEvent.click(within(insp).getByRole('button', { name: 'Change state' }));
    const select = await screen.findByRole('combobox', { name: 'New state' });
    const values = within(select).getAllByRole('option').map((o) => (o as HTMLOptionElement).value);
    expect(values).toEqual(['open', 'under_investigation']);
  });

  it('from an open finding every disposition is offered except accepting a risk, which has its own flow', async () => {
    const { insp } = await openDialog({});
    await userEvent.click(within(insp).getByRole('button', { name: 'Change state' }));
    const select = await screen.findByRole('combobox', { name: 'New state' });
    const values = within(select).getAllByRole('option').map((o) => (o as HTMLOptionElement).value);
    expect(values).toEqual(['under_investigation', 'affected', 'not_affected', 'out_of_scope', 'duplicate', 'fixed']);
    expect(values).not.toContain('risk_accepted');
  });

  it('a duplicate cannot be submitted without the finding it repeats', async () => {
    const { insp } = await openDialog({});
    await userEvent.click(within(insp).getByRole('button', { name: 'Change state' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'New state' }), 'duplicate');
    const submit = within(dialog).getByRole('button', { name: 'Change state' });
    expect(submit).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText('Duplicate of'), 'f-9');
    expect(submit).toBeEnabled();
  });

  it('"s" opens the dialog for the selected finding, but not while typing in a field', async () => {
    await openDialog({});
    await userEvent.keyboard('s');
    expect(await screen.findByRole('dialog', { name: 'Change state' })).toBeInTheDocument();
    const note = screen.getByLabelText('Note');
    await userEvent.type(note, 'sss');
    expect(note).toHaveValue('sss'); // the keystrokes went to the field, not to the shortcut
  });

  it('a conflict says someone else changed it, and offers to reload', async () => {
    const { insp } = await openDialog({ patch: 409 });
    await userEvent.click(within(insp).getByRole('button', { name: 'Change state' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Change state' }));
    expect(await within(dialog).findByText('Someone else changed this finding')).toBeInTheDocument();
    expect(within(dialog).getByText('Reload it to see their change, then decide again.')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: 'Reload the finding' })).toBeInTheDocument();
  });

  it('a refused decision shows the server reason in the dialog and keeps what was typed', async () => {
    const { insp } = await openDialog({ patch: 400 });
    await userEvent.click(within(insp).getByRole('button', { name: 'Change state' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('Note'), 'my reasoning');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Change state' }));
    expect(await within(dialog).findByText('The state was not changed')).toBeInTheDocument();
    expect(within(dialog).getByText(/needs the id of the finding it duplicates/)).toBeInTheDocument();
    expect(within(dialog).getByLabelText('Note')).toHaveValue('my reasoning');
  });

  it('the dialog has no accessibility violations', async () => {
    const { insp } = await openDialog({});
    await userEvent.click(within(insp).getByRole('button', { name: 'Change state' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.selectOptions(within(dialog).getByRole('combobox', { name: 'New state' }), 'not_affected');
    expect(await axe(dialog)).toHaveNoViolations();
  });

  it('the timeline says who did what, in words, oldest first', async () => {
    const { insp } = await openDialog({
      events: [
        { id: 'e1', at: '2026-10-01T00:00:00Z', actor: 'system:parser', type: 'created' },
        { id: 'e2', at: '2026-10-02T00:00:00Z', actor: 'user:sara@acme.example', type: 'state_changed', from: 'open', to: 'not_affected', note: 'never routed' },
        { id: 'e3', at: '2026-10-03T00:00:00Z', actor: 'user:sara@acme.example', type: 'severity_changed', from: 'high', to: 'low', note: 'internal tool' },
      ],
    });
    const section = (await within(insp).findByRole('heading', { name: 'Timeline' })).closest('section')!;
    const items = await within(section).findAllByRole('listitem');
    expect(items.map((li) => li.querySelector('p')?.textContent)).toEqual([
      'First reported',
      'sara@acme.example changed the state from Open to Not affected',
      'sara@acme.example changed the severity from high to low',
    ]);
    expect(within(items[1]!).getByText(/never routed/)).toBeInTheDocument();
  });

  it('an empty timeline says so', async () => {
    const { insp } = await openDialog({});
    expect(await within(insp).findByText('Nothing has happened to this finding yet.')).toBeInTheDocument();
  });
});
