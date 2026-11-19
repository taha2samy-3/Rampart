import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('signing out', () => {
  // It used to leave the person on the same page: the cache was cleared before the session was set to "none", which
  // detached the bootstrap from the session, so the login page still saw a session and sent them straight back.
  it('leaves the page and shows the sign-in screen', async () => {
    mockFetch({ loggedIn: true, role: 'admin' });
    const { history } = renderApp('/feeds');
    await screen.findByRole('heading', { level: 1, name: 'Feeds' });

    await userEvent.click(screen.getByRole('button', { name: /user menu|account/i }));
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Sign out' }));

    await waitFor(() => expect(history.location.pathname).toBe('/login'));
    // the sign-in screen, not the page that was open
    expect(await screen.findByRole('heading', { name: 'Sign in to Rampart' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { level: 1, name: 'Feeds' })).toBeNull();
  });
});
