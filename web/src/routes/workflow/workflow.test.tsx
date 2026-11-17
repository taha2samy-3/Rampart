قimport { screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { acceptance, mockFetch, renderApp } from '@/test/helpers';

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('workflow route', () => {
  it('renders acceptances tab when empty', async () => {
    mockFetch({ loggedIn: true, acceptances: [] });
    renderApp('/workflow');
    expect(await screen.findByText('No risk acceptances')).toBeInTheDocument();
  });

  it('renders acceptances tab with data', async () => {
    mockFetch({ loggedIn: true, acceptances: [acceptance(1)] });
    renderApp('/workflow');
    expect(await screen.findByText(/The service 1 is internal/)).toBeInTheDocument();
  });

  it('renders held closes tab', async () => {
    mockFetch({ loggedIn: true, heldCloses: [] });
    renderApp('/workflow?tab=held_closes');
    expect(await screen.findByText('No mass-closes held')).toBeInTheDocument();
  });

  it('renders groups tab', async () => {
    mockFetch({ loggedIn: true, groups: [] });
    renderApp('/workflow?tab=groups');
    expect(await screen.findByText('No finding groups yet')).toBeInTheDocument();
  });
});
