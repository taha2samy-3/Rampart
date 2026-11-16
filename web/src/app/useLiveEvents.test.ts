import { describe, expect, it, vi } from 'vitest';
import { QueryClient } from '@tanstack/react-query';
import { invalidateTopic, STREAM_URL } from './useLiveEvents';

describe('live updates (D91)', () => {
  it('uses the one stream path with every topic', () => {
    expect(STREAM_URL).toBe('/api/v1/stream?topics=ingests,findings,operations');
  });

  it('invalidates what each topic changes, and everything on reset', () => {
    const qc = new QueryClient();
    const spy = vi.spyOn(qc, 'invalidateQueries');
    invalidateTopic(qc, 'findings');
    const keys = spy.mock.calls.map((c) => JSON.stringify(c[0]?.queryKey));
    expect(keys).toContain(JSON.stringify(['findings']));
    expect(keys).toContain(JSON.stringify(['overview']));
    spy.mockClear();
    invalidateTopic(qc, 'operations');
    expect(spy.mock.calls.map((c) => JSON.stringify(c[0]?.queryKey))).toContain(JSON.stringify(['notifications']));
    spy.mockClear();
    invalidateTopic(qc, 'reset');
    expect(spy).toHaveBeenCalledWith();
  });
});
