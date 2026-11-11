import { describe, expect, it } from 'vitest';
import { safeReturnTo } from './returnTo';

describe('safeReturnTo', () => {
  it('keeps same-origin paths with query and hash', () => {
    expect(safeReturnTo('/findings?q=risk:high#x')).toBe('/findings?q=risk:high#x');
    expect(safeReturnTo('/t/acme/findings/123')).toBe('/t/acme/findings/123');
  });
  it.each(['https://evil.example/x', '//evil.example', '/\\evil.example', 'javascript:alert(1)', 'findings', '/a\nb', '/auth/login', '/login', '', null, undefined])(
    'rejects %s',
    (v) => expect(safeReturnTo(v as string)).toBe('/findings'),
  );
});
