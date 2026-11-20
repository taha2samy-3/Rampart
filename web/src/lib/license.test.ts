import { describe, expect, it } from 'vitest';
import { classifyLicenseRisk } from './license';

describe('classifyLicenseRisk', () => {
  it('does not false-positive on words containing license substrings', () => {
    expect(classifyLicenseRisk('Limited Liability Company License')).toBe('unknown');
    expect(classifyLicenseRisk('Miscellaneous')).toBe('unknown');
    expect(classifyLicenseRisk('Simple Public License')).toBe('unknown');
  });

  it('evaluates OR expressions where user selects permissive option', () => {
    expect(classifyLicenseRisk('MIT OR GPL-3.0-or-later')).toBe('permissive');
    expect(classifyLicenseRisk('Apache-2.0 OR BSD-3-Clause')).toBe('permissive');
  });

  it('evaluates AND expressions where strictest copyleft requirement applies', () => {
    expect(classifyLicenseRisk('MIT AND Zlib')).toBe('permissive');
    expect(classifyLicenseRisk('MIT AND GPL-2.0-only')).toBe('copyleft');
    expect(classifyLicenseRisk('Apache-2.0 AND AGPL-3.0-or-later')).toBe('copyleft');
  });

  it('classifies standard single licenses correctly', () => {
    expect(classifyLicenseRisk('MIT')).toBe('permissive');
    expect(classifyLicenseRisk('Apache-2.0')).toBe('permissive');
    expect(classifyLicenseRisk('BSD-3-Clause')).toBe('permissive');
    expect(classifyLicenseRisk('ISC')).toBe('permissive');
    expect(classifyLicenseRisk('0BSD')).toBe('permissive');
    expect(classifyLicenseRisk('Unlicense')).toBe('permissive');

    expect(classifyLicenseRisk('GPL-2.0-only')).toBe('copyleft');
    expect(classifyLicenseRisk('GPL-3.0-or-later')).toBe('copyleft');
    expect(classifyLicenseRisk('AGPL-3.0')).toBe('copyleft');
    expect(classifyLicenseRisk('LGPL-2.1-only')).toBe('copyleft');
    expect(classifyLicenseRisk('MPL-2.0')).toBe('copyleft');
    expect(classifyLicenseRisk('EPL-2.0')).toBe('copyleft');
  });

  it('returns unknown for empty, missing or unlisted licenses', () => {
    expect(classifyLicenseRisk(null)).toBe('unknown');
    expect(classifyLicenseRisk('')).toBe('unknown');
    expect(classifyLicenseRisk('   ')).toBe('unknown');
    expect(classifyLicenseRisk('Unknown')).toBe('unknown');
    expect(classifyLicenseRisk('Custom-Proprietary-EULA')).toBe('unknown');
  });
});
