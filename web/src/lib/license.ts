export type LicenseRisk = 'permissive' | 'copyleft' | 'unknown';

const PERMISSIVE_IDS = new Set([
  '0bsd',
  'afl-1.1',
  'afl-1.2',
  'afl-2.0',
  'afl-2.1',
  'afl-3.0',
  'apache-1.0',
  'apache-1.1',
  'apache-2.0',
  'artistic-1.0',
  'artistic-2.0',
  'blueoak-1.0.0',
  'bsd-2-clause',
  'bsd-2-clause-freebsd',
  'bsd-2-clause-netbsd',
  'bsd-3-clause',
  'bsd-3-clause-clear',
  'bsd-4-clause',
  'bsl-1.0',
  'cc0-1.0',
  'cc-by-1.0',
  'cc-by-2.0',
  'cc-by-2.5',
  'cc-by-3.0',
  'cc-by-4.0',
  'isc',
  'mit',
  'mit-0',
  'mit-x11',
  'postgresql',
  'python-2.0',
  'unlicense',
  'wtfpl',
  'zlib',
]);

const COPYLEFT_PREFIXES = [
  'gpl',
  'agpl',
  'lgpl',
  'mpl',
  'epl',
  'cddl',
  'sspl',
  'osl',
  'eupl',
  'cc-by-sa',
  'sleepycat',
];

function classifySingle(raw: string): LicenseRisk {
  const norm = raw.trim().toLowerCase();
  if (!norm || norm === 'unknown') {
    return 'unknown';
  }
  if (PERMISSIVE_IDS.has(norm)) {
    return 'permissive';
  }
  for (const prefix of COPYLEFT_PREFIXES) {
    if (norm === prefix || norm.startsWith(`${prefix}-`)) {
      return 'copyleft';
    }
  }
  return 'unknown';
}

/**
 * Classifies an SPDX expression or raw license string into a LicenseRisk category.
 * - Handles simple licenses (e.g. "MIT", "GPL-3.0-only")
 * - Handles "OR" compound expressions (permissive if either option is permissive)
 * - Handles "AND" compound expressions (copyleft if any requirement is copyleft)
 * - Strips parentheses and "WITH <exception>" clauses
 */
export function classifyLicenseRisk(license?: string | null): LicenseRisk {
  if (!license || !license.trim()) {
    return 'unknown';
  }

  // Remove WITH exception clauses and outer parentheses
  const cleaned = license
    .replace(/\bWITH\s+[\w.-]+/gi, ' ')
    .replace(/[()]/g, ' ')
    .trim();

  // Handle OR clauses (choice of recipient: permissive takes precedence)
  if (/\bOR\b/i.test(cleaned)) {
    const parts = cleaned.split(/\bOR\b/i).map((p) => classifyLicenseRisk(p));
    if (parts.includes('permissive')) {
      return 'permissive';
    }
    if (parts.includes('copyleft')) {
      return 'copyleft';
    }
    return 'unknown';
  }

  // Handle AND clauses (all must be satisfied: strictest takes precedence)
  if (/\bAND\b/i.test(cleaned)) {
    const parts = cleaned.split(/\bAND\b/i).map((p) => classifyLicenseRisk(p));
    if (parts.includes('copyleft')) {
      return 'copyleft';
    }
    if (parts.every((p) => p === 'permissive')) {
      return 'permissive';
    }
    return 'unknown';
  }

  return classifySingle(cleaned);
}
