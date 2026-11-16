import { useState } from 'react';

/**
 * The mark of a compliance framework: one flat shape with the framework's initials cut out of it, in the product's
 * own two colours. The colour says where the framework comes from: indigo for the ones that ship with Rampart, teal
 * for the ones this organisation installed. Official logos are trademarks and are not copied into the product; a
 * framework resource may name its own with logoUrl, which the server serves from its own origin (`logo`).
 */
export type MarkFamily = 'owasp' | 'cwe' | 'pci' | 'iso' | 'nist' | 'custom';

/** The family of a framework id: the built-in ones by name, anything else is custom. */
export function markFamily(id: string): MarkFamily {
  if (id.startsWith('owasp-')) return 'owasp';
  if (id.startsWith('cwe-')) return 'cwe';
  if (id.startsWith('pci-')) return 'pci';
  if (id.startsWith('iso')) return 'iso';
  if (id.startsWith('nist-')) return 'nist';
  return 'custom';
}

/** Up to two letters from a name: "ACME secure coding policy" is AS. */
export function initials(name: string): string {
  const words = name.replace(/[^\p{L}\p{N}\s-]/gu, '').split(/\s+/).filter(Boolean);
  if (words.length === 0) return '?';
  const first = words[0]!;
  const letters = words.length === 1 ? first.replace(/-/g, '').slice(0, 2) : first[0]! + words[1]![0]!;
  return letters.toUpperCase();
}

const SHAPE: Record<MarkFamily, { label: string; size: number; d: string }> = {
  owasp: { label: 'OW', size: 12.5, d: 'M16 2a14 14 0 1 0 0 28 14 14 0 0 0 0-28Z' }, // a disc
  cwe: { label: 'CWE', size: 9.5, d: 'M16 1.5 28.6 8.75v14.5L16 30.5 3.4 23.25V8.75Z' }, // a hexagon, point up
  pci: { label: 'PCI', size: 10, d: 'M3 3h26v26H3Z' }, // a square
  iso: { label: 'ISO', size: 10, d: 'M10.3 2h11.4L30 10.3v11.4L21.7 30H10.3L2 21.7V10.3Z' }, // an octagon
  nist: { label: 'NIST', size: 8, d: 'M3 30V14C3 7.4 8.8 2 16 2s13 5.4 13 12v16Z' }, // an arch
  custom: { label: '', size: 12.5, d: 'M3 3h26v18L21 29H3Z' }, // a square with one corner cut
};

export function FrameworkMark({ id, name, origin, logo, size = 24 }: { id: string; name: string; origin?: string; logo?: string; size?: number }) {
  const [failed, setFailed] = useState(false);
  if (logo && !failed) {
    return <img src={logo} alt="" width={size} height={size} className="shrink-0 object-contain" onError={() => setFailed(true)} />;
  }
  const family = markFamily(id);
  const shape = SHAPE[family];
  const label = family === 'custom' ? initials(name) : shape.label;
  const installed = family === 'custom' || (origin !== undefined && origin !== 'builtin');
  return (
    <svg
      viewBox="0 0 32 32"
      width={size}
      height={size}
      aria-hidden="true"
      focusable="false"
      className="shrink-0"
      data-family={family}
    >
      <path d={shape.d} fill={installed ? 'var(--mark-front)' : 'var(--mark-back)'} />
      <text
        x="16"
        y="16"
        textAnchor="middle"
        dominantBaseline="central"
        fontSize={shape.size}
        fontWeight="700"
        letterSpacing="-0.2"
        fill={installed ? '#141922' : 'var(--accent-contrast)'} // dark letters on teal: white on teal is about 2:1
        style={{ fontFamily: 'inherit' }}
      >
        {label}
      </text>
    </svg>
  );
}
