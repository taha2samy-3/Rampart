import { fireEvent, render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { axe } from 'vitest-axe';
import { FrameworkMark, initials, markFamily } from './FrameworkMark';

describe('FrameworkMark', () => {
  it('knows the families of the built-in frameworks, and calls anything else custom', () => {
    for (const [id, want] of [['owasp-top10-2021', 'owasp'], ['owasp-top10-2025', 'owasp'], ['cwe-top25', 'cwe'], ['pci-dss-4.0.1-req6', 'pci'], ['iso27001-2022-a8', 'iso'], ['nist-ssdf-1.1', 'nist'], ['acme-policy', 'custom'], ['', 'custom']] as const) {
      expect(markFamily(id), id).toBe(want);
    }
  });

  it('takes initials from a name: two words give two letters, one word gives its first two', () => {
    expect(initials('ACME secure coding policy')).toBe('AS');
    expect(initials('Payments')).toBe('PA');
    expect(initials('  soc-2 trust  ')).toBe('ST');
    expect(initials('')).toBe('?');
    expect(initials('***')).toBe('?');
    expect(initials('éclair d’or')).toBe('ÉD');
  });

  it('draws one mark per family, in indigo when it ships with Rampart and teal when it was installed', () => {
    const shapes = new Set<string>();
    for (const id of ['owasp-top10-2021', 'cwe-top25', 'pci-dss-4.0.1-req6', 'iso27001-2022-a8', 'nist-ssdf-1.1']) {
      const { container, unmount } = render(<FrameworkMark id={id} name={id} origin="builtin" />);
      const path = container.querySelector('path')!;
      expect(path.getAttribute('fill')).toBe('var(--mark-back)');
      shapes.add(path.getAttribute('d')!);
      unmount();
    }
    expect(shapes.size).toBe(5); // each family has its own silhouette

    const own = render(<FrameworkMark id="acme-policy" name="ACME secure coding" origin="tenant" />);
    expect(own.container.querySelector('path')!.getAttribute('fill')).toBe('var(--mark-front)');
    expect(own.container.querySelector('text')!.textContent).toBe('AS');
  });

  it('is decorative: the name next to it says what it is', async () => {
    const { container } = render(<div><FrameworkMark id="cwe-top25" name="CWE Top 25" /><span>CWE Top 25</span></div>);
    expect(container.querySelector('svg')!.getAttribute('aria-hidden')).toBe('true');
    expect(await axe(container)).toHaveNoViolations();
  });

  it('shows the logo the server serves, and falls back to its own mark when the picture does not load', () => {
    const { container } = render(<FrameworkMark id="acme-policy" name="Acme" origin="tenant" logo="/api/v1/taxonomies/acme-policy/logo?v=ab12cd34" />);
    const img = container.querySelector('img')!;
    expect(img.getAttribute('src')).toBe('/api/v1/taxonomies/acme-policy/logo?v=ab12cd34');
    expect(img.getAttribute('alt')).toBe(''); // decorative
    fireEvent.error(img);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('svg')).not.toBeNull();
  });
});
