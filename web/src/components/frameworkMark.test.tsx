import { fireEvent, render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { type ComponentProps } from 'react';
import { axe } from 'vitest-axe';
import { FrameworkMark, initials, markFamily } from './FrameworkMark';

describe('FrameworkMark', () => {
  it('knows the families of the built-in frameworks and of the policy chart, and calls anything else custom', () => {
    for (const [id, want] of [['owasp-top10-2021', 'owasp'], ['owasp-top10-2025', 'owasp'], ['cwe-top25', 'cwe'], ['pci-dss-4.0.1-req6', 'pci'], ['iso27001-2022-a8', 'iso'], ['nist-ssdf-1.1', 'nist'], ['nist-800-53-r5', 'nist'], ['pci-dss-4.0.1-extended', 'pci'], ['iso-27001-2022-extended', 'iso'], ['owasp-api-top10-2023', 'owasp'], ['soc2-tsc', 'soc2'], ['hipaa-security-rule', 'hipaa'], ['gdpr-art-32', 'gdpr'], ['eu-cra-annex-i', 'cra'], ['eu-nis2-art-21', 'nis2'], ['nca-ecc-2-2024', 'nca'], ['sama-csf', 'sama'], ['acme-policy', 'custom'], ['', 'custom']] as const) {
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
    for (const id of ['owasp-top10-2021', 'cwe-top25', 'pci-dss-4.0.1-req6', 'iso27001-2022-a8', 'nist-ssdf-1.1', 'soc2-tsc', 'hipaa-security-rule', 'gdpr-art-32', 'eu-cra-annex-i', 'eu-nis2-art-21', 'nca-ecc-2-2024', 'sama-csf']) {
      const { container, unmount } = render(<FrameworkMark id={id} name={id} origin="builtin" />);
      const path = container.querySelector('path')!;
      expect(path.getAttribute('fill')).toBe('var(--mark-back)');
      shapes.add(path.getAttribute('d')!);
      unmount();
    }
    expect(shapes.size).toBe(12); // each family has its own silhouette

    const own = render(<FrameworkMark id="acme-policy" name="ACME secure coding" origin="tenant" />);
    expect(own.container.querySelector('path')!.getAttribute('fill')).toBe('var(--mark-front)');
    expect(own.container.querySelector('text')!.textContent).toBe('AS');
  });

  it('cuts the label of every family inside its shape, whatever its length', () => {
    for (const [id, label] of [['soc2-tsc', 'SOC2'], ['hipaa-security-rule', 'HIPAA'], ['gdpr-art-32', 'GDPR'], ['eu-cra-annex-i', 'CRA'], ['eu-nis2-art-21', 'NIS2'], ['nca-ecc-2-2024', 'NCA'], ['sama-csf', 'SAMA']] as const) {
      const { container, unmount } = render(<FrameworkMark id={id} name={id} origin="cluster" />);
      expect(container.querySelector('text')!.textContent, id).toBe(label);
      expect(container.querySelector('path')!.getAttribute('fill'), id).toBe('var(--mark-front)'); // installed, so teal
      unmount();
    }
  });

  it('is decorative: the name next to it says what it is', async () => {
    const { container } = render(<div><FrameworkMark id="cwe-top25" name="CWE Top 25" /><span>CWE Top 25</span></div>);
    expect(container.querySelector('svg')!.getAttribute('aria-hidden')).toBe('true');
    expect(await axe(container)).toHaveNoViolations();
  });

  it('draws a default mark for a framework with no logo, whatever its name or id', () => {
    for (const [id, name, want] of [['acme-policy', 'ACME secure coding', 'AS'], ['x', 'Payments', 'PA'], ['', '', '?']] as const) {
      const { container, unmount } = render(<FrameworkMark id={id} name={name} origin="tenant" />);
      expect(container.querySelector('img'), id).toBeNull();
      expect(container.querySelector('svg'), id).not.toBeNull();
      expect(container.querySelector('text')!.textContent, id).toBe(want);
      unmount();
    }
  });

  it('asks again when the logo address changes after a failure, and not on every render of the same address', () => {
    const props = (logo: string): ComponentProps<typeof FrameworkMark> => ({ id: 'acme-policy', name: 'Acme', origin: 'tenant', logo });
    const { container, rerender } = render(<FrameworkMark {...props('/api/v1/taxonomies/acme-policy/logo?v=one')} />);
    fireEvent.error(container.querySelector('img')!);
    expect(container.querySelector('img')).toBeNull(); // fell back to the mark
    rerender(<FrameworkMark {...props('/api/v1/taxonomies/acme-policy/logo?v=one')} />);
    expect(container.querySelector('img')).toBeNull(); // the same address is not tried again
    rerender(<FrameworkMark {...props('/api/v1/taxonomies/acme-policy/logo?v=two')} />);
    expect(container.querySelector('img')!.getAttribute('src')).toContain('v=two'); // a new address is
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
