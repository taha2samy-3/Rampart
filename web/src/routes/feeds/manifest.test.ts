import { describe, expect, it } from 'vitest';
import { buildManifest } from './manifest';

describe('buildManifest', () => {
  it('prints no source and no public address when the server has no resource', () => {
    const yaml = buildManifest(null);
    expect(yaml).toContain('kind: ClusterFeed');
    expect(yaml).toContain('egress: allow');
    expect(yaml).toContain('storageMode: lightweight');
    expect(yaml).not.toMatch(/https?:\/\//);
    expect(yaml).not.toMatch(/\n {2}(kev|epss|nvd|osv|vulnrichment|exploitdb|metasploit|euvd|vulncheckKev):/);
  });

  it('prints the sources the resource sets, with their url and token file', () => {
    const yaml = buildManifest({
      egress: 'deny', storageMode: 'full',
      kev: { url: 'https://mirror.local/kev.json' }, euvd: { tokenFile: '/etc/rampart/feed-secrets/euvd' }, osv: { url: '' },
      custom: [{ name: 'internal', format: 'cve5', url: 'https://feeds.local/x', pushTokenFile: '/var/run/rampart/feeds/x' }],
    });
    expect(yaml).toContain('egress: deny');
    expect(yaml).toContain('storageMode: full');
    expect(yaml).toContain('  kev:\n    url: "https://mirror.local/kev.json"');
    expect(yaml).toContain('  euvd:\n    tokenFile: "/etc/rampart/feed-secrets/euvd"');
    expect(yaml).toContain('  osv:\n    {}');
    expect(yaml).toContain('    - name: internal\n      format: cve5\n      url: "https://feeds.local/x"');
    expect(yaml).toContain('      pushTokenFile: "/var/run/rampart/feeds/x"');
  });
});
