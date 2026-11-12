import type { SVGProps } from 'react';

type P = SVGProps<SVGSVGElement>;
const base = (p: P): P => ({
  width: 16,
  height: 16,
  viewBox: '0 0 16 16',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.5,
  strokeLinecap: 'square',
  strokeLinejoin: 'miter',
  'aria-hidden': true,
  focusable: false,
  ...p,
});

export const IconSearch = (p: P) => (
  <svg {...base(p)}><circle cx="7" cy="7" r="4.25" /><path d="M10.5 10.5 14 14" /></svg>
);
export const IconChevronDown = (p: P) => (
  <svg {...base(p)}><path d="m4 6 4 4 4-4" /></svg>
);
export const IconBell = (p: P) => (
  <svg {...base(p)}><path d="M4 11V7a4 4 0 0 1 8 0v4l1 1.5H3Z" /><path d="M6.5 14a1.6 1.6 0 0 0 3 0" /></svg>
);
export const IconCheck = (p: P) => (
  <svg {...base(p)}><path d="m3 8.5 3.2 3L13 4.5" /></svg>
);
export const IconX = (p: P) => (
  <svg {...base(p)}><path d="m4 4 8 8M12 4l-8 8" /></svg>
);
export const IconCopy = (p: P) => (
  <svg {...base(p)}><rect x="5.5" y="5.5" width="8" height="8" /><path d="M10.5 5.5v-3h-8v8h3" /></svg>
);
export const IconSidebar = (p: P) => (
  <svg {...base(p)}><rect x="2" y="3" width="12" height="10" /><path d="M6 3v10" /></svg>
);
export const IconSun = (p: P) => (
  <svg {...base(p)}><circle cx="8" cy="8" r="2.75" /><path d="M8 1.5v1.75M8 12.75v1.75M1.5 8h1.75M12.75 8h1.75M3.4 3.4l1.2 1.2M11.4 11.4l1.2 1.2M12.6 3.4l-1.2 1.2M4.6 11.4l-1.2 1.2" /></svg>
);
export const IconMoon = (p: P) => (
  <svg {...base(p)}><path d="M13.5 9.5A5.75 5.75 0 0 1 6.5 2.5a5.75 5.75 0 1 0 7 7Z" /></svg>
);
export const IconMonitor = (p: P) => (
  <svg {...base(p)}><rect x="2" y="3" width="12" height="8" /><path d="M6 14h4M8 11v3" /></svg>
);
export const IconFilter = (p: P) => (
  <svg {...base(p)}><path d="M2 3.5h12M4.5 8h7M7 12.5h2" /></svg>
);
export const IconWarning = (p: P) => (
  <svg {...base(p)}><path d="M8 2 14.5 13.5h-13Z" /><path d="M8 6.5v3M8 11.5v.01" /></svg>
);

// Navigation: one simple glyph per section.
export const IconOverview = (p: P) => (
  <svg {...base(p)}><path d="M2 12.5h12M4 12.5V8M8 12.5V4M12 12.5V6.5" /></svg>
);
export const IconFindings = (p: P) => (
  <svg {...base(p)}><path d="M2.5 4h11M2.5 8h11M2.5 12h7" /></svg>
);
export const IconApplications = (p: P) => (
  <svg {...base(p)}><rect x="2" y="2.5" width="5" height="5" /><rect x="9" y="2.5" width="5" height="5" /><rect x="2" y="9.5" width="5" height="4" /><rect x="9" y="9.5" width="5" height="4" /></svg>
);
export const IconInventory = (p: P) => (
  <svg {...base(p)}><path d="M2 5.5 8 2.5l6 3-6 3Z" /><path d="m2 8.5 6 3 6-3M2 11.5l6 3 6-3" /></svg>
);
export const IconVulnerabilities = (p: P) => (
  <svg {...base(p)}><path d="M8 2.5 13.5 5v4.5c0 2.2-2.4 3.7-5.5 4.5-3.1-.8-5.5-2.3-5.5-4.5V5Z" /><path d="M8 6v3M8 11v.01" /></svg>
);
export const IconWorkflow = (p: P) => (
  <svg {...base(p)}><circle cx="4" cy="4" r="1.75" /><circle cx="12" cy="12" r="1.75" /><path d="M4 5.75V8h8v2.25" /></svg>
);
export const IconCompliance = (p: P) => (
  <svg {...base(p)}><rect x="3" y="2" width="10" height="12" /><path d="m5.5 6 1 1 2-2M5.5 10.5h5" /></svg>
);
export const IconIngestion = (p: P) => (
  <svg {...base(p)}><path d="M8 2.5v8M4.5 7 8 10.5 11.5 7M2.5 13.5h11" /></svg>
);
export const IconPolicies = (p: P) => (
  <svg {...base(p)}><path d="M2.5 5h6M11.5 5h2M2.5 11h2M7.5 11h6" /><circle cx="10" cy="5" r="1.5" /><circle cx="6" cy="11" r="1.5" /></svg>
);
export const IconIntegrations = (p: P) => (
  <svg {...base(p)}><path d="M6 2.5v3M10 2.5v3M4.5 5.5h7V8a3.5 3.5 0 0 1-7 0ZM8 11.5v2" /></svg>
);
export const IconAdmin = (p: P) => (
  <svg {...base(p)}><circle cx="8" cy="8" r="2.25" /><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4" /></svg>
);
