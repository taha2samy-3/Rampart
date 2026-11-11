import { cn } from '@/lib/cn';

/**
 * The real mark (docs/images/logo-mark.svg and logo-mark-dark.svg), recoloured
 * through the --mark-* tokens so it follows the theme. Geometry is unchanged.
 */
export function LogoMark({ size = 24, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" role="img" aria-label="Rampart" className={cn('shrink-0', className)}>
      <polygon
        points="18.00,7.75 46.00,7.75 54.63,22.70 47.00,22.70 47.00,36.70 39.40,36.70 39.40,22.70 24.60,22.70 24.60,36.70 17.00,36.70 17.00,22.70 9.37,22.70"
        fill="var(--mark-front)" stroke="var(--mark-front)" strokeWidth="1.4" strokeLinejoin="round"
      />
      <polygon
        points="18.00,56.25 4.00,32.00 7.29,26.30 13.40,26.30 13.40,40.30 28.20,40.30 28.20,26.30 35.80,26.30 35.80,40.30 50.60,40.30 50.60,26.30 56.71,26.30 60.00,32.00 46.00,56.25"
        fill="var(--mark-back)" stroke="var(--mark-back)" strokeWidth="1.4" strokeLinejoin="round"
      />
    </svg>
  );
}

/** Mark plus the lower-case wordmark in Red Hat Display ExtraBold (live text, self-hosted font). */
export function Logo({ size = 24, showWord = true }: { size?: number; showWord?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2">
      <LogoMark size={size} />
      {showWord && <span className="display text-16 leading-none text-ink">rampart</span>}
    </span>
  );
}
