import { cn } from '@/lib/cn';

export function Spinner({ size = 16, label }: { size?: number; label?: string }) {
  return (
    <span role={label ? 'status' : undefined} aria-label={label} className="inline-flex">
      <svg
        width={size}
        height={size}
        viewBox="0 0 16 16"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        aria-hidden="true"
        className="motion-safe:animate-spin"
      >
        <path d="M8 2a6 6 0 1 0 6 6" opacity={0.9} />
      </svg>
    </span>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn('block bg-[color-mix(in_srgb,var(--rule)_60%,transparent)] motion-safe:animate-pulse', className)}
    />
  );
}
