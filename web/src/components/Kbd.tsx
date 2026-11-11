export function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex min-w-5 items-center justify-center rounded-ctl border border-rule px-1 font-mono text-12 text-ink-2">
      {children}
    </kbd>
  );
}
