import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cn } from '@/lib/cn';
import { Spinner } from './Spinner';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost';

const VARIANT: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-contrast border-accent hover:brightness-110',
  secondary: 'bg-surface text-ink border-rule hover:bg-chrome',
  ghost: 'bg-transparent text-ink border-transparent hover:bg-chrome',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** One primary per view. */
  variant?: ButtonVariant;
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', loading, disabled, className, children, type = 'button', ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(
        'inline-flex h-8 items-center justify-center gap-2 whitespace-nowrap rounded-ctl border px-3 text-13 font-medium',
        'cursor-pointer select-none disabled:cursor-not-allowed disabled:opacity-55',
        VARIANT[variant],
        className,
      )}
      {...rest}
    >
      {loading && <Spinner size={12} />}
      {children}
    </button>
  );
});

export const IconButton = forwardRef<HTMLButtonElement, Omit<ButtonProps, 'children'> & { label: string; children: React.ReactNode }>(
  function IconButton({ label, children, className, variant = 'ghost', ...rest }, ref) {
    return (
      <Button
        ref={ref}
        variant={variant}
        aria-label={label}
        className={cn('size-8 shrink-0 px-0', className)}
        {...rest}
      >
        {children}
      </Button>
    );
  },
);
