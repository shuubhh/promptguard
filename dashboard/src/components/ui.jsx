import { useEffect } from 'react';

// ------------------------------------------------------------------
// Button
// ------------------------------------------------------------------
export function Button({ variant = 'primary', className = '', ...props }) {
  const styles = {
    primary:
      'bg-accent text-white hover:bg-[#d63851] disabled:opacity-50 disabled:cursor-not-allowed',
    outline:
      'border border-line text-soft hover:border-muted hover:text-white disabled:opacity-50',
    ghost: 'text-muted hover:text-white hover:bg-white/5 disabled:opacity-50',
    danger: 'bg-accent/15 text-accent border border-accent/40 hover:bg-accent/25'
  };
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold transition-colors cursor-pointer ${styles[variant]} ${className}`}
      {...props}
    />
  );
}

// ------------------------------------------------------------------
// Card
// ------------------------------------------------------------------
export function Card({ className = '', children, ...props }) {
  return (
    <div
      className={`rounded-xl border border-line bg-card p-5 shadow-[0_10px_30px_rgba(0,0,0,0.25)] ${className}`}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({ title, subtitle, action }) {
  return (
    <div className="mb-4 flex items-start justify-between gap-3">
      <div>
        <h3 className="text-base font-bold text-white">{title}</h3>
        {subtitle ? <p className="mt-0.5 text-xs text-muted">{subtitle}</p> : null}
      </div>
      {action}
    </div>
  );
}

// ------------------------------------------------------------------
// Inputs
// ------------------------------------------------------------------
export function Input({ label, className = '', ...props }) {
  return (
    <label className="block">
      {label ? <span className="mb-1.5 block text-xs font-semibold text-muted">{label}</span> : null}
      <input
        className={`w-full rounded-lg border border-line bg-navy px-3 py-2 text-sm text-soft outline-none focus:border-accent ${className}`}
        {...props}
      />
    </label>
  );
}

export function Select({ label, children, className = '', ...props }) {
  return (
    <label className="block">
      {label ? <span className="mb-1.5 block text-xs font-semibold text-muted">{label}</span> : null}
      <select
        className={`w-full rounded-lg border border-line bg-navy px-3 py-2 text-sm text-soft outline-none focus:border-accent ${className}`}
        {...props}
      >
        {children}
      </select>
    </label>
  );
}

// ------------------------------------------------------------------
// Badge
// ------------------------------------------------------------------
export function Badge({ tone = 'neutral', children }) {
  const tones = {
    neutral: 'bg-white/5 text-muted border border-line',
    green: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30',
    amber: 'bg-warning/10 text-warning border border-warning/40',
    red: 'bg-accent/10 text-accent border border-accent/40',
    blue: 'bg-success text-white border border-success'
  };
  return (
    <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[11px] font-bold uppercase tracking-wide ${tones[tone]}`}>
      {children}
    </span>
  );
}

// ------------------------------------------------------------------
// Modal
// ------------------------------------------------------------------
export function Modal({ open, onClose, title, children }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="w-full max-w-lg rounded-xl border border-line bg-card p-6 shadow-2xl">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-bold text-white">{title}</h3>
          <button onClick={onClose} className="text-muted hover:text-white cursor-pointer" aria-label="Close">
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// Misc
// ------------------------------------------------------------------
export function Spinner({ label = 'Loading…' }) {
  return (
    <div className="flex items-center justify-center gap-3 py-12 text-muted">
      <span className="h-5 w-5 animate-spin rounded-full border-2 border-muted border-t-accent" />
      <span className="text-sm">{label}</span>
    </div>
  );
}

export function EmptyState({ title, hint }) {
  return (
    <div className="rounded-xl border border-dashed border-line py-12 text-center">
      <div className="text-3xl">🛡️</div>
      <p className="mt-2 text-sm font-semibold text-soft">{title}</p>
      {hint ? <p className="mt-1 text-xs text-muted">{hint}</p> : null}
    </div>
  );
}

export function formatTime(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString([], {
      day: '2-digit',
      month: 'short',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch (err) {
    return String(iso);
  }
}
