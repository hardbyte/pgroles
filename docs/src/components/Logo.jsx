import clsx from 'clsx'

function LogomarkPaths() {
  return (
    <g fill="none" strokeLinejoin="round" strokeWidth={1}>
      <ellipse cx="12" cy="7" rx="8" ry="3" style={{ fill: '#115e59', stroke: '#134e4a', strokeWidth: 0.5 }} />
      <path d="M4 7v10c0 1.66 3.58 3 8 3s8-1.34 8-3V7" style={{ fill: '#115e59', stroke: '#134e4a', strokeWidth: 0.5 }} />
      <ellipse cx="12" cy="12" rx="8" ry="3" style={{ fill: 'none', stroke: 'rgba(255,255,255,0.3)', strokeWidth: 0.5 }} />
      <ellipse cx="12" cy="17" rx="8" ry="3" style={{ fill: 'none', stroke: 'rgba(255,255,255,0.3)', strokeWidth: 0.5 }} />
      <path d="M12 9l4 2v3c0 2.2-1.8 4-4 4s-4-1.8-4-4v-3l4-2z" style={{ fill: '#f6c453', stroke: 'none' }} />
      <circle cx="12" cy="14" r="1" style={{ fill: '#292524' }} />
      <path d="M12 14v1.5" style={{ stroke: '#292524', strokeWidth: 0.8, strokeLinecap: 'round' }} />
    </g>
  )
}

export function Logomark(props) {
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" {...props}>
      <LogomarkPaths />
    </svg>
  )
}

export function Logo(props) {
  let { className, ...rest } = props

  return (
    <div className={clsx('flex items-center gap-3', className)} {...rest}>
      <div className="relative flex h-10 w-10 flex-none items-center justify-center rounded-xl border border-stone-300/90 bg-white shadow-[0_8px_24px_-18px_rgba(28,25,23,0.5)] dark:border-stone-700 dark:bg-stone-900 dark:shadow-none">
        <div className="absolute inset-0 rounded-xl bg-[linear-gradient(135deg,rgba(245,158,11,0.12),transparent_48%,rgba(20,184,166,0.14))] dark:bg-[linear-gradient(135deg,rgba(245,158,11,0.16),transparent_52%,rgba(20,184,166,0.18))]" />
        <Logomark className="relative h-8 w-8" />
      </div>
      <div className="flex min-w-0 flex-col">
        <span className="font-display text-[0.95rem] uppercase tracking-[0.26em] text-stone-900 dark:text-stone-100">
          pgroles
        </span>
        <span className="truncate text-[0.63rem] font-medium uppercase tracking-[0.18em] text-stone-500 dark:text-stone-400">
          PostgreSQL control plane
        </span>
      </div>
    </div>
  )
}
