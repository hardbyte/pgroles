function Node({ eyebrow, name, detail, tone = 'stone' }) {
  const tones = {
    amber:
      'border-amber-200 bg-amber-50/70 dark:border-amber-900/60 dark:bg-amber-950/20',
    teal: 'border-teal-200 bg-teal-50/70 dark:border-teal-900/60 dark:bg-teal-950/20',
    stone: 'border-stone-300 bg-white dark:border-stone-700 dark:bg-stone-900',
  }

  return (
    <div className={`min-w-0 rounded-2xl border p-4 ${tones[tone]}`}>
      <p className="m-0 text-[10px] font-semibold uppercase tracking-[0.18em] text-stone-500 dark:text-stone-400">
        {eyebrow}
      </p>
      <p className="mb-0 mt-2 break-words font-mono text-sm font-semibold text-stone-950 dark:text-white">
        {name}
      </p>
      <p className="mb-0 mt-2 text-xs leading-5 text-stone-600 dark:text-stone-300">
        {detail}
      </p>
    </div>
  )
}

function Arrow({ label, blocked = false }) {
  return (
    <div className="flex min-w-20 flex-col items-center justify-center gap-1 py-1">
      <svg
        aria-hidden="true"
        viewBox="0 0 64 20"
        className={`h-5 w-16 ${
          blocked
            ? 'text-stone-300 dark:text-stone-700'
            : 'text-teal-500 dark:text-teal-400'
        }`}
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeDasharray={blocked ? '4 4' : undefined}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M2 10h52" />
        {!blocked && <path d="m48 4 10 6-10 6" />}
        {blocked && (
          <>
            <path d="m49 5 10 10" />
            <path d="m59 5-10 10" />
          </>
        )}
      </svg>
      <span className="text-center text-[9px] font-semibold uppercase tracking-[0.14em] text-stone-500 dark:text-stone-400">
        {label}
      </span>
    </div>
  )
}

function CompactPath({ from, relation, to, outcome, blocked = false }) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr),auto,minmax(0,1.15fr)] items-center gap-2 rounded-2xl border border-stone-200 bg-white p-3 dark:border-stone-800 dark:bg-stone-900">
      <span className="break-words font-mono text-xs font-semibold text-stone-950 dark:text-white">
        {from}
      </span>
      <span
        aria-hidden="true"
        className={`text-lg ${
          blocked ? 'text-stone-400' : 'text-teal-500 dark:text-teal-400'
        }`}
      >
        {blocked ? '×' : '→'}
      </span>
      <span className="min-w-0">
        <span className="block break-words font-mono text-xs font-semibold text-stone-950 dark:text-white">
          {to}
        </span>
        <span className="mt-1 block text-[10px] leading-4 text-stone-500 dark:text-stone-400">
          {relation} · {outcome}
        </span>
      </span>
    </div>
  )
}

export function ProductionRoleShapeDiagram() {
  return (
    <figure className="not-prose my-8 overflow-hidden rounded-[2rem] border border-stone-300/90 bg-stone-50/80 shadow-[0_24px_60px_-44px_rgba(28,25,23,0.45)] dark:border-stone-700 dark:bg-stone-950/30 dark:shadow-none">
      <div className="border-b border-stone-200 bg-white/90 px-5 py-4 dark:border-stone-800 dark:bg-stone-900/80 sm:px-6">
        <p className="m-0 font-display text-lg text-stone-950 dark:text-white">
          A production role shape
        </p>
        <p className="mb-0 mt-1 text-sm text-stone-600 dark:text-stone-400">
          Logins identify actors. Capability roles hold access. Owner roles hold
          objects.
        </p>
      </div>

      <div className="grid gap-3 p-4 md:hidden">
        <CompactPath
          from="alice"
          relation="member of orders_reader"
          to="app.orders"
          outcome="USAGE + SELECT"
        />
        <CompactPath
          from="mallory"
          relation="no membership"
          to="app.orders"
          outcome="blocked"
          blocked
        />
        <CompactPath
          from="deploy"
          relation="becomes app_owner"
          to="app.orders"
          outcome="owns"
        />
      </div>

      <div className="hidden gap-5 p-5 sm:p-6 md:grid">
        <div className="grid items-center gap-3 lg:grid-cols-[minmax(0,1fr),auto,minmax(0,1fr),auto,minmax(0,1.25fr)]">
          <Node
            eyebrow="Login role"
            name="alice"
            detail="The application or person that opens the session."
            tone="amber"
          />
          <Arrow label="member of" />
          <Node
            eyebrow="Capability role"
            name="orders_reader"
            detail="A reusable bundle of read permissions."
            tone="teal"
          />
          <Arrow label="USAGE + SELECT" />
          <Node
            eyebrow="Database objects"
            name="app → orders"
            detail="The schema must be reachable before the table operation is allowed."
          />
        </div>

        <div className="grid items-center gap-3 lg:grid-cols-[minmax(0,1fr),auto,minmax(0,1fr),auto,minmax(0,1.25fr)]">
          <Node
            eyebrow="Login role"
            name="mallory"
            detail="A valid identity that is deliberately outside the read hierarchy."
          />
          <Arrow label="no membership" blocked />
          <Node
            eyebrow="Capability role"
            name="No access path"
            detail="No membership means no inherited schema or table privileges."
          />
          <Arrow label="cannot reach" blocked />
          <Node
            eyebrow="Database objects"
            name="app → orders"
            detail="The same SQL is denied for Mallory."
          />
        </div>

        <div className="grid items-center gap-3 lg:grid-cols-[minmax(0,1fr),auto,minmax(0,1fr),auto,minmax(0,1.25fr)]">
          <Node
            eyebrow="Migration login"
            name="deploy"
            detail="Controlled automation activates the owner only while running DDL."
          />
          <Arrow label="becomes" />
          <Node
            eyebrow="Owner role"
            name="app_owner"
            detail="A NOLOGIN role used by controlled migrations."
          />
          <Arrow label="owns" />
          <Node
            eyebrow="Database objects"
            name="app → orders"
            detail="Ownership stays separate from day-to-day application access."
          />
        </div>
      </div>

      <figcaption className="border-t border-stone-200 px-5 py-4 text-sm leading-6 text-stone-600 dark:border-stone-800 dark:text-stone-400 sm:px-6">
        Alice reaches <span className="font-mono">app.orders</span> through the{' '}
        <span className="font-mono">orders_reader</span> capability. Mallory has
        no path. Controlled migrations use the separate{' '}
        <span className="font-mono">app_owner</span> role, which owns the schema
        and table without becoming an application login.
      </figcaption>
    </figure>
  )
}
