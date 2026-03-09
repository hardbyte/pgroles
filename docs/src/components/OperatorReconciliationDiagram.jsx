export function OperatorReconciliationDiagram() {
  const steps = [
    {
      step: '1',
      title: 'Read policy and Secret',
      body: 'Load the PostgresPolicy, fetch DATABASE_URL from the referenced Secret, and refresh the cached pool when credentials change.',
      tone: 'teal',
    },
    {
      step: '2',
      title: 'Build desired state',
      body: 'Convert the CRD to the shared PolicyManifest model, then expand profiles and schemas into concrete roles, grants, and memberships.',
      tone: 'stone',
    },
    {
      step: '3',
      title: 'Inspect PostgreSQL',
      body: 'Query the live database state that matters for this policy, including managed roles, privileges, memberships, and provider-specific constraints.',
      tone: 'amber',
    },
    {
      step: '4',
      title: 'Diff and safety checks',
      body: 'Compute the convergent change plan, detect conflicts, and enforce per-database locking before any mutation is attempted.',
      tone: 'stone',
    },
    {
      step: '5',
      title: 'Apply in one transaction',
      body: 'Execute the rendered SQL statements inside a single transaction so the reconcile either commits fully or rolls back cleanly.',
      tone: 'amber',
    },
    {
      step: '6',
      title: 'Patch status and emit telemetry',
      body: 'Write conditions, summaries, and last-error state back to Kubernetes, and export OTLP metrics for runtime visibility.',
      tone: 'teal',
    },
  ]

  return (
    <div className="not-prose my-10">
      <div className="grid gap-4 lg:grid-cols-3">
        {steps.map((step, index) => (
          <ReconcileCard
            key={step.step}
            {...step}
            arrow={index < steps.length - 1}
          />
        ))}
      </div>
    </div>
  )
}

function ReconcileCard({ step, title, body, tone, arrow }) {
  const tones = {
    teal: 'from-teal-100 to-white border-teal-200 dark:from-teal-950/35 dark:to-stone-900 dark:border-teal-900/60',
    stone:
      'from-stone-100 to-white border-stone-300 dark:from-stone-950/40 dark:to-stone-900 dark:border-stone-700',
    amber:
      'from-amber-100 to-white border-amber-200 dark:from-amber-950/30 dark:to-stone-900 dark:border-amber-900/60',
  }

  return (
    <div className="relative">
      <div
        className={`h-full rounded-[1.6rem] border bg-gradient-to-br p-5 shadow-[0_18px_36px_-30px_rgba(28,25,23,0.25)] dark:shadow-none ${tones[tone]}`}
      >
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-stone-900 text-sm font-bold text-white dark:bg-white dark:text-stone-900">
            {step}
          </div>
          <p className="m-0 font-display text-xl text-stone-900 dark:text-white">{title}</p>
        </div>
        <p className="mt-4 text-sm leading-6 text-stone-700 dark:text-stone-300">{body}</p>
      </div>
      {arrow ? (
        <div className="pointer-events-none absolute -bottom-3 left-1/2 hidden -translate-x-1/2 lg:block xl:hidden">
          <ArrowDown />
        </div>
      ) : null}
    </div>
  )
}

function ArrowDown() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      className="h-6 w-6 text-stone-400 dark:text-stone-500"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 5v14" />
      <path d="m6 13 6 6 6-6" />
    </svg>
  )
}
