export function OperatorArchitectureDiagram() {
  return (
    <div className="not-prose my-10 overflow-hidden rounded-[2rem] border border-stone-300/90 bg-[linear-gradient(180deg,#fff,rgba(245,245,244,0.96))] shadow-[0_26px_70px_-44px_rgba(28,25,23,0.35)] dark:border-stone-700 dark:bg-[linear-gradient(180deg,rgba(28,25,23,0.96),rgba(17,24,39,0.9))] dark:shadow-none">
      <div className="border-b border-stone-300/80 bg-white/90 px-6 py-4 backdrop-blur dark:border-stone-700 dark:bg-stone-900/85">
        <p className="m-0 font-display text-lg text-stone-900 dark:text-white">
          Operator control plane
        </p>
        <p className="mt-1 text-sm text-stone-600 dark:text-stone-400">
          Kubernetes changes trigger reconciles, the operator serializes work per database target,
          then writes status and telemetry back out.
        </p>
      </div>

      <div className="px-5 py-6 sm:px-6">
        <div className="rounded-[1.4rem] border border-teal-200/80 bg-teal-50/60 px-4 py-3 text-center dark:border-teal-900/60 dark:bg-teal-950/25">
          <p className="m-0 text-xs font-semibold uppercase tracking-[0.2em] text-teal-800 dark:text-teal-300">
            Kubernetes API
          </p>
          <div className="mt-3 grid gap-3 sm:grid-cols-3">
            <DiagramChip title="PostgresPolicy" subtitle="generation changes" tone="teal" />
            <DiagramChip title="Secret" subtitle="resourceVersion changes" tone="amber" />
            <DiagramChip title="Status" subtitle="conditions and summary" tone="stone" />
          </div>
        </div>

        <div className="flex justify-center py-3">
          <VerticalArrow />
        </div>

        <div className="rounded-[2rem] border border-stone-300/90 bg-white/90 p-5 shadow-[0_18px_40px_-32px_rgba(28,25,23,0.28)] dark:border-stone-700 dark:bg-stone-900/80 dark:shadow-none">
          <div className="flex items-center justify-between gap-3 border-b border-stone-300/80 pb-4 dark:border-stone-700">
            <div>
              <p className="m-0 font-display text-xl text-stone-900 dark:text-white">
                pgroles-operator
              </p>
              <p className="mt-1 text-sm text-stone-600 dark:text-stone-400">
                Continuous PostgreSQL role reconciler
              </p>
            </div>
            <div className="rounded-full border border-stone-200 bg-stone-50 px-3 py-1 text-xs font-medium text-stone-600 dark:border-stone-700 dark:bg-stone-950 dark:text-stone-300">
              OTLP + probes
            </div>
          </div>

          <div className="mt-5 grid gap-4 xl:grid-cols-[0.95fr,1.25fr,1fr]">
            <DiagramPanel
              eyebrow="Watchers"
              title="Trigger sources"
              tone="teal"
              items={[
                'PostgresPolicy generation updates',
                'Referenced Secret changes',
                'Interval-based requeues',
              ]}
            />

            <DiagramPanel
              eyebrow="Reconcile pipeline"
              title="Desired state -> live state -> change plan"
              tone="stone"
              items={[
                'Fetch Secret and refresh sqlx pool',
                'Convert CRD to PolicyManifest',
                'Expand profiles and schemas',
                'Inspect PostgreSQL',
                'Diff current vs desired state',
                'Apply SQL in one transaction',
                'Patch status conditions and summary',
              ]}
            />

            <div className="grid gap-4">
              <DiagramPanel
                eyebrow="Safety"
                title="Production guardrails"
                tone="amber"
                items={[
                  'Ownership conflict detection',
                  'In-process per-database locking',
                  'PostgreSQL advisory locking',
                  'Error-aware retry and backoff',
                ]}
              />
              <DiagramPanel
                eyebrow="Observability"
                title="Runtime signals"
                tone="teal"
                items={[
                  '/livez',
                  '/readyz',
                  'OTLP metrics to Collector',
                ]}
              />
            </div>
          </div>
        </div>

        <div className="flex justify-center py-3">
          <VerticalArrow />
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <DiagramTerminal
            title="PostgreSQL"
            subtitle="roles, grants, default privileges, memberships"
            tone="stone"
          />
          <DiagramTerminal
            title="OpenTelemetry Collector"
            subtitle="metrics pipeline to your backend"
            tone="teal"
          />
        </div>
      </div>
    </div>
  )
}

function DiagramChip({ title, subtitle, tone }) {
  const tones = {
    teal: 'border-teal-200 bg-white text-teal-950 dark:border-teal-900/60 dark:bg-stone-900/80 dark:text-teal-200',
    amber:
      'border-amber-200 bg-white text-amber-900 dark:border-amber-900/60 dark:bg-stone-900/80 dark:text-amber-200',
    stone:
      'border-stone-300 bg-white text-stone-900 dark:border-stone-700 dark:bg-stone-900/80 dark:text-stone-200',
  }

  return (
    <div className={`rounded-2xl border px-3 py-3 text-left ${tones[tone]}`}>
      <p className="m-0 text-sm font-semibold">{title}</p>
      <p className="mt-1 text-xs opacity-80">{subtitle}</p>
    </div>
  )
}

function DiagramPanel({ eyebrow, title, items, tone }) {
  const tones = {
    teal: 'border-teal-200/80 bg-teal-50/80 dark:border-teal-900/60 dark:bg-teal-950/20',
    stone: 'border-stone-300/90 bg-stone-50 dark:border-stone-700 dark:bg-stone-950/40',
    amber: 'border-amber-200/80 bg-amber-50/80 dark:border-amber-900/60 dark:bg-amber-950/20',
  }

  return (
    <div className={`rounded-[1.5rem] border p-4 ${tones[tone]}`}>
      <p className="m-0 text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">
        {eyebrow}
      </p>
      <p className="mt-2 font-display text-lg text-stone-900 dark:text-white">{title}</p>
      <ul className="mt-4 space-y-2 text-sm text-stone-700 dark:text-stone-300">
        {items.map((item) => (
          <li key={item} className="flex gap-2">
            <span className="mt-1 h-2 w-2 flex-none rounded-full bg-stone-400/80 dark:bg-stone-500" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function DiagramTerminal({ title, subtitle, tone }) {
  const tones = {
    stone: 'border-stone-300/90 bg-white dark:border-stone-700 dark:bg-stone-900/80',
    teal:
      'border-teal-200 bg-white dark:border-teal-900/60 dark:bg-stone-900/80',
  }

  return (
    <div className={`rounded-[1.5rem] border px-5 py-4 shadow-[0_14px_28px_-24px_rgba(28,25,23,0.28)] dark:shadow-none ${tones[tone]}`}>
      <p className="m-0 font-display text-lg text-stone-900 dark:text-white">{title}</p>
      <p className="mt-1 text-sm text-stone-600 dark:text-stone-400">{subtitle}</p>
    </div>
  )
}

function VerticalArrow() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 48"
      className="h-10 w-5 text-teal-500 dark:text-teal-400"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 2v38" />
      <path d="M6 34l6 10 6-10" />
    </svg>
  )
}
