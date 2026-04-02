import { Button } from '@/components/Button'

const manifestSnippet = `profiles:
  writer:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE, TRIGGER]
        object: { type: table, name: "*" }
      - privileges: [USAGE, SELECT, UPDATE]
        object: { type: sequence, name: "*" }`

const planSnippet = `Plan: 4 change(s)
  1 role(s) to create
  2 grant(s) to add
  1 default privilege(s) to set`

const statusSnippet = `status:
  conditions:
    - type: Ready
      status: "True"
      reason: Planned
    - type: Drifted
      status: "True"`

export function Hero() {
  return (
    <div className="relative overflow-hidden bg-stone-100 text-stone-900 dark:bg-stone-950 dark:text-stone-100">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(245,158,11,0.18),transparent_24%),radial-gradient(circle_at_82%_12%,rgba(20,184,166,0.12),transparent_24%),linear-gradient(180deg,rgba(255,255,255,0.98),rgba(245,245,244,0.96))] dark:bg-[radial-gradient(circle_at_top_left,rgba(245,158,11,0.28),transparent_26%),radial-gradient(circle_at_78%_8%,rgba(20,184,166,0.2),transparent_24%),linear-gradient(180deg,rgba(12,10,9,0.96),rgba(12,10,9,0.92))]" />
      <div className="absolute inset-0 opacity-[0.08] [background-image:linear-gradient(rgba(28,25,23,0.08)_1px,transparent_1px),linear-gradient(90deg,rgba(28,25,23,0.08)_1px,transparent_1px)] [background-size:28px_28px] dark:opacity-[0.08] dark:[background-image:linear-gradient(rgba(255,255,255,0.14)_1px,transparent_1px),linear-gradient(90deg,rgba(255,255,255,0.14)_1px,transparent_1px)]" />
      <div className="absolute inset-x-0 bottom-0 h-20 bg-[linear-gradient(180deg,rgba(245,245,244,0)_0%,rgba(245,245,244,0.94)_86%,rgb(245,245,244)_100%)] dark:h-24 dark:bg-[linear-gradient(180deg,rgba(12,10,9,0)_0%,rgba(12,10,9,0.92)_88%,rgb(12,10,9)_100%)]" />

      <div className="relative py-14 sm:px-2 lg:py-16">
        <div className="mx-auto grid max-w-8xl grid-cols-1 gap-10 px-4 lg:grid-cols-[0.94fr,1.06fr] lg:gap-12 lg:px-8 xl:px-12">
          <div className="max-w-xl">
            <div className="flex flex-wrap gap-2 text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-300">
              <span className="rounded-full border border-stone-300 bg-white/90 px-3 py-1 shadow-sm dark:border-stone-700 dark:bg-stone-900/60 dark:shadow-none">CLI</span>
              <span className="rounded-full border border-stone-300 bg-white/90 px-3 py-1 shadow-sm dark:border-stone-700 dark:bg-stone-900/60 dark:shadow-none">Operator</span>
              <span className="rounded-full border border-amber-300 bg-amber-50 px-3 py-1 text-amber-900 shadow-sm dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200 dark:shadow-none">Plan before apply</span>
            </div>

            <h1 className="mt-5 max-w-2xl font-display text-[2.8rem] leading-[1.02] tracking-[-0.04em] text-stone-950 sm:text-[3.35rem] dark:text-stone-50">
              Treat PostgreSQL access like a control plane, not a pile of grants.
            </h1>

            <p className="mt-5 max-w-xl text-lg leading-8 text-stone-700 dark:text-stone-300">
              Define roles, memberships, schema profiles, and default privileges once. Review the exact SQL plan, then let pgroles converge the database and keep drift visible.
            </p>

            <div className="mt-8 flex flex-wrap gap-4">
              <Button href="/docs/quick-start">Start with a diff</Button>
              <Button href="/docs/operator" variant="secondary">
                Explore the operator
              </Button>
            </div>

            <dl className="mt-9 grid gap-5 border-t border-stone-300/90 pt-5 dark:border-stone-800/90 sm:grid-cols-3">
              <Stat label="Convergent model" value="Manifest is truth" />
              <Stat label="Preview path" value="CLI diff + operator plan" />
              <Stat label="Runtime" value="CI, OTLP, Kubernetes" />
            </dl>
          </div>

          <div className="grid gap-4 lg:pt-3">
            <ConsoleCard
              title="Policy manifest"
              eyebrow="Desired state"
              tone="amber"
              code={manifestSnippet}
            />
            <div className="grid gap-4 lg:grid-cols-[0.92fr,1.08fr]">
              <ConsoleCard
                title="Diff summary"
                eyebrow="Change plan"
                tone="teal"
                code={planSnippet}
              />
              <ConsoleCard
                title="Operator status"
                eyebrow="Control plane"
                tone="stone"
                code={statusSnippet}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function Stat({ label, value }) {
  return (
    <div>
      <dt className="text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">{label}</dt>
      <dd className="mt-2 font-display text-base text-stone-900 dark:text-stone-100">{value}</dd>
    </div>
  )
}

function ConsoleCard({ eyebrow, title, code, tone }) {
  const tones = {
    amber:
      'border-amber-300/80 bg-white/88 shadow-[0_24px_50px_-34px_rgba(217,119,6,0.18)] dark:border-amber-500/30 dark:bg-stone-950/70 dark:shadow-[0_24px_50px_-34px_rgba(245,158,11,0.32)]',
    teal:
      'border-teal-300/80 bg-white/88 shadow-[0_24px_50px_-34px_rgba(13,148,136,0.16)] dark:border-teal-500/30 dark:bg-stone-950/70 dark:shadow-[0_24px_50px_-34px_rgba(20,184,166,0.28)]',
    stone:
      'border-stone-300/90 bg-stone-50/92 shadow-[0_24px_50px_-36px_rgba(28,25,23,0.15)] dark:border-stone-700 dark:!bg-stone-950/88 dark:shadow-[0_24px_50px_-38px_rgba(255,255,255,0.07)]',
  }

  const accents = {
    amber: 'bg-amber-500 dark:bg-amber-400',
    teal: 'bg-teal-500 dark:bg-teal-400',
    stone: 'bg-stone-500 dark:bg-stone-400',
  }

  return (
    <div className={`rounded-[1.45rem] border p-4 backdrop-blur ${tones[tone]}`}>
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="m-0 text-[11px] font-semibold uppercase tracking-[0.22em] text-stone-500 dark:text-stone-400">
            {eyebrow}
          </p>
          <p className="mt-2 font-display text-lg text-stone-950 dark:text-stone-50">{title}</p>
        </div>
        <div className="flex gap-1.5">
          <span className={`h-2.5 w-2.5 rounded-full ${accents[tone]}`} />
          <span className="h-2.5 w-2.5 rounded-full bg-stone-300 dark:bg-stone-700" />
          <span className="h-2.5 w-2.5 rounded-full bg-stone-300 dark:bg-stone-700" />
        </div>
      </div>
      <pre className="mt-4 overflow-x-auto rounded-[1.2rem] border border-stone-200 bg-stone-950 p-4 font-mono text-[13px] leading-6 text-stone-200 dark:border-stone-800">
        <code>{code}</code>
      </pre>
    </div>
  )
}
