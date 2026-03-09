export function WorkspaceDataFlowDiagram() {
  return (
    <div className="not-prose my-10 overflow-hidden rounded-3xl border border-slate-200 bg-gradient-to-br from-white via-slate-50 to-cyan-50 shadow-xl shadow-slate-900/5 dark:border-slate-800 dark:from-slate-900 dark:via-slate-900 dark:to-slate-800">
      <div className="border-b border-slate-200/80 bg-white/80 px-6 py-4 backdrop-blur dark:border-slate-800 dark:bg-slate-900/80">
        <p className="m-0 font-display text-lg text-slate-900 dark:text-white">Workspace data flow</p>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          The CLI and operator both feed the same manifest, inspection, diff, and SQL rendering pipeline.
        </p>
      </div>

      <div className="px-5 py-6 sm:px-6">
        <div className="grid gap-4 xl:grid-cols-[0.95fr,1.35fr,0.95fr]">
          <DiagramSource
            eyebrow="Inputs"
            title="Desired state"
            tone="sky"
            items={[
              'YAML manifest or PostgresPolicy spec',
              'Profiles, schemas, grants, retirements',
              'Validation at parse time',
            ]}
          />

          <div className="grid gap-4">
            <DiagramStage
              eyebrow="pgroles-core"
              title="Manifest -> desired RoleGraph"
              tone="indigo"
              items={[
                'Parse PolicyManifest',
                'Expand profiles across schemas',
                'Normalize into desired RoleGraph',
              ]}
            />
            <DiagramStage
              eyebrow="pgroles-inspect"
              title="Database -> current RoleGraph"
              tone="amber"
              items={[
                'Inspect roles, grants, defaults, memberships',
                'Detect managed provider constraints',
                'Detect PostgreSQL version for SQL context',
              ]}
            />
            <DiagramStage
              eyebrow="Diff + render"
              title="Convergent change plan"
              tone="emerald"
              items={[
                'Compare current vs desired graphs',
                'Order changes safely',
                'Render SQL with version-aware syntax',
              ]}
            />
          </div>

          <DiagramSource
            eyebrow="Outputs"
            title="Execution surfaces"
            tone="rose"
            items={[
              'CLI diff / apply / generate',
              'Operator apply or plan mode',
              'SQL script, status, metrics, and Events',
            ]}
          />
        </div>

        <div className="mt-6 grid gap-4 lg:grid-cols-3">
          <FlowNote
            title="Shared engine"
            body="The operator is not a second implementation. It wraps the same manifest expansion, diffing, and SQL rendering code used by the CLI."
          />
          <FlowNote
            title="Convergent model"
            body="Desired state is complete. Anything missing from the manifest is treated as drift and planned for revocation or removal in dependency order."
          />
          <FlowNote
            title="Version-aware SQL"
            body="Inspection discovers the PostgreSQL version before rendering, so SQL stays compatible across the supported server versions."
          />
        </div>
      </div>
    </div>
  )
}

function DiagramSource({ eyebrow, title, items, tone }) {
  const tones = {
    sky: 'border-sky-200/80 bg-sky-50/80 dark:border-sky-900/60 dark:bg-sky-950/30',
    rose: 'border-rose-200/80 bg-rose-50/80 dark:border-rose-900/60 dark:bg-rose-950/20',
  }

  return (
    <div className={`rounded-3xl border p-5 ${tones[tone]}`}>
      <p className="m-0 text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">
        {eyebrow}
      </p>
      <p className="mt-2 font-display text-xl text-slate-900 dark:text-white">{title}</p>
      <ul className="mt-4 space-y-2 text-sm text-slate-700 dark:text-slate-300">
        {items.map((item) => (
          <li key={item} className="flex gap-2">
            <span className="mt-1 h-2 w-2 flex-none rounded-full bg-slate-400/80 dark:bg-slate-500" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function DiagramStage({ eyebrow, title, items, tone }) {
  const tones = {
    indigo:
      'border-indigo-200/80 bg-white dark:border-indigo-900/60 dark:bg-slate-900/80',
    amber: 'border-amber-200/80 bg-white dark:border-amber-900/60 dark:bg-slate-900/80',
    emerald:
      'border-emerald-200/80 bg-white dark:border-emerald-900/60 dark:bg-slate-900/80',
  }

  return (
    <div className={`rounded-3xl border p-5 shadow-sm ${tones[tone]}`}>
      <p className="m-0 text-[11px] font-semibold uppercase tracking-[0.2em] text-slate-500 dark:text-slate-400">
        {eyebrow}
      </p>
      <p className="mt-2 font-display text-lg text-slate-900 dark:text-white">{title}</p>
      <ul className="mt-4 space-y-2 text-sm text-slate-700 dark:text-slate-300">
        {items.map((item) => (
          <li key={item} className="flex gap-2">
            <span className="mt-1 h-2 w-2 flex-none rounded-full bg-slate-400/80 dark:bg-slate-500" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function FlowNote({ title, body }) {
  return (
    <div className="rounded-3xl border border-slate-200 bg-white/85 p-4 dark:border-slate-800 dark:bg-slate-900/80">
      <p className="m-0 font-display text-lg text-slate-900 dark:text-white">{title}</p>
      <p className="mt-2 text-sm leading-6 text-slate-700 dark:text-slate-300">{body}</p>
    </div>
  )
}
