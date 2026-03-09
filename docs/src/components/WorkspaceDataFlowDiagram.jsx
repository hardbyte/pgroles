export function WorkspaceDataFlowDiagram() {
  return (
    <div className="not-prose my-10 overflow-hidden rounded-[2rem] border border-stone-300/90 bg-[linear-gradient(180deg,#fff,rgba(245,245,244,0.96))] shadow-[0_26px_70px_-44px_rgba(28,25,23,0.35)] dark:border-stone-700 dark:bg-[linear-gradient(180deg,rgba(28,25,23,0.96),rgba(17,24,39,0.9))] dark:shadow-none">
      <div className="border-b border-stone-300/80 bg-white/90 px-6 py-4 backdrop-blur dark:border-stone-700 dark:bg-stone-900/85">
        <p className="m-0 font-display text-lg text-stone-900 dark:text-white">Workspace data flow</p>
        <p className="mt-1 text-sm text-stone-600 dark:text-stone-400">
          The CLI and operator both feed the same manifest, inspection, diff, and SQL rendering pipeline.
        </p>
      </div>

      <div className="px-5 py-6 sm:px-6">
        <div className="grid gap-4 xl:grid-cols-[0.95fr,1.35fr,0.95fr]">
            <DiagramSource
              eyebrow="Inputs"
              title="Desired state"
              tone="teal"
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
              tone="stone"
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
              tone="teal"
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
              tone="amber"
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
    teal: 'border-teal-200/80 bg-teal-50/55 dark:border-teal-900/60 dark:bg-teal-950/20',
    amber: 'border-amber-200/80 bg-amber-50/60 dark:border-amber-900/60 dark:bg-amber-950/20',
  }

  return (
    <div className={`rounded-[1.6rem] border p-5 ${tones[tone]}`}>
      <p className="m-0 text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">
        {eyebrow}
      </p>
      <p className="mt-2 font-display text-xl text-stone-900 dark:text-white">{title}</p>
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

function DiagramStage({ eyebrow, title, items, tone }) {
  const tones = {
    stone:
      'border-stone-300/90 bg-white dark:border-stone-700 dark:bg-stone-900/85',
    amber: 'border-amber-200/80 bg-white dark:border-amber-900/60 dark:bg-stone-900/85',
    teal:
      'border-teal-200/80 bg-white dark:border-teal-900/60 dark:bg-stone-900/85',
  }

  return (
    <div className={`rounded-[1.6rem] border p-5 shadow-[0_16px_34px_-28px_rgba(28,25,23,0.4)] dark:shadow-none ${tones[tone]}`}>
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

function FlowNote({ title, body }) {
  return (
    <div className="rounded-[1.5rem] border border-stone-300/90 bg-white/90 p-4 shadow-[0_14px_28px_-24px_rgba(28,25,23,0.35)] dark:border-stone-700 dark:bg-stone-900/80 dark:shadow-none">
      <p className="m-0 font-display text-lg text-stone-900 dark:text-white">{title}</p>
      <p className="mt-2 text-sm leading-6 text-stone-700 dark:text-stone-300">{body}</p>
    </div>
  )
}
