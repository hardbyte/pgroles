export function RoleGraphDiagram() {
  return (
    <div className="not-prose my-10 overflow-hidden rounded-[2rem] border border-stone-300/90 bg-[linear-gradient(180deg,#fff,rgba(245,245,244,0.96))] shadow-[0_26px_70px_-44px_rgba(28,25,23,0.35)] dark:border-stone-700 dark:bg-[linear-gradient(180deg,rgba(28,25,23,0.96),rgba(17,24,39,0.9))] dark:shadow-none">
      <div className="border-b border-stone-300/80 bg-white/90 px-6 py-4 backdrop-blur dark:border-stone-700 dark:bg-stone-900/85">
        <p className="m-0 font-display text-lg text-stone-900 dark:text-white">
          The role graph you are about to build
        </p>
        <p className="mt-1 text-sm text-stone-600 dark:text-stone-400">
          One login role, <span className="font-mono">analytics</span>, granted read-only access to
          the <span className="font-mono">public</span> schema in{' '}
          <span className="font-mono">mydb</span>.
        </p>
      </div>

      <div className="px-5 py-6 sm:px-6">
        <div className="grid items-center gap-4 xl:grid-cols-[minmax(0,0.9fr),auto,minmax(0,1.4fr)]">
          <RoleNode
            eyebrow="Role"
            name="analytics"
            comment="Analytics read-only role"
            attributes={['LOGIN']}
          />

          <EdgeArrow label="is granted" />

          <div className="grid min-w-0 gap-3">
            <GrantNode
              privilege="CONNECT"
              objectType="Database"
              objectName="mydb"
              body="Lets the role open a connection to the database."
              tone="teal"
            />
            <GrantNode
              privilege="USAGE"
              objectType="Schema"
              objectName="public"
              body="Lets the role reach the objects that live inside the schema."
              tone="stone"
            />
            <GrantNode
              privilege="SELECT"
              objectType="Tables"
              objectName="public.*"
              body="Read-only access to every table currently in the schema."
              tone="amber"
            />
          </div>
        </div>

        <div className="mt-6 grid gap-4">
          <GraphNote title="No membership edges yet">
            This manifest declares no <span className="font-mono">memberships</span>, so{' '}
            <span className="font-mono">analytics</span> holds every privilege directly. When you do
            add one, the edge runs <span className="font-mono">member -&gt; role</span>: the member
            inherits the privileges of the role it is granted, never the other way around.
          </GraphNote>
        </div>
      </div>
    </div>
  )
}

function RoleNode({ eyebrow, name, comment, attributes }) {
  return (
    <div className="min-w-0 rounded-[1.6rem] border border-teal-200/80 bg-teal-50/55 p-5 shadow-[0_16px_34px_-28px_rgba(28,25,23,0.4)] dark:border-teal-900/60 dark:bg-teal-950/20 dark:shadow-none">
      <p className="m-0 text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">
        {eyebrow}
      </p>
      <p className="mt-2 break-words font-mono text-xl text-stone-900 dark:text-white">{name}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {attributes.map((attribute) => (
          <span
            key={attribute}
            className="rounded-full border border-teal-200 bg-white px-3 py-1 font-mono text-xs text-teal-800 dark:border-teal-900/60 dark:bg-stone-900/80 dark:text-teal-200"
          >
            {attribute}
          </span>
        ))}
      </div>
      <p className="mt-4 text-sm leading-6 text-stone-700 dark:text-stone-300">{comment}</p>
    </div>
  )
}

function EdgeArrow({ label }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-1">
      <svg
        aria-hidden="true"
        viewBox="0 0 24 48"
        className="h-10 w-5 text-teal-500 dark:text-teal-400 xl:hidden"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M12 2v38" />
        <path d="M6 34l6 10 6-10" />
      </svg>
      <svg
        aria-hidden="true"
        viewBox="0 0 48 24"
        className="hidden h-5 w-10 text-teal-500 dark:text-teal-400 xl:block"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M2 12h38" />
        <path d="M34 6l10 6-10 6" />
      </svg>
      <p className="m-0 text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">
        {label}
      </p>
    </div>
  )
}

function GrantNode({ privilege, objectType, objectName, body, tone }) {
  const tones = {
    teal: 'border-teal-200/80 bg-white dark:border-teal-900/60 dark:bg-stone-900/85',
    stone: 'border-stone-300/90 bg-white dark:border-stone-700 dark:bg-stone-900/85',
    amber: 'border-amber-200/80 bg-white dark:border-amber-900/60 dark:bg-stone-900/85',
  }

  const chips = {
    teal: 'border-teal-200 bg-teal-50/80 text-teal-800 dark:border-teal-900/60 dark:bg-teal-950/30 dark:text-teal-200',
    stone:
      'border-stone-300 bg-stone-50 text-stone-800 dark:border-stone-700 dark:bg-stone-950/40 dark:text-stone-200',
    amber:
      'border-amber-200 bg-amber-50/80 text-amber-900 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-200',
  }

  return (
    <div
      className={`min-w-0 rounded-[1.5rem] border p-4 shadow-[0_14px_28px_-24px_rgba(28,25,23,0.35)] dark:shadow-none ${tones[tone]}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded-full border px-3 py-1 font-mono text-xs ${chips[tone]}`}>
          {privilege}
        </span>
        <span className="text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">
          {objectType}
        </span>
        <span className="break-all font-mono text-sm text-stone-900 dark:text-white">
          {objectName}
        </span>
      </div>
      <p className="mt-2 text-sm leading-6 text-stone-700 dark:text-stone-300">{body}</p>
    </div>
  )
}

function GraphNote({ title, children }) {
  return (
    <div className="rounded-[1.5rem] border border-stone-300/90 bg-white/90 p-4 shadow-[0_14px_28px_-24px_rgba(28,25,23,0.35)] dark:border-stone-700 dark:bg-stone-900/80 dark:shadow-none">
      <p className="m-0 font-display text-lg text-stone-900 dark:text-white">{title}</p>
      <p className="mt-2 text-sm leading-6 text-stone-700 dark:text-stone-300">{children}</p>
    </div>
  )
}
