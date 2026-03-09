import Link from 'next/link'

import { Icon } from '@/components/Icon'

export function QuickLinks({ children }) {
  return (
    <div className="not-prose my-14 grid grid-cols-1 gap-4 sm:grid-cols-2">
      {children}
    </div>
  )
}

export function QuickLink({ title, description, href, icon }) {
  const category = getCategory(href)

  return (
    <div className="group relative overflow-hidden rounded-[1.35rem] border border-stone-300/90 bg-white transition duration-200 hover:-translate-y-0.5 hover:border-amber-400/80 hover:shadow-[0_18px_38px_-30px_rgba(28,25,23,0.35)] dark:border-stone-700 dark:bg-stone-900 dark:hover:border-teal-700/80 dark:hover:shadow-none">
      <div className="absolute left-0 top-0 h-full w-1 bg-[linear-gradient(180deg,rgba(245,158,11,0.9),rgba(20,184,166,0.7))]" />
      <div className="relative p-5 pl-6">
        <div className="flex items-start justify-between gap-4">
          <div className="inline-flex rounded-xl border border-stone-200 bg-stone-50 p-2 dark:border-stone-700 dark:bg-stone-950">
            <Icon icon={icon} className="h-6 w-6" />
          </div>
          <span className="rounded-full border border-stone-200 bg-stone-50 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-stone-500 dark:border-stone-700 dark:bg-stone-950 dark:text-stone-400">
            {category}
          </span>
        </div>

        <h2 className="mt-4 font-display text-lg leading-7 tracking-[-0.02em] text-stone-950 dark:text-stone-100">
          <Link href={href}>
            <span className="absolute inset-0 rounded-[1.35rem]" />
            {title}
          </Link>
        </h2>
        <p className="mt-2 max-w-[28rem] text-sm leading-6 text-stone-700 dark:text-stone-300">
          {description}
        </p>

        <div className="mt-5 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-amber-700 dark:text-amber-300">
          <span>Open guide</span>
          <span aria-hidden="true" className="transition group-hover:translate-x-0.5">
            →
          </span>
        </div>
      </div>
    </div>
  )
}

function getCategory(href) {
  if (href.includes('/cli')) return 'Reference'
  if (href.includes('/quick-start')) return 'Start here'
  if (href.includes('/manifest-format')) return 'Schema'
  if (href.includes('/profiles')) return 'Patterns'
  return 'Guide'
}
