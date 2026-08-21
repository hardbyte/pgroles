import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import clsx from 'clsx'

function SectionLinks({ links, pathname }) {
  return (
    <ul
      role="list"
      className="mt-3 space-y-1.5 border-l border-stone-300/90 dark:border-stone-700 lg:mt-4"
    >
      {links.map((link) => (
        <li key={link.href} className="relative">
          <Link
            href={link.href}
            className={clsx(
              'block w-full rounded-r-lg py-1.5 pl-4 pr-3 transition before:pointer-events-none before:absolute before:-left-px before:top-0 before:h-full before:w-px',
              link.href === pathname
                ? 'bg-amber-50/80 font-semibold text-amber-800 before:bg-amber-500 dark:bg-stone-900 dark:text-amber-300 dark:before:bg-amber-400'
                : 'text-stone-600 before:hidden before:bg-stone-400 hover:bg-stone-100/80 hover:text-stone-900 hover:before:block dark:text-stone-400 dark:before:bg-stone-600 dark:hover:bg-stone-900/70 dark:hover:text-stone-200'
            )}
          >
            {link.title}
          </Link>
        </li>
      ))}
    </ul>
  )
}

function NavSection({ section, pathname }) {
  const containsCurrent = section.links.some((link) => link.href === pathname)
  const [open, setOpen] = useState(!section.collapsible || containsCurrent)

  // Navigating into a collapsed section opens it so the active page's
  // highlight is never hidden; navigating away leaves the reader's choice.
  useEffect(() => {
    if (containsCurrent) setOpen(true)
  }, [containsCurrent])

  const heading = (
    <h2 className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-stone-500 dark:text-stone-400">
      {section.title}
    </h2>
  )

  if (!section.collapsible) {
    return (
      <li>
        {heading}
        <SectionLinks links={section.links} pathname={pathname} />
      </li>
    )
  }

  return (
    <li>
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
        className="group flex w-full items-center justify-between gap-2 text-left"
      >
        {heading}
        <svg
          aria-hidden="true"
          viewBox="0 0 16 16"
          className={clsx(
            'h-3 w-3 shrink-0 fill-none stroke-stone-400 stroke-2 transition-transform group-hover:stroke-stone-600 dark:group-hover:stroke-stone-300',
            open ? 'rotate-90' : 'rotate-0'
          )}
        >
          <path d="M5.5 3.5 10 8l-4.5 4.5" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {open ? (
        <SectionLinks links={section.links} pathname={pathname} />
      ) : (
        <p className="mt-2 border-l border-stone-300/90 pl-4 text-xs text-stone-400 dark:border-stone-700 dark:text-stone-500">
          {section.links.length} chapters
        </p>
      )}
    </li>
  )
}

export function Navigation({ navigation, className }) {
  let router = useRouter()

  return (
    <nav className={clsx('text-base lg:text-sm', className)}>
      <ul role="list" className="space-y-8">
        {navigation.map((section) => (
          <NavSection
            key={section.title}
            section={section}
            pathname={router.pathname}
          />
        ))}
      </ul>
    </nav>
  )
}
