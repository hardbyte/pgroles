import Link from 'next/link'
import { useRouter } from 'next/router'
import clsx from 'clsx'

export function Navigation({ navigation, className }) {
  let router = useRouter()

  return (
    <nav className={clsx('text-base lg:text-sm', className)}>
      <ul role="list" className="space-y-8">
        {navigation.map((section) => (
          <li key={section.title}>
            <h2 className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-stone-500 dark:text-stone-400">
              {section.title}
            </h2>
            <ul
              role="list"
              className="mt-3 space-y-1.5 border-l border-stone-300/90 dark:border-stone-700 lg:mt-4"
            >
              {section.links.map((link) => (
                <li key={link.href} className="relative">
                  <Link
                    href={link.href}
                    className={clsx(
                      'block w-full rounded-r-lg py-1.5 pl-4 pr-3 transition before:pointer-events-none before:absolute before:-left-px before:top-0 before:h-full before:w-px',
                      link.href === router.pathname
                        ? 'bg-amber-50/80 font-semibold text-amber-800 before:bg-amber-500 dark:bg-stone-900 dark:text-amber-300 dark:before:bg-amber-400'
                        : 'text-stone-600 before:hidden before:bg-stone-400 hover:bg-stone-100/80 hover:text-stone-900 hover:before:block dark:text-stone-400 dark:before:bg-stone-600 dark:hover:bg-stone-900/70 dark:hover:text-stone-200'
                    )}
                  >
                    {link.title}
                  </Link>
                </li>
              ))}
            </ul>
          </li>
        ))}
      </ul>
    </nav>
  )
}
