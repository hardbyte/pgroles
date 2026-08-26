import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { IconChevronRight } from '@tabler/icons-react'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@partly/pitstop/collapsible'

import { cn } from '@/lib/utils'

function SectionHeading({ children }) {
  return (
    <h2 className="font-display text-[11px] font-semibold tracking-[0.22em] text-muted-foreground uppercase">
      {children}
    </h2>
  )
}

function SectionLinks({ links, pathname, className }) {
  return (
    <ul
      role="list"
      className={cn('mt-3 space-y-1.5 border-l lg:mt-4', className)}
    >
      {links.map((link) => (
        <li key={link.href} className="relative">
          <Link
            href={link.href}
            className={cn(
              'block w-full rounded-r-lg py-1.5 pr-3 pl-4 transition before:pointer-events-none before:absolute before:top-0 before:-left-px before:h-full before:w-px',
              link.href === pathname
                ? 'bg-amber-50/80 font-semibold text-amber-800 before:bg-amber-500 dark:bg-card dark:text-amber-300 dark:before:bg-amber-400'
                : 'text-muted-foreground before:hidden before:bg-border hover:bg-muted hover:text-foreground hover:before:block'
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
  const [isExpanded, setIsExpanded] = useState(
    !section.collapsible || containsCurrent
  )

  // Navigating into a collapsed section opens it so the active page's
  // highlight is never hidden; navigating away leaves the reader's choice.
  useEffect(() => {
    if (containsCurrent) setIsExpanded(true)
  }, [containsCurrent])

  if (!section.collapsible) {
    return (
      <li>
        <SectionHeading>{section.title}</SectionHeading>
        <SectionLinks links={section.links} pathname={pathname} />
      </li>
    )
  }

  return (
    <li>
      <Collapsible isExpanded={isExpanded} onExpandedChange={setIsExpanded}>
        <CollapsibleTrigger className="group flex w-full items-center justify-between gap-2 rounded-sm text-left">
          <SectionHeading>{section.title}</SectionHeading>
          <IconChevronRight className="size-3.5 shrink-0 text-muted-foreground transition-transform group-expanded/collapsible:rotate-90" />
        </CollapsibleTrigger>
        <CollapsibleContent>
          <SectionLinks links={section.links} pathname={pathname} />
        </CollapsibleContent>
        <p className="mt-2 border-l pl-4 text-xs text-muted-foreground group-expanded/collapsible:hidden">
          {section.links.length} chapters
        </p>
      </Collapsible>
    </li>
  )
}

export function Navigation({ navigation, className }) {
  let router = useRouter()

  return (
    <nav className={cn('text-base lg:text-sm', className)}>
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
