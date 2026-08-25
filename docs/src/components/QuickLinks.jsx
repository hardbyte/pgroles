import Link from 'next/link'
import { Badge } from '@partly/pitstop/badge'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@partly/pitstop/card'

import { Icon } from '@/components/Icon'

export function QuickLinks({ children }) {
  return (
    <div className="not-prose my-14 grid grid-cols-1 gap-4 sm:grid-cols-2">
      {children}
    </div>
  )
}

export function QuickLink({ title, description, href, icon }) {
  return (
    <Card className="group relative gap-4 transition duration-200 hover:-translate-y-0.5 hover:ring-primary/70 focus-within:ring-primary/70">
      <CardHeader>
        <CardAction>
          <Badge variant="outline">{getCategory(href)}</Badge>
        </CardAction>
        <div className="mb-2 inline-flex w-fit rounded-xl border bg-muted p-2">
          <Icon icon={icon} className="h-6 w-6" />
        </div>
        <CardTitle className="font-display text-lg leading-7 tracking-[-0.02em]">
          <Link href={href}>
            {/* Stretches the link's hit area across the whole card. */}
            <span className="absolute inset-0 rounded-[inherit]" />
            {title}
          </Link>
        </CardTitle>
        <CardDescription className="max-w-[28rem] leading-6">
          {description}
        </CardDescription>
      </CardHeader>
      <CardContent className="flex items-center gap-2 text-[11px] font-semibold tracking-[0.18em] text-amber-700 uppercase dark:text-amber-300">
        <span>Open guide</span>
        <span aria-hidden="true" className="transition group-hover:translate-x-0.5">
          &rarr;
        </span>
      </CardContent>
    </Card>
  )
}

function getCategory(href) {
  if (href.includes('/cli')) return 'Reference'
  if (href.includes('/quick-start')) return 'Start here'
  if (href.includes('/manifest-format')) return 'Schema'
  if (href.includes('/profiles')) return 'Patterns'
  return 'Guide'
}
