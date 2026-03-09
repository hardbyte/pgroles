import clsx from 'clsx'

import { Icon } from '@/components/Icon'

const styles = {
  note: {
    container:
      'border border-teal-200/90 bg-white dark:border-teal-900/50 dark:bg-stone-900',
    rail: 'bg-[linear-gradient(180deg,rgba(13,148,136,0.9),rgba(20,184,166,0.55))]',
    badge: 'border-stone-200 bg-stone-50 text-stone-800 dark:border-stone-700 dark:bg-stone-950 dark:text-stone-300',
    title: 'text-stone-950 dark:text-stone-100',
    body: 'text-stone-700 [--tw-prose-background:theme(colors.white)] [--tw-prose-underline:theme(colors.teal.300)] prose-a:text-teal-950 prose-code:text-teal-950 dark:text-stone-300 dark:[--tw-prose-background:theme(colors.stone.900)] dark:[--tw-prose-underline:theme(colors.teal.800)] dark:prose-code:text-stone-200',
  },
  warning: {
    container:
      'border border-amber-200/90 bg-white dark:border-amber-900/50 dark:bg-stone-900',
    rail: 'bg-[linear-gradient(180deg,rgba(217,119,6,0.92),rgba(245,158,11,0.55))]',
    badge: 'border-amber-200 bg-amber-50 text-amber-950 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300',
    title: 'text-amber-950 dark:text-amber-300',
    body: 'text-stone-700 [--tw-prose-background:theme(colors.white)] [--tw-prose-underline:theme(colors.amber.400)] prose-a:text-amber-950 prose-code:text-amber-950 dark:text-stone-300 dark:[--tw-prose-background:theme(colors.stone.900)] dark:[--tw-prose-underline:theme(colors.amber.800)] dark:prose-code:text-stone-200',
  },
  beginner: {
    container:
      'border border-stone-300/90 bg-white dark:border-stone-700 dark:bg-stone-900',
    rail: 'bg-[linear-gradient(180deg,rgba(87,83,78,0.95),rgba(120,113,108,0.55))]',
    badge: 'border-stone-200 bg-stone-50 text-stone-800 dark:border-stone-700 dark:bg-stone-950 dark:text-stone-300',
    title: 'text-stone-900 dark:text-stone-100',
    body: 'text-stone-700 [--tw-prose-background:theme(colors.white)] [--tw-prose-underline:theme(colors.amber.300)] prose-a:text-stone-950 prose-code:text-stone-950 dark:text-stone-300 dark:[--tw-prose-background:theme(colors.stone.900)] dark:[--tw-prose-underline:theme(colors.amber.800)] dark:prose-code:text-stone-200',
  },
}

const icons = {
  note: (props) => <Icon icon="lightbulb" color="stone" {...props} />,
  warning: (props) => <Icon icon="warning" color="amber" {...props} />,
  beginner: (props) => <Icon icon="installation" color="stone" {...props} />,
}

export function Callout({ type = 'note', title, children }) {
  let IconComponent = icons[type]
  let style = styles[type]

  return (
    <div className={clsx('my-8 overflow-hidden rounded-[1.35rem] shadow-[0_16px_40px_-34px_rgba(28,25,23,0.3)] dark:shadow-none', style.container)}>
      <div className="flex">
        <div className={clsx('w-1.5 flex-none', style.rail)} />
        <div className="min-w-0 flex-auto p-5 sm:p-6">
          <div className="flex items-start gap-4">
            <div className={clsx('inline-flex rounded-xl border p-2 shadow-sm dark:shadow-none', style.badge)}>
              <IconComponent className="h-6 w-6 flex-none" />
            </div>
            <div className="min-w-0 flex-auto">
              <p className={clsx('m-0 font-display text-base uppercase tracking-[0.18em]', style.title)}>
                {title}
              </p>
              <div className={clsx('prose mt-2.5', style.body)}>
                {children}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
