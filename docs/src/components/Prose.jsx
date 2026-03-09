import clsx from 'clsx'

export function Prose({ as: Component = 'div', className, ...props }) {
  return (
    <Component
      className={clsx(
        className,
        'prose prose-stone max-w-none dark:prose-invert dark:text-stone-300',
        // headings
        'prose-headings:scroll-mt-28 prose-headings:font-display prose-headings:font-normal prose-headings:tracking-[-0.02em] lg:prose-headings:scroll-mt-[8.5rem]',
        // lead
        'prose-lead:text-stone-600 dark:prose-lead:text-stone-400',
        // links
        'prose-a:font-semibold prose-a:text-stone-900 dark:prose-a:text-stone-100',
        // link underline
        'prose-a:no-underline prose-a:shadow-[inset_0_-2px_0_0_var(--tw-prose-background,#fff),inset_0_calc(-1*(var(--tw-prose-underline-size,4px)+2px))_0_0_var(--tw-prose-underline,theme(colors.amber.300))] hover:prose-a:[--tw-prose-underline-size:6px] dark:[--tw-prose-background:theme(colors.stone.950)] dark:prose-a:shadow-[inset_0_calc(-1*var(--tw-prose-underline-size,2px))_0_0_var(--tw-prose-underline,theme(colors.amber.700))] dark:hover:prose-a:[--tw-prose-underline-size:6px]',
        // pre
        'prose-pre:rounded-2xl prose-pre:border prose-pre:border-stone-800 prose-pre:bg-stone-950 prose-pre:shadow-[0_22px_50px_-36px_rgba(28,25,23,0.85)] dark:prose-pre:border-stone-700 dark:prose-pre:bg-stone-900 dark:prose-pre:shadow-none',
        // hr
        'prose-hr:border-stone-300 dark:prose-hr:border-stone-800'
      )}
      {...props}
    />
  )
}
