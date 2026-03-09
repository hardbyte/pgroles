import React from 'react';
import Link from 'next/link'
import clsx from 'clsx'

const styles = {
  primary:
    'rounded-lg border border-amber-300 bg-amber-300 px-4 py-2 text-sm font-semibold text-stone-950 shadow-[0_14px_30px_-22px_rgba(217,119,6,0.7)] transition hover:-translate-y-px hover:bg-amber-200 focus:outline-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500/60 active:translate-y-0 active:bg-amber-400',
  secondary:
    'rounded-lg border border-stone-700/70 bg-stone-900/55 px-4 py-2 text-sm font-medium text-stone-100 transition hover:border-stone-500 hover:bg-stone-900/70 focus:outline-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-stone-500/50 active:text-stone-300',
}

export function Button({ variant = 'primary', className, href, icon, ...props }) {
  className = clsx(styles[variant], className)

  const content = (
    <>
    {icon && <span className="mr-2">{icon}</span>}
      {props.children}
    </>
  );

  return href ? (
    <Link href={href} className={className} {...props}>
      {content}
    </Link>
  ) : (
    <button className={className} {...props}>
      {content}
    </button>);
}
