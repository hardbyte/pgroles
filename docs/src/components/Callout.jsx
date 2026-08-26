import { IconAlertTriangle, IconBulb, IconSchool } from '@tabler/icons-react'
import { Alert, AlertDescription, AlertTitle } from '@partly/pitstop/alert'

const variants = {
  note: { intent: 'info', icon: IconBulb },
  warning: { intent: 'warning', icon: IconAlertTriangle },
  beginner: { intent: 'default', icon: IconSchool },
}

export function Callout({ type = 'note', title, children }) {
  let { intent, icon: CalloutIcon } = variants[type] ?? variants.note

  return (
    <Alert intent={intent} className="my-8">
      <CalloutIcon aria-hidden="true" />
      <AlertTitle className="font-display text-base tracking-[0.18em] uppercase">
        {title}
      </AlertTitle>
      <AlertDescription className="prose prose-sm mt-2 max-w-none dark:prose-invert prose-code:before:content-none prose-code:after:content-none">
        {children}
      </AlertDescription>
    </Alert>
  )
}
