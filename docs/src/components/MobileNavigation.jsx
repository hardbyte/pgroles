import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { IconMenu2 } from '@tabler/icons-react'
import { Button } from '@partly/pitstop/button'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@partly/pitstop/sheet'

import { Logomark } from '@/components/Logo'
import { Navigation } from '@/components/Navigation'

export function MobileNavigation({ navigation }) {
  let router = useRouter()
  let [isOpen, setIsOpen] = useState(false)
  let shownPath = useRef(router.asPath)

  // Following a link inside the sheet dismisses it. The ref guard keeps this
  // to an actual navigation: a bare `setIsOpen(false)` here would also fire on
  // the re-render that opens the sheet.
  useEffect(() => {
    if (shownPath.current === router.asPath) return
    shownPath.current = router.asPath
    setIsOpen(false)
  }, [router.asPath])

  return (
    <Sheet isOpen={isOpen} onOpenChange={setIsOpen}>
      <Button variant="ghost" size="icon" aria-label="Open navigation">
        <IconMenu2 className="size-6" />
      </Button>
      <SheetContent side="left" className="px-4 pb-12 sm:px-6 lg:hidden">
        <SheetHeader className="px-0 pt-1">
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <Link href="/" aria-label="Home page">
            <Logomark className="h-9 w-9" />
          </Link>
        </SheetHeader>
        <Navigation navigation={navigation} className="px-1" />
      </SheetContent>
    </Sheet>
  )
}
