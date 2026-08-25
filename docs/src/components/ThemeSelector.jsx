import { useEffect, useState } from 'react'
import { IconDeviceDesktop, IconMoon, IconSun } from '@tabler/icons-react'
import { Button } from '@partly/pitstop/button'
import { Menu, MenuContent, MenuGroup, MenuItem } from '@partly/pitstop/menu'

const themes = [
  { id: 'light', name: 'Light', icon: IconSun },
  { id: 'dark', name: 'Dark', icon: IconMoon },
  { id: 'system', name: 'System', icon: IconDeviceDesktop },
]

export function ThemeSelector({ className, ...props }) {
  // `system` matches what the inline script in `_document` renders, so the
  // first client render agrees with the server; the effect below then adopts
  // whatever the script actually resolved.
  let [theme, setTheme] = useState('system')

  useEffect(() => {
    setTheme(document.documentElement.getAttribute('data-theme') ?? 'system')
  }, [])

  useEffect(() => {
    let handler = () => setTheme(window.localStorage.theme ?? 'system')
    window.addEventListener('storage', handler)
    return () => window.removeEventListener('storage', handler)
  }, [])

  // The `data-theme` attribute is the source of truth: the observer installed
  // in `_document` persists it and toggles the `dark` class.
  function selectTheme(keys) {
    let [next] = keys
    if (!next) return
    setTheme(next)
    document.documentElement.setAttribute('data-theme', next)
  }

  return (
    <Menu {...props}>
      <Button
        variant="outline"
        size="icon"
        aria-label="Theme"
        className={className}
      >
        {/* Which glyph shows is decided in CSS from the attributes the inline
            theme script sets, so the button renders the same on the server. */}
        <IconSun className="hidden text-amber-600 [[data-theme=light]_&]:block" />
        <IconMoon className="hidden text-teal-500 [[data-theme=dark]_&]:block" />
        <IconSun className="hidden text-muted-foreground [:not(.dark)[data-theme=system]_&]:block" />
        <IconMoon className="hidden text-muted-foreground [.dark[data-theme=system]_&]:block" />
      </Button>
      <MenuContent className="w-36" aria-label="Theme">
        <MenuGroup
          aria-label="Theme"
          selectionMode="single"
          selectedKeys={[theme]}
          onSelectionChange={selectTheme}
        >
          {themes.map((option) => (
            <MenuItem key={option.id} id={option.id} textValue={option.name}>
              <option.icon />
              {option.name}
            </MenuItem>
          ))}
        </MenuGroup>
      </MenuContent>
    </Menu>
  )
}
