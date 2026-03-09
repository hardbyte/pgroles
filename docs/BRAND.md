# pgroles Docs Brand Guide

This is an internal reference for the docs and marketing surface of `pgroles`.
It is not part of the published docs navigation.

## Brand Position

`pgroles` should read as a PostgreSQL control plane:

- operational
- deliberate
- infrastructural
- trustworthy
- auditable

It should not look like a generic developer SaaS template.

## Visual Principles

1. Light mode is the primary reference.
2. Dark mode must mirror the same hierarchy, not become a different product.
3. Surfaces should feel like guide panels or instrumentation, not soft marketing cards.
4. Accents should communicate role, not decoration.
5. Documentation pages should remain highly readable before they become expressive.

## Typography

- Display: `Space Grotesk`
- Body: `IBM Plex Sans`
- Code: `IBM Plex Mono`

Usage:

- `font-display` for page titles, section labels, and key UI chrome
- `font-sans` for all body content
- `font-mono` for code, SQL, and command examples

## Color System

### Base neutrals

Use the `stone` scale for structure:

- `stone-50/100`: light-mode backgrounds
- `stone-300`: light-mode borders and dividers
- `stone-500/600`: secondary text
- `stone-900/950`: dark surfaces and code panels
- `stone-700`: dark-mode borders

### Accent roles

#### Amber

Use amber for:

- active navigation
- primary actions
- plan/change emphasis
- warning or attention states

Representative shades:

- `amber-300`: light emphasis borders/backgrounds
- `amber-500`: active accents
- `amber-900/950`: light-mode text accents

#### Teal

Use teal for:

- system/control-plane cues
- informational callouts
- observability/runtime concepts
- secondary diagram emphasis

Representative shades:

- `teal-300`: light emphasis borders/backgrounds
- `teal-500`: active accents
- `teal-900/950`: light-mode text accents

## Component Rules

### Header and shell

- header should feel precise, not decorative
- sidebar and TOC should read as guide panels
- keep rounded corners, but avoid “pillowy” cards everywhere

### Hero

- same information architecture in light and dark themes
- light mode uses pale stone/white surfaces with dark code wells
- dark mode can be more dramatic, but must keep the same structure

### Callouts and quick links

- these must belong to the same family
- use left rails, structured borders, and restrained accent labels
- avoid generic feature-card gradients

### Diagrams

- diagrams should use the same palette as the docs shell
- default diagram tones are:
  - `stone` for structure
  - `amber` for change/action
  - `teal` for control-plane/runtime
- avoid reintroducing `sky`, `indigo`, `rose`, `cyan`, or other template-era colors unless there is a strong reason

## Interaction Style

- motion should be minimal and purposeful
- hover states should sharpen hierarchy, not add spectacle
- transitions should be subtle enough not to distract from reading

## Copy and Tone

The UI should reinforce the product voice:

- clear
- technical
- concrete
- low-fluff

Avoid:

- generic SaaS language
- playful embellishment
- unexplained visual flourishes

## Implementation Notes

- Prefer existing `stone`, `amber`, and `teal` utility classes over inventing one-off gradients.
- If a new component needs a new visual pattern, align it with one of the established families:
  - shell panel
  - guide panel
  - callout
  - diagram card
- If a component still uses older palette names like `blue`, `sky`, `indigo`, `emerald`, `rose`, or `cyan`, treat that as design debt and normalize it.
