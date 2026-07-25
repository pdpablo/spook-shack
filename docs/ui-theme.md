# Spook Shack UI Theme Direction

## Goal

The UI should evoke the vibe of Zenless Zone Zero's Spook Shack: dark, stylish, kinetic, and slightly urban-futurist, while still remaining a professional analyst workspace.

This is an inspiration target, not a request to copy protected art, logos, or exact game assets.

## Design principles

- **Dark noir base** — let the content glow against a low-light canvas.
- **Sharp framing** — use angular panels, hard edges, and layered cards.
- **Fast feedback** — keep interactions snappy and animated only where they add clarity.
- **Analyst first** — ensure the layout still supports long-form reading, filtering, and comparison.
- **Signal hierarchy** — let confidence, severity, and freshness read instantly.

## Visual language

### Palette
- Base background: charcoal, graphite, and blue-black
- Accent 1: neon cyan
- Accent 2: electric violet
- Accent 3: acid green
- Accent 4: warm amber
- Danger: crimson / orange-red
- Paper / text highlight: warm ivory

### Typography
- Display headings: condensed, modern, slightly aggressive
- Body text: clean sans-serif for readability
- Technical data: monospace for hashes, indicators, and source metadata

### Texture and atmosphere
- subtle scanlines or noise
- faint glow on active cards
- soft contrast gradients
- occasional sticker / label treatment for important tags

## Layout ideas

### Shell
- persistent left navigation rail
- top utility bar for source health, search, user profile, and theme state
- central working area with wide cards
- optional right-side inspector for raw source details, notes, and verdicts

### Dashboard components
- source cards with sync health and ingestion counts
- timeline widgets for spikes and bursts
- entity chips with confidence badges
- correlation graphs or relationship tables
- report composer with section blocks
- future-tech forecast board with maturity and risk scoring

## Component styling ideas

### Cards
- slightly elevated, with thin borders and asymmetric padding
- title bars that feel like agency dossiers
- active state glows in cyan/violet

### Buttons
- minimal primary buttons
- outlined secondary buttons
- destructive actions clearly separated and color-coded

### Chips / badges
- compact, rounded, but not too soft
- use color to show verdict, confidence, or severity

### Tables
- dense by default
- sticky headers
- row hover highlights
- monospace for hashes and raw indicators

### Charts
- restrained, high-contrast lines and bars
- avoid overly glossy gradients that reduce legibility

## Motion

Use motion sparingly:
- quick fade / slide in for cards and drawers
- subtle hover lift
- small pulse on new alerts
- avoid long looping motion that distracts analysts

## Copy style

The interface copy should sound like a SOC / CTI tool:
- source health
- freshness
- confidence
- verdict
- correlation
- cluster
- observed technique
- forecast

## Suggested page set

- Overview
- Sources
- Source Detail
- Search / Correlation
- Analyst Queue
- Reports
- Future Tech Lab
- Admin

## Future-tech panel style

The prediction dashboard should look like an intelligence lab:
- card for each emerging technology
- adjacent technology mapping
- attack-surface summary
- confidence meter
- evidence sources
- analyst commentary drawer

## Implementation note

If you later implement this in code, treat the theme as a token system rather than one-off page styling:
- colors
- border radii
- card shadows
- typography
- spacing density
- motion timing
- panel chrome

That keeps the theme coherent across the whole product.
