---
name: ThreatScope Dashboard
description: A calm night-shift console for triaging security events, where severity is the only loud thing.
colors:
  night-ground: "#0B1220"
  sidebar-ground: "#0D1525"
  panel: "#111A2B"
  panel-hover: "#16223A"
  slate-border: "#1E2B44"
  text: "#E6EDF7"
  muted: "#9AA9C0"
  faint: "#64748B"
  cyan-accent: "#22D3EE"
  cyan-muted: "#1F7A90"
  healthy-green: "#34D399"
  critical-rose: "#F43F5E"
  high-orange: "#F97316"
  medium-amber: "#FBBF24"
  low-blue: "#3B82F6"
  info-slate: "#94A3B8"
  investigating-violet: "#A78BFA"
typography:
  title:
    fontFamily: "Source Sans Pro, Segoe UI, system-ui, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 700
    lineHeight: 1.25
    letterSpacing: "-0.01em"
  kpi-value:
    fontFamily: "Source Sans Pro, Segoe UI, system-ui, sans-serif"
    fontSize: "1.9rem"
    fontWeight: 700
    lineHeight: 1.15
    fontFeature: "tnum"
  panel-title:
    fontFamily: "Source Sans Pro, Segoe UI, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 600
  body:
    fontFamily: "Source Sans Pro, Segoe UI, system-ui, sans-serif"
    fontSize: "13.5px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "Source Sans Pro, Segoe UI, system-ui, sans-serif"
    fontSize: "12.5px"
    fontWeight: 600
  mono:
    fontFamily: "Source Code Pro, Cascadia Mono, Consolas, monospace"
    fontSize: "12.5px"
    fontWeight: 400
rounded:
  sm: "6px"
  md: "8px"
  lg: "10px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "12px"
  lg: "18px"
  page-x: "2rem"
components:
  panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.lg}"
    padding: "16px 18px 22px"
  kpi-card:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.lg}"
    padding: "15px 18px 14px"
  button:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.md}"
  button-hover:
    backgroundColor: "{colors.panel-hover}"
    textColor: "{colors.text}"
  status-pill:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.pill}"
    padding: "4px 11px"
  tag:
    textColor: "{colors.cyan-accent}"
    rounded: "{rounded.sm}"
    padding: "0 8px"
---

# Design System: ThreatScope Dashboard

## Overview

**Creative North Star: "The Night-Shift Console"**

A quiet room with the lights down and one instrument panel lit. The ground is deep navy, panels are one step lighter, edges are 1px slate lines, and nothing glows. Cyan is the single accent and is spent on selection, the focus ring, the active nav item, tags and trend. The only other colour that appears is severity, and it never appears alone: every severity colour travels with a text label, so the console reads in greyscale.

The density is dense but calm, for an analyst triaging on a laptop and for examiners watching a live run. Numbers are tabular, identifiers (IPs, hashes, ids, event types) are monospace, everything else is the sans face. Empty and error states speak plainly and stay inside the same panel language rather than becoming illustrations.

**Key Characteristics:**
- Navy ground, one cyan accent, severity colours reserved for severity.
- Flat: depth is tonal layering plus 1px borders, no shadows, no glow, no gradients.
- 10px panels, 8px controls, pill badges.
- Source Sans Pro for text, Source Code Pro only for identifiers, tabular numerals for counts.
- Colour is always backed by a text label.

## Colors

A navy-and-slate neutral family with one cyan accent, a fixed five-step severity scale, and a green for healthy.

### Primary
- **Signal Cyan** (#22D3EE): the single accent. Focus ring, selection tint, active nav background (at 14% alpha), button hover border, cross-source tags, the indicator diamonds in the relationship graph, the "open" incident status, and informational icons.
- **Dimmed Cyan** (#1F7A90): the accent at roughly 45% over a panel. Used for neutral bars (events by source) that must not compete with severity colours.

### Secondary
- **Healthy Green** (#34D399): only the "healthy" state dot in status pills.

### Tertiary (severity and status)
- **Critical Rose** (#F43F5E): critical severity; also the unavailable state dot and error titles.
- **High Orange** (#F97316), **Medium Amber** (#FBBF24), **Low Blue** (#3B82F6), **Info Slate** (#94A3B8): the rest of the fixed severity scale.
- **Investigating Violet** (#A78BFA): the "investigating" incident status, the only non-severity, non-accent hue; closed reuses Muted.

### Neutral
- **Night Ground** (#0B1220): page background.
- **Sidebar Ground** (#0D1525): sidebar, a slightly cooler second layer.
- **Panel** (#111A2B): panels, KPI cards, pills, buttons, skeletons.
- **Panel Hover** (#16223A): table row hover, button hover, chart tooltips.
- **Slate Border** (#1E2B44): every 1px edge and row divider.
- **Text** (#E6EDF7): primary text.
- **Muted** (#9AA9C0): secondary text, captions, table headers (about 6.8:1 on panel).
- **Faint** (#64748B): decoration only (chart gridlines at low alpha, the unknown-state dot). Never text.

### Named Rules
**The Severity-Only Loudness Rule.** Warm and red hues mean severity and nothing else. A KPI figure takes its severity colour only when the count is above zero; zero stays neutral so colour means something when it appears.

**The Label Beside Colour Rule.** A colour that carries meaning (severity, incident status, health) is always accompanied by its word: badge text, pill text, KPI label.

**The One Voice Rule.** Cyan is the only accent. Neutral data (counts by source) uses the dimmed cyan, never a second hue.

## Typography

**Display Font:** none; the page title is Source Sans Pro bold.
**Body Font:** Source Sans Pro (with Segoe UI, system-ui, Roboto, Arial). It ships inside Streamlit, so every machine and the data grid canvas draw the same face.
**Label/Mono Font:** Source Code Pro (with Cascadia Mono, Consolas, Menlo).

**Character:** a single humanist sans does all the work through weight and size; monospace marks "this is a machine value you may copy".

### Hierarchy
- **Title** (700, 1.5rem, 1.25, -0.01em): page title, one per page, followed by a muted 0.92rem one-line description.
- **KPI value** (700, 1.9rem, 1.15, tabular): the one number per KPI card.
- **Panel title** (600, 15px): panel heading, with a muted 13px subtitle beneath.
- **Body** (400, 13.5px, ~1.45): table cells, definition values, state text (capped at 62ch).
- **Label** (600, 12.5px, muted): table column headers; badges are 12px/600; KPI labels and context are 13px muted.
- **Mono** (400, 12.5px): IPs, domains, URLs, hashes, ids, event types and rule names.

### Named Rules
**The Mono-Means-Machine Rule.** Monospace is for identifiers and values only, never for headings, labels or prose.

**The Tabular Rule.** Counts and scores use tabular numerals and right alignment in tables.

## Layout

A fixed left sidebar (name plus navigation) and a content column capped at 1440px with 2rem side padding (1.4rem top). Each page opens with the title and description at left and the status cluster (API and Database pills, "Updated HH:MM UTC", Refresh) right-aligned. Overview then stacks a row of five equal KPI cards, three chart panels (events over time wide, severity, source), the recent events table, and a final row pairing top recurring indicators with recent high-risk activity. Charts are 270px high with identical bar thickness (26px) across panels. Spacing is a small rhythm of 4, 8, 12 and 16-18px inside components. Tables scroll horizontally inside a 620px minimum width. Below 760px the content padding shrinks to 1rem, the status cluster left-aligns, and definition lists collapse to a single column.

## Elevation & Depth

Flat. Depth is conveyed by tonal layering (ground, sidebar, panel, hover) and 1px slate borders. The build has no box-shadows and no glow; the only motion is a 0.15s background/border transition on controls and a pulsing opacity on loading skeletons, both disabled under reduced motion.

### Named Rules
**The Flat-By-Default Rule.** A surface is distinguished by its panel tone and border, never by a shadow or glow. Hover and active states change tone or border colour only.

## Shapes

Soft rectangles with small radii: 10px for panels, KPI cards and skeletons; 8px for buttons and nav links; 6px for tags; fully rounded pills for status pills and severity and status badges. Borders are always 1px; badges and tags use a 40-45% tint of their own colour as the border over a 15% tint fill (badges). Icons are drawn 1.8px-stroke line SVGs at 22px (info, alert) plus Material icons from Streamlit; no emoji, no glyph icons.

## Components

### Buttons
- **Shape:** 8px radius, 1px slate border.
- **Default:** Panel fill, Text colour, 13.5px.
- **Hover / Focus:** panel-hover fill and a cyan border; active takes a 14% cyan wash; focus-visible is a 2px cyan outline with 2px offset; disabled is 50% opacity.

### Panels and KPI cards
- **Corner Style:** 10px. **Background:** Panel. **Border:** 1px slate. **Shadow:** none.
- **Padding:** 16px 18px 22px (panel), 15px 18px 14px (KPI).
- **KPI anatomy:** small dot plus 13px muted label, 1.9rem figure, 13px muted factual context line. The dot takes the severity or status colour.

### Badges and pills
- **Severity and status badge:** pill, 12px/600, text in the colour, 15% colour fill, 40% colour border, word always present.
- **Status pill (header):** pill on Panel with a 8px dot (green healthy, rose unavailable, faint unknown) and a text label.
- **Tag:** 6px radius, cyan text and 45% cyan border, e.g. "cross-source".

### Tables
Borderless except 1px slate row dividers; muted 12.5px semibold headers; 9px 10px cell padding; row hover to Panel Hover; numeric columns right-aligned and tabular. Identifiers are mono, timestamps are muted and nowrap and always labelled UTC.

### Definition lists
Two-column grid (11rem label, muted 13px; value 13.5px) with slate row dividers, used for event, indicator and incident detail.

### Navigation
Sidebar on Sidebar Ground with a 1px slate right border. Links are 8px radius, muted 14.5px; hover gives a 8% cyan wash and Text colour; the current page gets a 14% cyan wash and weight 600.

### States
Empty states use an info icon in cyan, error states an alert icon in rose with a rose title, both with a 14.5px/600 title and muted text, in the same panel with no illustration. Loading uses a pulsing Panel-coloured skeleton block.

### Charts
Plotly on a transparent ground, muted 12px labels, gridlines Faint at 18% alpha, tooltips on Panel Hover with a slate border. Severity series use the fixed severity colours with critical at the bottom of stacks; horizontal bars carry a value label outside the bar; the relationship graph uses cyan diamonds for indicators and severity-coloured circles for events.

## Do's and Don'ts

### Do:
- **Do** keep severity colours bound to severity and always show the label word beside them.
- **Do** draw every colour from the token set in `theme.py` so CSS, badges and charts agree.
- **Do** use mono for identifiers only and tabular numerals for counts.
- **Do** keep panels flat: Panel fill, 1px Slate Border, 10px radius.
- **Do** label times as UTC and the score as an experimental prioritisation score.
- **Do** keep focus visible with the 2px cyan outline.

### Don't:
- **Don't** add a second accent hue or use warm colours for anything but severity.
- **Don't** add shadows, glow, gradients or decorative widgets.
- **Don't** use Faint (#64748B) for text.
- **Don't** carry meaning by colour alone.
- **Don't** put raw colours in inline styles; Streamlit strips them, so colour travels as a class (`sev-*`, `st-*`).
