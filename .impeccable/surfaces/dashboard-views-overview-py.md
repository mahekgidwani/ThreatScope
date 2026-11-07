---
version: 1
slug: "dashboard-views-overview-py"
primary_target: "dashboard/views/overview.py"
related_targets: []
---

# Dashboard shell and Overview

Mode: Operate. Audience: analyst triaging events; examiners watching a live demo on a laptop. Task: see at a glance what arrived, what is severe, what repeats; jump to detail. Constraints: Streamlit, real API data only, local only. The shell (sidebar, header, tokens) is shared by every later page.

## Direction contract

THESIS: A calm night-shift console where severity is the only loud thing. The category default of neon glow, gradient cards and decorative widgets is refused; quiet panels, one cyan accent, severity colours reserved for severity.

OWN-WORLD: Navy ground (#0B1220), a cooler second neutral for sidebar and panels (#0E1626 / #111A2B), 1px slate borders, 10px radius, no glow, soft low shadow only on floating elements. Cyan #22D3EE is the single accent (selection, primary action, trend). Severity palette fixed: critical rose-red, high orange, medium amber, low blue, info slate; always paired with a text label. System sans for everything, monospace only for IPs, hashes, ids; tabular numerals. Drawn Material icons, one weight.

STORY: Within five seconds the viewer reads: is the system healthy, how many events, how many are critical or high, what happened lately, what repeats. Then clicks into Events or Indicators.

FIRST VIEWPORT: Left sidebar with name and seven nav items. Header row: page title and one-line description at left; API and Database status pills, "Updated HH:MM UTC" and Refresh at right. Row of five equal KPI cards (Total, Critical, High-risk, Indicators, Open incidents) each with a label, one value and one factual context line. Below, three chart panels (events over time wide, severity, source). Lower rows hold the recent events table, then top recurring indicators beside recent high-risk activity.

FORM: Brief-pinned world (user specified palette, layout and rows); no concept roll run. seed: none (unavailable)

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
