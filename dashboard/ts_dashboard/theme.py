"""Design tokens and the stylesheet. One place for every colour so charts, badges and CSS agree.

World: a calm night-shift console. Navy ground, one cyan accent, severity colours reserved for severity
(always paired with a text label), system sans, monospace only for IPs / hashes / ids.
"""

COLORS = {
    "bg": "#0B1220",          # page ground
    "sidebar": "#0D1525",     # second neutral layer, slightly cooler
    "panel": "#111A2B",
    "panel_hover": "#16223A",
    "border": "#1E2B44",
    "text": "#E6EDF7",
    "muted": "#9AA9C0",       # 6.8:1 on panel
    "faint": "#64748B",       # decoration only (grid lines, borders), never text
    "accent": "#22D3EE",
    "accent_muted": "#1F7A90",   # accent at ~45% over the panel: neutral bars that must not compete with severity colours
    "ok": "#34D399",
    "bad": "#F43F5E",
}
SEVERITY_COLOURS = {"critical": "#F43F5E", "high": "#F97316", "medium": "#FBBF24", "low": "#3B82F6", "info": "#94A3B8"}
SEVERITY_LABELS = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
SOURCE_LABELS = {"domain": "Domain", "honeypot": "Honeypot", "file": "File", "network": "Network"}
INDICATOR_LABELS = {"ip": "IP address", "domain": "Domain", "url": "URL", "sha256": "SHA-256"}
SCORE_NOTE = "Experimental prioritisation score — not a probability of compromise."
# Source Sans Pro / Source Code Pro ship inside Streamlit, so every machine (and the data grid's canvas) draws the same faces.
FONT_SANS = '"Source Sans Pro", "Segoe UI", system-ui, -apple-system, Roboto, "Helvetica Neue", Arial, sans-serif'
FONT_MONO = '"Source Code Pro", "Cascadia Mono", Consolas, "SF Mono", Menlo, monospace'


def css() -> str:
    c = COLORS
    variables = (f"--ts-bg:{c['bg']};--ts-sidebar:{c['sidebar']};--ts-panel:{c['panel']};"
                 f"--ts-panel-hover:{c['panel_hover']};--ts-border:{c['border']};--ts-text:{c['text']};"
                 f"--ts-muted:{c['muted']};--ts-faint:{c['faint']};--ts-accent:{c['accent']};--ts-ok:{c['ok']};"
                 f"--ts-bad:{c['bad']};--ts-sans:{FONT_SANS};--ts-mono:{FONT_MONO};")
    # Streamlit strips inline style attributes from markdown HTML, so colours travel as classes.
    severity_rules = "".join(f".sev-{name}{{--c:{colour};}}" for name, colour in SEVERITY_COLOURS.items())
    return ":root{" + variables + "}" + severity_rules + _STATIC


_STATIC = """
html, body, [class*="css"], .stApp { font-family: var(--ts-sans); }
.stApp { background: var(--ts-bg); color: var(--ts-text); }
[data-testid="stHeader"] { background: transparent; }
footer, #MainMenu { visibility: hidden; }
.block-container { max-width: 1440px; padding: 1.4rem 2rem 3rem; }
::selection { background: rgba(34,211,238,.30); }
a:focus-visible, button:focus-visible, [role="button"]:focus-visible, [tabindex]:focus-visible {
  outline: 2px solid var(--ts-accent) !important; outline-offset: 2px; }
* { scrollbar-width: thin; scrollbar-color: var(--ts-border) transparent; }

/* sidebar */
[data-testid="stSidebar"] { background: var(--ts-sidebar); border-right: 1px solid var(--ts-border); }
[data-testid="stSidebarNavLink"] { border-radius: 8px; color: var(--ts-muted); font-size: 14.5px; transition: background .15s; }
[data-testid="stSidebarNavLink"]:hover { background: rgba(34,211,238,.08); color: var(--ts-text); }
[data-testid="stSidebarNavLink"][aria-current="page"] { background: rgba(34,211,238,.14); color: var(--ts-text); font-weight: 600; }

/* header */
.ts-title { font-size: 1.5rem; font-weight: 700; letter-spacing: -.01em; margin: 0; line-height: 1.25; }
.ts-desc { color: var(--ts-muted); font-size: .92rem; margin: .2rem 0 1.1rem; }
.ts-status { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: flex-end; }
.ts-pill { display: inline-flex; align-items: center; gap: 7px; padding: 4px 11px; border-radius: 999px;
  border: 1px solid var(--ts-border); background: var(--ts-panel); font-size: 12.5px; white-space: nowrap; }
.ts-pill i { width: 8px; height: 8px; border-radius: 50%; background: var(--ts-faint); display: inline-block; }
.ts-pill.ok i { background: var(--ts-ok); }
.ts-pill.bad i { background: var(--ts-bad); }
.ts-updated { color: var(--ts-muted); font-size: 12.5px; text-align: right; margin-top: 6px; }
.stButton > button { background: var(--ts-panel); border: 1px solid var(--ts-border); color: var(--ts-text);
  border-radius: 8px; font-size: 13.5px; transition: border-color .15s, background .15s; }
.stButton > button:hover { border-color: var(--ts-accent); background: var(--ts-panel-hover); color: var(--ts-text); }
.stButton > button:active { background: rgba(34,211,238,.14); }
.stButton > button:disabled { opacity: .5; }

/* panels and KPI cards */
[class*="st-key-panel-"] { background: var(--ts-panel); border: 1px solid var(--ts-border); border-radius: 10px;
  padding: 16px 18px 22px; }
[class*="st-key-panel-"] [data-testid="stElementContainer"] { max-width: 100%; }   /* Streamlit sizes elements from the padded width */
[class*="st-key-panel-"] [data-testid="stPlotlyChart"] { max-width: 100%; overflow: hidden; }
.ts-kpi { background: var(--ts-panel); border: 1px solid var(--ts-border); border-radius: 10px; padding: 15px 18px 14px; height: 100%; }
.ts-kpi-label { display: flex; align-items: center; gap: 8px; color: var(--ts-muted); font-size: 13px; }
.ts-kpi-label i { width: 8px; height: 8px; border-radius: 50%; background: var(--c, var(--ts-accent)); }
.ts-kpi-value { font-size: 1.9rem; font-weight: 700; line-height: 1.15; margin: 6px 0 2px; font-variant-numeric: tabular-nums; }
.ts-kpi-value.lit { color: var(--c); }   /* only when a severity count is above zero */
.ts-kpi-context { color: var(--ts-muted); font-size: 12.5px; }
.ts-panel-title { font-size: 15px; font-weight: 600; margin: 0; }
.ts-panel-sub { color: var(--ts-muted); font-size: 12.5px; margin: 2px 0 8px; }
.ts-center { text-align: center; }
.ts-note { color: var(--ts-muted); font-size: 12px; margin: 10px 0 2px; line-height: 1.4; }

/* tables */
.ts-table-wrap { overflow-x: auto; }
.ts-table { width: 100%; border-collapse: collapse; font-size: 13.5px; border: 0 !important; }
.ts-table th, .ts-table td { border-left: 0 !important; border-right: 0 !important; background: transparent; }
.ts-table th { text-align: left; color: var(--ts-muted); font-weight: 600; font-size: 12.5px; padding: 6px 10px 8px;
  border-top: 0 !important; border-bottom: 1px solid var(--ts-border) !important; white-space: nowrap; }
.ts-table td { padding: 9px 10px; border-top: 0 !important; border-bottom: 1px solid var(--ts-border) !important; vertical-align: top; }
.ts-table tr:last-child td { border-bottom: 0 !important; }
.ts-table tbody tr:hover td { background: var(--ts-panel-hover) !important; }
.ts-table .num { text-align: right; font-variant-numeric: tabular-nums; }
.ts-table th.num { text-align: right; }
.ts-mono { font-family: var(--ts-mono); font-size: 12.5px; overflow-wrap: anywhere; }
.ts-nowrap { white-space: nowrap; }
.ts-muted { color: var(--ts-muted); }
.ts-badge { display: inline-flex; align-items: center; padding: 1px 9px; border-radius: 999px; font-size: 12px; font-weight: 600;
  color: var(--c); background: color-mix(in srgb, var(--c) 15%, transparent);
  border: 1px solid color-mix(in srgb, var(--c) 40%, transparent); white-space: nowrap; }

.ts-dl { margin: 0; display: grid; gap: 0; }
.ts-dl-row { display: grid; grid-template-columns: 11rem 1fr; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--ts-border); }
.ts-dl-row:last-child { border-bottom: 0; }
.ts-dl dt { color: var(--ts-muted); font-size: 13px; margin: 0; }
.ts-dl dd { margin: 0; font-size: 13.5px; min-width: 0; overflow-wrap: anywhere; }
@media (max-width: 760px) { .ts-dl-row { grid-template-columns: 1fr; gap: 2px; } }

.ts-tag { display: inline-block; padding: 0 8px; border-radius: 6px; font-size: 11.5px; color: var(--ts-accent);
  border: 1px solid color-mix(in srgb, var(--ts-accent) 45%, transparent); margin-left: 4px; white-space: nowrap; }

/* states */
.ts-state { display: flex; gap: 14px; align-items: flex-start; padding: 18px 4px; }
.ts-state svg { flex: none; width: 22px; height: 22px; margin-top: 2px; }
.ts-state-title { font-weight: 600; font-size: 14.5px; margin: 0 0 3px; }
.ts-state-text { color: var(--ts-muted); font-size: 13.5px; margin: 0; max-width: 62ch; }
.ts-state.error .ts-state-title { color: var(--ts-bad); }
.ts-skeleton { background: var(--ts-panel); border: 1px solid var(--ts-border); border-radius: 10px; height: 92px;
  animation: ts-pulse 1.3s ease-in-out infinite; }
@keyframes ts-pulse { 0%,100% { opacity: .55; } 50% { opacity: 1; } }
@media (prefers-reduced-motion: reduce) { .ts-skeleton { animation: none; } * { transition: none !important; } }
@media (max-width: 760px) { .block-container { padding: 4rem 1rem 2rem; } .ts-status { justify-content: flex-start; } .ts-updated { text-align: left; } }
"""
