"""Plotly figures for the dashboard. All colours come from `theme`; all data comes from the caller."""
import plotly.graph_objects as go

from ts_dashboard.overview import Trend
from ts_dashboard.models import SEVERITIES
from ts_dashboard.theme import COLORS, FONT_SANS, SEVERITY_COLOURS, SEVERITY_LABELS, SOURCE_LABELS

CHART_CONFIG = {"displayModeBar": False}
HEIGHT = 270
_GRID = "rgba(100,116,139,0.18)"
BAR_PX = 26


def _base(fig: go.Figure, height: int = HEIGHT, top: int = 6) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=4, r=26, t=top, b=4), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT_SANS, color=COLORS["muted"], size=12), bargap=0.28,
        hoverlabel=dict(bgcolor=COLORS["panel_hover"], bordercolor=COLORS["border"], font=dict(color=COLORS["text"])),
    )
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor=_GRID, tickcolor=_GRID)
    fig.update_yaxes(gridcolor=_GRID, zeroline=False, linecolor="rgba(0,0,0,0)")
    return fig


def trend_figure(trend: Trend) -> go.Figure:
    hourly = trend.step.total_seconds() < 86400
    hover_time = "%d %b %H:%M UTC" if hourly else "%d %b %Y"
    fig = go.Figure()
    for severity in SEVERITIES[::-1]:  # critical at the bottom of each stack
        counts = trend.series[severity]
        if not any(counts):
            continue
        fig.add_bar(x=trend.starts, y=counts, name=SEVERITY_LABELS[severity], marker_color=SEVERITY_COLOURS[severity],
                    hovertemplate=f"{SEVERITY_LABELS[severity]}: %{{y}}<br>%{{x|{hover_time}}}<extra></extra>")
    fig.update_layout(barmode="stack", showlegend=True, legend=dict(orientation="h", y=1.02, yanchor="bottom", x=0, font=dict(size=12)))
    fig.update_xaxes(automargin=True)
    fig.update_yaxes(automargin=True, dtick=1 if max(sum(col) for col in zip(*trend.series.values())) <= 5 else None, rangemode="tozero")
    return _base(fig, top=30)


def _horizontal_bars(labels: list[str], values: list[int], colours: list[str], height: int) -> go.Figure:
    fig = go.Figure(go.Bar(
        x=values, y=labels, orientation="h", marker_color=colours, text=values, textposition="outside",
        textfont=dict(color=COLORS["text"]), cliponaxis=False, hovertemplate="%{y}: %{x}<extra></extra>"))
    fig.update_yaxes(autorange="reversed", showgrid=False, automargin=True, tickfont=dict(color=COLORS["text"]), ticksuffix="  ")
    fig.update_xaxes(visible=False, range=[0, max(values) * 1.3 or 1])
    fig = _base(fig, height)
    fig.update_layout(bargap=1 - BAR_PX * len(values) / (height - 10))   # same bar thickness in every panel
    return fig


def severity_figure(counts: dict[str, int]) -> go.Figure:
    order = SEVERITIES[::-1]  # critical first
    return _horizontal_bars([SEVERITY_LABELS[s] for s in order], [counts.get(s, 0) for s in order],
                            [SEVERITY_COLOURS[s] for s in order], HEIGHT)


def source_figure(counts: dict[str, int]) -> go.Figure:
    order = sorted(counts, key=lambda s: (-counts[s], s))
    return _horizontal_bars([SOURCE_LABELS.get(s, s) for s in order], [counts[s] for s in order],
                            [COLORS["accent_muted"]] * len(order), HEIGHT)
