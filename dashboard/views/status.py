"""System status page: what the dashboard can reach, read from /health."""
import streamlit as st

from ts_dashboard import components
from ts_dashboard.config import load_settings
from views.common import page_header, require_api, read_health


def render() -> None:
    api = require_api()
    page_header("System status", "Backend and database health as reported by the ThreatScope API", api)
    health = read_health(api)
    with st.container(key="panel-status"):
        st.markdown(components.panel_heading("Components", f"Read from {load_settings().threatscope_api_url}/health just now"),
                    unsafe_allow_html=True)
        if health is None:
            st.markdown(components.error_state(
                "ThreatScope API is unavailable",
                "The dashboard cannot reach the backend, so the database state is unknown. "
                "Start it with: docker compose up -d"), unsafe_allow_html=True)
            return
        db = health.database
        latency = f"{db.latency_ms:.1f} ms" if db.latency_ms is not None else "no measurement"
        rows = [
            [components.cell_text("API"), components.status_pill("Healthy", "ok"), components.cell_muted("process is up and answering")],
            [components.cell_text("PostgreSQL"),
             components.status_pill("Healthy" if db.status == "up" else "Unavailable", "ok" if db.status == "up" else "bad"),
             components.cell_muted(f"query latency {latency}" if db.status == "up" else "the API cannot reach the database")],
            [components.cell_text("Overall"), components.status_pill(health.status.replace("_", " "), "ok" if health.status == "ready" else "bad"),
             components.cell_muted("ready = the API can serve requests")],
        ]
        st.markdown(components.table([("Component", False), ("State", False), ("Detail", False)], rows), unsafe_allow_html=True)
