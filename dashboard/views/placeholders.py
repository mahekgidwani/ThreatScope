"""Pages that arrive in later tasks. Each says so plainly instead of showing invented content."""
import streamlit as st

from ts_dashboard import components
from views.common import page_header, require_api


def _coming(title: str, description: str, task: int) -> None:
    api = require_api()
    page_header(title, description, api)
    with st.container(key="panel-soon"):
        st.markdown(components.empty_state(f"{title} is not built yet", f"This page is delivered in Phase 4, Task {task}."),
                    unsafe_allow_html=True)


def incidents() -> None:
    _coming("Incidents", "Group related events and track the investigation", 5)


def reports() -> None:
    _coming("Reports", "Summaries and CSV exports of stored data", 6)
