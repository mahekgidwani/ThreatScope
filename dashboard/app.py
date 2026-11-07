"""ThreatScope dashboard entry point. Run from this folder: `streamlit run app.py`.

Task 1 foundation only: it proves the Streamlit -> API client -> FastAPI path by showing /health.
The real pages (Overview, Events, ...) arrive in later tasks.
"""
from datetime import datetime, timezone

import streamlit as st
from pydantic import ValidationError

from ts_dashboard.api_client import ApiError, ThreatScopeApi
from ts_dashboard.config import load_settings

st.set_page_config(page_title="ThreatScope", layout="wide")


@st.cache_resource
def get_api() -> ThreatScopeApi:
    return ThreatScopeApi(load_settings())


st.title("ThreatScope")
try:
    api = get_api()
except ValidationError:
    st.error("Dashboard configuration is invalid. Check THREATSCOPE_API_URL and THREATSCOPE_TIMEOUT_SECONDS.")
    st.stop()

st.button("Refresh")  # any click reruns the script, which re-reads /health
try:
    health = api.health()
except ApiError as error:
    st.error(f"API unavailable: {error.user_message}")
    st.stop()

st.session_state["last_ok"] = datetime.now(timezone.utc)
(st.success if health.status == "ready" else st.warning)(
    f"API: {health.api.status}  |  Database: {health.database.status}"
    + (f" ({health.database.latency_ms:.1f} ms)" if health.database.latency_ms is not None else ""))
st.caption(f"Last successful check: {st.session_state['last_ok']:%Y-%m-%d %H:%M:%S} UTC")
