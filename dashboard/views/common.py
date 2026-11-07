"""Shared by every page: the API client and the page header."""
from datetime import datetime, timezone

import streamlit as st
from pydantic import ValidationError

from ts_dashboard import components
from ts_dashboard.api_client import ApiError, ThreatScopeApi
from ts_dashboard.config import load_settings
from ts_dashboard.models import Health


@st.cache_resource
def _client() -> ThreatScopeApi:
    return ThreatScopeApi(load_settings())


def require_api() -> ThreatScopeApi:
    """The client, or a configuration error on screen and the page stopped."""
    try:
        return _client()
    except ValidationError:
        st.markdown(components.error_state(
            "Dashboard configuration is invalid",
            "Check THREATSCOPE_API_URL (http://host:port, no path or credentials) and THREATSCOPE_TIMEOUT_SECONDS."),
            unsafe_allow_html=True)
        st.stop()


def read_health(api: ThreatScopeApi) -> Health | None:
    """None when the API cannot be reached (the page shows 'API unavailable', never old data)."""
    try:
        return api.health()
    except ApiError:
        return None


def page_header(title: str, description: str, api: ThreatScopeApi) -> Health | None:
    health = read_health(api)
    left, middle, right = st.columns([5, 4, 1.4], vertical_alignment="center")
    left.markdown(components.page_title(title, description), unsafe_allow_html=True)
    middle.markdown(
        f'<div class="ts-status">{components.health_pills(health)}</div>'
        f'<div class="ts-updated">Updated {datetime.now(timezone.utc):%H:%M:%S} UTC</div>', unsafe_allow_html=True)
    right.button("Refresh", icon=":material/refresh:", key=f"refresh-{title}", use_container_width=True)
    return health
