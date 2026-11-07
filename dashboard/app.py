"""ThreatScope dashboard entry point. Run from this folder: `streamlit run app.py`.

Streamlit runs this file first on every page view; it sets up the theme and the sidebar navigation.
"""
import streamlit as st

from ts_dashboard.theme import css
from views import events, overview, placeholders, status

st.set_page_config(page_title="ThreatScope", page_icon=":material/shield:", layout="wide", initial_sidebar_state="auto")
st.markdown(f"<style>{css()}</style>", unsafe_allow_html=True)
st.logo("assets/logo.svg", size="large")

navigation = st.navigation([
    st.Page(overview.render, title="Overview", icon=":material/dashboard:", url_path="overview", default=True),
    st.Page(events.render, title="Events", icon=":material/list_alt:", url_path="events"),
    st.Page(placeholders.indicators, title="Indicators", icon=":material/fingerprint:", url_path="indicators"),
    st.Page(placeholders.correlation, title="Correlation", icon=":material/hub:", url_path="correlation"),
    st.Page(placeholders.incidents, title="Incidents", icon=":material/crisis_alert:", url_path="incidents"),
    st.Page(placeholders.reports, title="Reports", icon=":material/summarize:", url_path="reports"),
    st.Page(status.render, title="System status", icon=":material/monitor_heart:", url_path="status"),
])
navigation.run()
