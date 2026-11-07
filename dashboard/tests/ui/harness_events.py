"""AppTest entry for the Events page alone (the real app routes pages through st.navigation, which AppTest cannot drive)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st  # noqa: E402

from ts_dashboard.theme import css  # noqa: E402
from views import events  # noqa: E402

st.markdown(f"<style>{css()}</style>", unsafe_allow_html=True)
events.render()
