"""AppTest entry for ONE page (the real app routes pages through st.navigation, which AppTest cannot drive).
The page module comes from the TS_PAGE environment variable, e.g. TS_PAGE=events."""
import importlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import streamlit as st  # noqa: E402

from ts_dashboard.theme import css  # noqa: E402

st.markdown(f"<style>{css()}</style>", unsafe_allow_html=True)
importlib.import_module(f"views.{os.environ['TS_PAGE']}").render()
