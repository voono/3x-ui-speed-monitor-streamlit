import streamlit as st

from streamlit_app import get_site_title, render_admin_page


st.set_page_config(page_title=f"{get_site_title()} Admin", layout="wide")
st.markdown(
    """
    <style>
    [data-testid="stSidebarNav"] { display: none; }
    </style>
    """,
    unsafe_allow_html=True,
)
render_admin_page()
