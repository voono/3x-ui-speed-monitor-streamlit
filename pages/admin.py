import streamlit as st

from streamlit_app import render_admin_page


st.set_page_config(page_title="3X-UI Admin", layout="wide")
st.markdown(
    """
    <style>
    [data-testid="stSidebarNav"] { display: none; }
    </style>
    """,
    unsafe_allow_html=True,
)
render_admin_page()
