from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from three_x_ui_speed import ThreeXUIError, format_rate, get_speed
from xui_speed_store import (
    DB_FILE,
    init_db,
    latest_reading,
    panel_id,
    recent_readings,
    save_reading,
)


PANELS_FILE = Path(os.environ.get("PANELS_FILE", "panels.json"))
SETTINGS_FILE = Path(os.environ.get("SETTINGS_FILE", "app_settings.json"))
HASH_ITERATIONS = 390_000
COOKIE_NAME = "xui_speed_monitor_auth"
COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 30
DEFAULT_SITE_TITLE = "3X-UI Speed Monitor"
CHART_PERIODS = ["3h", "6h", "12h", "24h"]
DEFAULT_PUBLIC_DISPLAY = {
    "show_upload": True,
    "show_download": True,
    "show_limit_line": True,
}


def hide_page_navigation() -> None:
    st.markdown(
        """
        <style>
        [data-testid="stSidebarNav"] { display: none; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def hide_public_sidebar() -> None:
    st.markdown(
        """
        <style>
        [data-testid="stSidebar"],
        [data-testid="stSidebarCollapsedControl"] { display: none; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def load_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        st.error(f"Could not load {path}: {exc}")
        return default


def save_json_file(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_panels() -> list[dict[str, Any]]:
    panels = load_json_file(PANELS_FILE, [])
    if not isinstance(panels, list):
        st.error(f"{PANELS_FILE} must contain a JSON array.")
        return []
    return [panel for panel in panels if isinstance(panel, dict)]


def save_panels(panels: list[dict[str, Any]]) -> None:
    save_json_file(PANELS_FILE, panels)


def load_settings() -> dict[str, Any]:
    settings = load_json_file(SETTINGS_FILE, {})
    if not isinstance(settings, dict):
        return {}
    return settings


def get_site_title() -> str:
    if not SETTINGS_FILE.exists():
        return DEFAULT_SITE_TITLE

    try:
        settings = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return DEFAULT_SITE_TITLE

    if not isinstance(settings, dict):
        return DEFAULT_SITE_TITLE

    title = str(settings.get("site_title") or "").strip()
    return title or DEFAULT_SITE_TITLE


def get_public_display() -> dict[str, bool]:
    settings = load_settings()
    return {
        key: bool(settings.get(key, default))
        for key, default in DEFAULT_PUBLIC_DISPLAY.items()
    }


def save_settings(settings: dict[str, Any]) -> None:
    save_json_file(SETTINGS_FILE, settings)


def ensure_cookie_secret(settings: dict[str, Any]) -> dict[str, Any]:
    if not settings.get("cookie_secret"):
        settings["cookie_secret"] = secrets.token_hex(32)
        save_settings(settings)
    return settings


def hash_password(password: str, salt_hex: str | None = None) -> dict[str, Any]:
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        HASH_ITERATIONS,
    )
    return {
        "salt": salt.hex(),
        "hash": digest.hex(),
        "iterations": HASH_ITERATIONS,
    }


def verify_password(password: str, settings: dict[str, Any]) -> bool:
    expected_hash = settings.get("password_hash")
    salt = settings.get("password_salt")
    iterations = int(settings.get("password_iterations", HASH_ITERATIONS))
    if not expected_hash or not salt:
        return False

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        iterations,
    ).hex()
    return hmac.compare_digest(digest, expected_hash)


def sign_login_cookie(settings: dict[str, Any]) -> str:
    settings = ensure_cookie_secret(settings)
    nonce = secrets.token_hex(12)
    payload = f"{int(datetime.now().timestamp())}:{nonce}"
    signature = hmac.new(
        settings["cookie_secret"].encode("utf-8"),
        f"{payload}:{settings.get('password_hash', '')}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}:{signature}"


def verify_login_cookie(token: str | None, settings: dict[str, Any]) -> bool:
    if not token or not settings.get("cookie_secret"):
        return False

    parts = token.split(":")
    if len(parts) != 3:
        return False

    issued_at_text, nonce, signature = parts
    try:
        issued_at = int(issued_at_text)
    except ValueError:
        return False

    now = int(datetime.now().timestamp())
    if issued_at > now or now - issued_at > COOKIE_MAX_AGE_SECONDS:
        return False

    payload = f"{issued_at}:{nonce}"
    expected = hmac.new(
        settings["cookie_secret"].encode("utf-8"),
        f"{payload}:{settings.get('password_hash', '')}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


def set_login_cookie(token: str) -> None:
    cookie_value = (
        f"{COOKIE_NAME}={token}; Path=/; Max-Age={COOKIE_MAX_AGE_SECONDS}; SameSite=Lax"
    )
    components.html(
        f"<script>document.cookie = {json.dumps(cookie_value)};</script>",
        height=0,
        width=0,
    )


def clear_login_cookie() -> None:
    cookie_value = f"{COOKIE_NAME}=; Path=/; Max-Age=0; SameSite=Lax"
    components.html(
        f"<script>document.cookie = {json.dumps(cookie_value)};</script>",
        height=0,
        width=0,
    )


def require_login() -> bool:
    settings = load_settings()
    has_password = bool(settings.get("password_hash") and settings.get("password_salt"))

    if has_password:
        settings = ensure_cookie_secret(settings)

    cookie_token = st.context.cookies.get(COOKIE_NAME)
    if not st.session_state.get("authenticated") and verify_login_cookie(
        cookie_token,
        settings,
    ):
        st.session_state["authenticated"] = True

    if st.session_state.get("authenticated"):
        token_to_set = st.session_state.pop("auth_cookie_to_set", None)
        if token_to_set:
            set_login_cookie(token_to_set)
        with st.sidebar:
            if st.button("Lock", use_container_width=True):
                clear_login_cookie()
                st.session_state["authenticated"] = False
                st.info("Locked.")
                st.stop()
        return True

    st.title(get_site_title())

    if not has_password:
        st.subheader("Create Web Password")
        with st.form("create_password"):
            password = st.text_input("Password", type="password")
            confirm = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button("Create password")

        if submitted:
            if len(password) < 8:
                st.error("Use at least 8 characters.")
            elif password != confirm:
                st.error("Passwords do not match.")
            else:
                hashed = hash_password(password)
                settings.update(
                    {
                        "password_salt": hashed["salt"],
                        "password_hash": hashed["hash"],
                        "password_iterations": hashed["iterations"],
                        "cookie_secret": secrets.token_hex(32),
                    }
                )
                save_settings(settings)
                st.session_state["authenticated"] = True
                st.session_state["auth_cookie_to_set"] = sign_login_cookie(settings)
                st.rerun()
        return False

    with st.form("login"):
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Unlock")

    if submitted:
        if verify_password(password, settings):
            st.session_state["authenticated"] = True
            st.session_state["auth_cookie_to_set"] = sign_login_cookie(settings)
            st.rerun()
        else:
            st.error("Wrong password.")

    return False


def panel_config(panel: dict[str, Any]) -> dict[str, Any]:
    return {
        "base_url": panel.get("base_url", ""),
        "username": panel.get("username", ""),
        "password": panel.get("password", ""),
        "two_factor_code": panel.get("two_factor_code", ""),
        "bearer_token": panel.get("bearer_token", ""),
        "sample_seconds": panel.get("sample_seconds", 2.0),
        "timeout": panel.get("timeout", 15.0),
        "insecure": panel.get("insecure", False),
    }


def format_kib(value: float) -> float:
    return round(value / 1024, 2)


def format_mib(value: float) -> float:
    return round(value / (1024 * 1024), 3)


def high_usage_mibps(panel: dict[str, Any]) -> float:
    return max(float(panel.get("high_usage_mibps") or 0), 0.0)


def chart_period_selector(key: str) -> int:
    selected = st.segmented_control(
        "Chart period",
        options=CHART_PERIODS,
        default="6h",
        key=key,
    )
    return int((selected or "6h").removesuffix("h"))


def record_speed(panel: dict[str, Any]) -> None:
    checked_at = datetime.now().isoformat(timespec="seconds")

    try:
        data = get_speed(panel_config(panel))
    except ThreeXUIError as exc:
        save_reading(panel, checked_at, ok=False, error=str(exc), db_path=DB_FILE)
        return

    save_reading(panel, checked_at, ok=True, data=data, db_path=DB_FILE)


def add_panel_form(panels: list[dict[str, Any]]) -> None:
    with st.sidebar.expander("Add panel", expanded=not panels):
        with st.form("add_panel", clear_on_submit=True):
            name = st.text_input("Name")
            base_url = st.text_input("Base URL")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            two_factor_code = st.text_input("2FA code")
            bearer_token = st.text_input("Bearer token", type="password")
            high_usage = st.number_input(
                "High usage line (MiB/s)",
                min_value=0.0,
                max_value=100000.0,
                value=0.0,
                step=1.0,
            )
            insecure = st.checkbox("Allow invalid HTTPS certificate")
            submitted = st.form_submit_button("Save", use_container_width=True)

    if not submitted:
        return

    if not name.strip() or not base_url.strip():
        st.sidebar.error("Name and Base URL are required.")
        return

    panels.append(
        {
            "name": name.strip(),
            "base_url": base_url.strip(),
            "username": username.strip(),
            "password": password,
            "two_factor_code": two_factor_code.strip(),
            "bearer_token": bearer_token.strip(),
            "sample_seconds": 2.0,
            "timeout": 15.0,
            "high_usage_mibps": high_usage,
            "insecure": insecure,
        }
    )
    save_panels(panels)
    st.rerun()


def site_settings_form() -> None:
    display = get_public_display()
    with st.sidebar.expander("Site settings"):
        with st.form("site_settings"):
            title = st.text_input("Site title", value=get_site_title(), max_chars=100)
            st.caption("Public dashboard")
            show_upload = st.checkbox("Show upload", value=display["show_upload"])
            show_download = st.checkbox("Show download", value=display["show_download"])
            show_limit_line = st.checkbox(
                "Show high-usage line",
                value=display["show_limit_line"],
            )
            submitted = st.form_submit_button("Save", use_container_width=True)

    if not submitted:
        return

    title = title.strip()
    if not title:
        st.sidebar.error("Site title is required.")
        return

    settings = load_settings()
    settings["site_title"] = title
    settings["show_upload"] = show_upload
    settings["show_download"] = show_download
    settings["show_limit_line"] = show_limit_line
    save_settings(settings)
    st.rerun()


def save_panel_editor(panel: dict[str, Any], index: int, panels: list[dict[str, Any]]) -> None:
    with st.expander("Settings"):
        panel["name"] = st.text_input("Name", value=panel.get("name", ""), key=f"name_{index}")
        panel["base_url"] = st.text_input(
            "Base URL",
            value=panel.get("base_url", ""),
            key=f"base_url_{index}",
        )
        panel["username"] = st.text_input(
            "Username",
            value=panel.get("username", ""),
            key=f"username_{index}",
        )
        panel["password"] = st.text_input(
            "Password",
            value=panel.get("password", ""),
            type="password",
            key=f"password_{index}",
        )
        panel["two_factor_code"] = st.text_input(
            "2FA code",
            value=panel.get("two_factor_code", ""),
            key=f"two_factor_code_{index}",
        )
        panel["bearer_token"] = st.text_input(
            "Bearer token",
            value=panel.get("bearer_token", ""),
            type="password",
            key=f"bearer_token_{index}",
        )

        col_a, col_b, col_c, col_d = st.columns(4)
        panel["sample_seconds"] = col_a.number_input(
            "Sample seconds",
            min_value=0.1,
            max_value=20.0,
            value=float(panel.get("sample_seconds", 2.0)),
            step=0.5,
            key=f"sample_seconds_{index}",
        )
        panel["timeout"] = col_b.number_input(
            "Timeout",
            min_value=1.0,
            max_value=60.0,
            value=float(panel.get("timeout", 15.0)),
            step=1.0,
            key=f"timeout_{index}",
        )
        panel["high_usage_mibps"] = col_c.number_input(
            "High line MiB/s",
            min_value=0.0,
            max_value=100000.0,
            value=high_usage_mibps(panel),
            step=1.0,
            key=f"high_usage_mibps_{index}",
        )
        panel["insecure"] = col_d.checkbox(
            "Invalid HTTPS OK",
            value=bool(panel.get("insecure", False)),
            key=f"insecure_{index}",
        )

        col_save, col_delete = st.columns(2)
        if col_save.button("Save", key=f"save_{index}", use_container_width=True):
            save_panels(panels)
            st.success("Saved.")
        if col_delete.button("Delete", key=f"delete_{index}", use_container_width=True):
            panels.pop(index)
            save_panels(panels)
            st.rerun()


def render_overuse_warning(
    latest: dict[str, Any] | None,
    panel: dict[str, Any],
    *,
    show_upload: bool,
    show_download: bool,
    show_limit_line: bool,
) -> None:
    threshold_mibps = high_usage_mibps(panel)
    if not latest or not latest["ok"] or threshold_mibps <= 0 or not show_limit_line:
        return

    threshold_bps = threshold_mibps * 1024 * 1024
    overuses: list[str] = []
    upload_bps = latest["upload_bps"] or 0
    download_bps = latest["download_bps"] or 0

    if show_upload and upload_bps > threshold_bps:
        overuses.append(f"upload {format_rate(upload_bps)}")
    if show_download and download_bps > threshold_bps:
        overuses.append(f"download {format_rate(download_bps)}")

    if overuses:
        st.warning(
            "High usage: "
            + ", ".join(overuses)
            + f" over {threshold_mibps:g} MiB/s"
        )


def render_speed_chart(
    history: list[dict[str, Any]],
    panel: dict[str, Any],
    *,
    show_upload: bool,
    show_download: bool,
    show_limit_line: bool,
) -> None:
    visible_series: list[str] = []
    if show_upload:
        visible_series.append("upload MiB/s")
    if show_download:
        visible_series.append("download MiB/s")

    if not history:
        st.caption("No chart data for the selected period.")
        return

    threshold_mibps = high_usage_mibps(panel)
    if not visible_series and not (threshold_mibps > 0 and show_limit_line):
        st.caption("Chart hidden by public display settings.")
        return

    frame = pd.DataFrame(
        {
            "time": pd.to_datetime([row["checked_at"] for row in history]),
            "upload MiB/s": [format_mib(row["upload_bps"] or 0) for row in history],
            "download MiB/s": [
                format_mib(row["download_bps"] or 0) for row in history
            ],
        }
    )
    chart = None
    if visible_series:
        long_frame = frame.melt(
            id_vars=["time"],
            value_vars=visible_series,
            var_name="direction",
            value_name="MiB/s",
        )
        chart = (
            alt.Chart(long_frame)
            .mark_line()
            .encode(
                x=alt.X("time:T", title=None),
                y=alt.Y("MiB/s:Q", title="MiB/s"),
                color=alt.Color("direction:N", title=None),
            )
        )

    if threshold_mibps > 0 and show_limit_line:
        threshold = alt.Chart(pd.DataFrame({"threshold": [threshold_mibps]})).mark_rule(
            color="#d62728",
            strokeDash=[6, 4],
        ).encode(y="threshold:Q")
        chart = threshold if chart is None else chart + threshold
        st.caption(f"High usage line: {threshold_mibps:g} MiB/s")

    if chart is not None:
        st.altair_chart(chart.properties(height=260), use_container_width=True)


def render_panel_card(
    panel: dict[str, Any],
    index: int,
    panels: list[dict[str, Any]],
    *,
    admin: bool,
    chart_hours: int,
) -> None:
    pid = panel_id(panel)
    name = panel.get("name") or f"Panel {index + 1}"
    latest = latest_reading(panel, db_path=DB_FILE)
    history = recent_readings(panel, hours=chart_hours, db_path=DB_FILE)
    display = DEFAULT_PUBLIC_DISPLAY if admin else get_public_display()

    with st.container(border=True):
        if admin:
            header_left, header_right = st.columns([3, 1])
            header_left.subheader(name)
            if header_right.button("Refresh", key=f"refresh_{pid}", use_container_width=True):
                with st.spinner(f"Checking {name}..."):
                    record_speed(panel)
                st.rerun()
        else:
            st.subheader(name)

        if latest and latest["ok"]:
            metric_items: list[tuple[str, str]] = []
            if display["show_upload"]:
                metric_items.append(("Upload", format_rate(latest["upload_bps"] or 0)))
            if display["show_download"]:
                metric_items.append(("Download", format_rate(latest["download_bps"] or 0)))
            metric_items.append(("Checked", latest["checked_at"].split("T")[-1]))
            columns = st.columns(len(metric_items))
            for column, (label, value) in zip(columns, metric_items):
                column.metric(label, value)
        elif latest:
            st.error(latest["error"] if admin else "Data temporarily unavailable.")
        else:
            st.caption("No collected data yet.")

        render_overuse_warning(latest, panel, **display)
        render_speed_chart(history, panel, **display)

        if admin:
            save_panel_editor(panel, index, panels)


def render_dashboard(
    panels: list[dict[str, Any]],
    auto_refresh: bool,
    refresh_seconds: int,
    *,
    admin: bool,
    chart_hours: int,
) -> None:
    run_every = f"{refresh_seconds}s" if auto_refresh else None

    @st.fragment(run_every=run_every)
    def live_panels() -> None:
        for index, panel in enumerate(panels):
            render_panel_card(
                panel,
                index,
                panels,
                admin=admin,
                chart_hours=chart_hours,
            )

    live_panels()


def render_admin_page() -> None:
    hide_page_navigation()
    if not require_login():
        return

    init_db(DB_FILE)
    panels = load_panels()

    st.title(get_site_title())
    st.caption(f"{len(panels)} saved panel{'s' if len(panels) != 1 else ''}")
    chart_hours = chart_period_selector("admin_chart_period")

    site_settings_form()
    add_panel_form(panels)

    with st.sidebar:
        st.subheader("Dashboard")
        auto_refresh = st.toggle("Auto-refresh view", value=True)
        refresh_seconds = st.number_input(
            "Every seconds",
            min_value=5,
            max_value=300,
            value=30,
            step=5,
        )
        if st.button("Refresh all now", use_container_width=True):
            for panel in panels:
                with st.spinner(f"Checking {panel.get('name') or panel.get('base_url')}..."):
                    record_speed(panel)
            st.rerun()

    if not panels:
        st.info("Add a panel from the sidebar.")
        return

    render_dashboard(
        panels,
        auto_refresh,
        int(refresh_seconds),
        admin=True,
        chart_hours=chart_hours,
    )


def main() -> None:
    st.set_page_config(page_title=get_site_title(), layout="wide")
    hide_page_navigation()
    hide_public_sidebar()
    init_db(DB_FILE)
    panels = load_panels()

    st.title(get_site_title())
    st.caption("Live network usage")
    chart_hours = chart_period_selector("public_chart_period")

    if not panels:
        st.info("No panels available.")
        return

    render_dashboard(
        panels,
        auto_refresh=True,
        refresh_seconds=30,
        admin=False,
        chart_hours=chart_hours,
    )


if __name__ == "__main__":
    main()
