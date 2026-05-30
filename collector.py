#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from three_x_ui_speed import (
    ThreeXUIAuthError,
    ThreeXUIClient,
    ThreeXUIError,
    build_client,
    get_speed_with_client,
    login_client,
)
from xui_speed_store import DB_FILE, init_db, panel_id, save_reading


PANELS_FILE = Path("panels.json")


def load_panels(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    panels = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(panels, list):
        raise ValueError(f"{path} must contain a JSON array.")

    return [panel for panel in panels if isinstance(panel, dict)]


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


def config_signature(config: dict[str, Any]) -> str:
    return json.dumps(config, sort_keys=True, separators=(",", ":"))


class PanelSession:
    def __init__(self, panel: dict[str, Any]) -> None:
        self.panel = panel
        self.config = panel_config(panel)
        self.signature = config_signature(self.config)
        self.client: ThreeXUIClient | None = None
        self.logged_in = False

    def update_panel(self, panel: dict[str, Any]) -> None:
        config = panel_config(panel)
        signature = config_signature(config)
        self.panel = panel
        if signature != self.signature:
            self.config = config
            self.signature = signature
            self.client = None
            self.logged_in = False

    def ensure_client(self, *, force_login: bool = False) -> ThreeXUIClient:
        if self.client is None:
            self.client = build_client(self.config)
            self.logged_in = False

        if force_login:
            self.logged_in = False

        if not self.logged_in:
            login_client(self.client, self.config)
            self.logged_in = True

        return self.client

    def collect(self) -> dict[str, Any]:
        sample_seconds = float(self.config.get("sample_seconds", 2.0))

        try:
            client = self.ensure_client()
            return get_speed_with_client(client, sample_seconds=sample_seconds)
        except ThreeXUIAuthError:
            client = self.ensure_client(force_login=True)
            return get_speed_with_client(client, sample_seconds=sample_seconds)


def collect_once(
    panels_file: Path,
    db_file: Path,
    sessions: dict[str, PanelSession],
) -> None:
    panels = load_panels(panels_file)
    init_db(db_file)
    active_keys: set[str] = set()

    for panel in panels:
        key = panel_id(panel)
        active_keys.add(key)
        session = sessions.get(key)
        if session is None:
            session = PanelSession(panel)
            sessions[key] = session
        else:
            session.update_panel(panel)

        checked_at = datetime.now().isoformat(timespec="seconds")
        name = panel.get("name") or panel.get("base_url") or "Panel"
        try:
            data = session.collect()
        except ThreeXUIError as exc:
            save_reading(panel, checked_at, ok=False, error=str(exc), db_path=db_file)
            print(f"{checked_at} {name}: error: {exc}", flush=True)
            continue

        save_reading(panel, checked_at, ok=True, data=data, db_path=db_file)
        print(
            f"{checked_at} {name}: up={data['upload']} down={data['download']}",
            flush=True,
        )

    stale_keys = set(sessions) - active_keys
    for key in stale_keys:
        del sessions[key]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect 3X-UI panel speeds into SQLite for the Streamlit dashboard."
    )
    parser.add_argument(
        "--panels-file",
        type=Path,
        default=PANELS_FILE,
        help="Path to panels.json. Default: panels.json",
    )
    parser.add_argument(
        "--db-file",
        type=Path,
        default=DB_FILE,
        help="Path to SQLite history DB. Default: xui_speed_history.db",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=30.0,
        help="Seconds between collection runs. Default: 30",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Collect once and exit.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    sessions: dict[str, PanelSession] = {}

    while True:
        try:
            collect_once(args.panels_file, args.db_file, sessions)
        except Exception as exc:
            print(f"{datetime.now().isoformat(timespec='seconds')}: {exc}", flush=True)

        if args.once:
            return 0

        time.sleep(max(args.interval, 5.0))


if __name__ == "__main__":
    raise SystemExit(main())
