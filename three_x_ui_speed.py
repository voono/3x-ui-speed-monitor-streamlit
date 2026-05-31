#!/usr/bin/env python3
"""
Read current upload/download speed from a 3X-UI panel.

The script logs in with the documented /login endpoint, then samples
/panel/api/server/status twice and calculates speed from netTraffic totals.
This is usually more reliable than trusting any one instantaneous snapshot.

Example config file:
  {
    "base_url": "http://localhost:2053/randompath",
    "username": "admin",
    "password": "your-password",
    "two_factor_code": "",
    "sample_seconds": 2
  }

Example:
  python3 three_x_ui_speed.py --config panel_credentials.json
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TrafficSnapshot:
    timestamp: float
    sent_bytes: int
    received_bytes: int
    reported_upload: int | None
    reported_download: int | None


class ThreeXUIError(RuntimeError):
    pass


class ThreeXUIAuthError(ThreeXUIError):
    pass


class ThreeXUIClient:
    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        timeout: float = 15.0,
        insecure: bool = False,
    ) -> None:
        base_url = base_url.rstrip("/")
        if base_url.endswith("/panel"):
            base_url = base_url[: -len("/panel")]
        self.base_url = base_url
        self.timeout = timeout
        self.bearer_token = bearer_token

        cookie_jar = http.cookiejar.CookieJar()
        handlers: list[urllib.request.BaseHandler] = [
            urllib.request.HTTPCookieProcessor(cookie_jar),
        ]
        if insecure:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=context))

        self.opener = urllib.request.build_opener(*handlers)

    def login(
        self,
        username: str,
        password: str,
        *,
        two_factor_code: str = "",
    ) -> None:
        payload = urllib.parse.urlencode(
            {
                "username": username,
                "password": password,
                "twoFactorCode": two_factor_code,
            }
        ).encode()

        data = self._request_json(
            "POST",
            "/login",
            body=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if not data.get("success"):
            raise ThreeXUIError(f"Login failed: {data.get('msg') or data}")

    def get_status(self) -> dict[str, Any]:
        data = self._request_json("GET", "/panel/api/server/status")
        if not data.get("success"):
            message = str(data.get("msg") or data)
            if _looks_like_auth_error(message):
                raise ThreeXUIAuthError(f"Session expired or unauthorized: {message}")
            raise ThreeXUIError(f"Status request failed: {message}")

        obj = data.get("obj")
        if not isinstance(obj, dict):
            raise ThreeXUIError(f"Unexpected status payload: {data}")

        return obj

    def traffic_snapshot(self) -> TrafficSnapshot:
        status = self.get_status()
        net_traffic = status.get("netTraffic") or {}
        net_io = status.get("netIO") or {}

        return TrafficSnapshot(
            timestamp=time.monotonic(),
            sent_bytes=int(net_traffic.get("sent") or 0),
            received_bytes=int(net_traffic.get("recv") or 0),
            reported_upload=_optional_int(net_io.get("up")),
            reported_download=_optional_int(net_io.get("down")),
        )

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        request_headers = {"Accept": "application/json", **(headers or {})}
        if self.bearer_token:
            request_headers["Authorization"] = f"Bearer {self.bearer_token}"

        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers=request_headers,
            method=method,
        )

        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            redirect = exc.headers.get("Location")
            location = f" Location: {redirect}" if redirect else ""
            if exc.code in (401, 403) or (
                exc.code == 404 and path == "/panel/api/server/status"
            ):
                raise ThreeXUIAuthError(
                    f"HTTP {exc.code} from {path}:{location} {detail}"
                ) from exc
            raise ThreeXUIError(
                f"HTTP {exc.code} from {path}:{location} {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ThreeXUIError(f"Connection error calling {path}: {exc.reason}") from exc

        try:
            parsed = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            text = raw.decode("utf-8", errors="replace")
            if _looks_like_auth_error(text):
                raise ThreeXUIAuthError(f"Session expired or unauthorized: {text}")
            raise ThreeXUIError(f"Non-JSON response from {path}: {text}") from exc

        if not isinstance(parsed, dict):
            raise ThreeXUIError(f"Unexpected JSON response from {path}: {parsed}")
        return parsed


def calculate_speed(first: TrafficSnapshot, second: TrafficSnapshot) -> tuple[float, float]:
    elapsed = max(second.timestamp - first.timestamp, 0.001)
    upload_bps = max(second.sent_bytes - first.sent_bytes, 0) / elapsed
    download_bps = max(second.received_bytes - first.received_bytes, 0) / elapsed
    return upload_bps, download_bps


def choose_speed(
    calculated_bps: float,
    reported_bps: int | None,
) -> tuple[float, str]:
    if reported_bps and reported_bps > 0:
        return float(reported_bps), "panel_net_io"
    if calculated_bps > 0:
        return calculated_bps, "traffic_delta"
    return calculated_bps, "traffic_delta"


def _looks_like_auth_error(text: str) -> bool:
    text = text.lower()
    auth_markers = (
        "unauthorized",
        "forbidden",
        "login",
        "session",
        "cookie",
        "permission",
    )
    return any(marker in text for marker in auth_markers)


def format_rate(bytes_per_second: float) -> str:
    units = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"]
    value = float(bytes_per_second)
    for unit in units:
        if abs(value) < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TiB/s"


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Get upload/download speed from a 3X-UI panel."
    )
    parser.add_argument(
        "--config",
        help="JSON file containing panel credentials and options.",
    )
    parser.add_argument(
        "--base-url",
        help="Panel base URL, including any web base path, e.g. http://host:2053/randompath",
    )
    parser.add_argument("--username", help="3X-UI username.")
    parser.add_argument("--password", help="3X-UI password.")
    parser.add_argument(
        "--two-factor-code",
        help="Optional 2FA code if enabled.",
    )
    parser.add_argument(
        "--bearer-token",
        help="Optional bearer token if your deployment uses token auth.",
    )
    parser.add_argument(
        "--sample-seconds",
        type=float,
        help="Seconds between traffic samples. Default: 2.0",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        help="HTTP timeout in seconds. Default: 15.0",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        default=None,
        help="Disable HTTPS certificate verification for self-signed panels.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        default=None,
        help="Print machine-readable JSON instead of text.",
    )
    return parser.parse_args()


def load_config(path: str | None) -> dict[str, Any]:
    if not path:
        return {}

    try:
        with open(path, "r", encoding="utf-8") as config_file:
            config = json.load(config_file)
    except OSError as exc:
        raise ThreeXUIError(f"Could not read config file {path!r}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ThreeXUIError(f"Invalid JSON in config file {path!r}: {exc}") from exc

    if not isinstance(config, dict):
        raise ThreeXUIError("Config file must contain a JSON object.")

    return config


def setting(
    args: argparse.Namespace,
    config: dict[str, Any],
    name: str,
    default: Any = None,
) -> Any:
    value = getattr(args, name)
    if value is not None:
        return value
    return config.get(name, default)


def build_client(config: dict[str, Any]) -> ThreeXUIClient:
    base_url = config.get("base_url")
    bearer_token = config.get("bearer_token")
    timeout = float(config.get("timeout", 15.0))
    insecure = bool(config.get("insecure", False))

    if not base_url:
        raise ThreeXUIError("Missing base_url.")

    return ThreeXUIClient(
        base_url,
        bearer_token=bearer_token,
        timeout=timeout,
        insecure=insecure,
    )


def login_client(client: ThreeXUIClient, config: dict[str, Any]) -> None:
    username = config.get("username")
    password = config.get("password")
    two_factor_code = config.get("two_factor_code", "")
    bearer_token = config.get("bearer_token")

    if not bearer_token and (not username or not password):
        raise ThreeXUIError("Provide username and password, or provide bearer_token.")

    if username and password:
        client.login(
            username,
            password,
            two_factor_code=two_factor_code,
        )


def get_speed_with_client(
    client: ThreeXUIClient,
    *,
    sample_seconds: float = 2.0,
) -> dict[str, Any]:
    first = client.traffic_snapshot()
    time.sleep(max(sample_seconds, 0.1))
    second = client.traffic_snapshot()
    upload_bps, download_bps = calculate_speed(first, second)
    upload_bps, upload_source = choose_speed(upload_bps, second.reported_upload)
    download_bps, download_source = choose_speed(download_bps, second.reported_download)

    return {
        "upload_bytes_per_second": upload_bps,
        "download_bytes_per_second": download_bps,
        "upload": format_rate(upload_bps),
        "download": format_rate(download_bps),
        "speed_source": {
            "upload": upload_source,
            "download": download_source,
        },
        "panel_reported_net_io": {
            "upload_bytes": second.reported_upload,
            "download_bytes": second.reported_download,
        },
    }


def get_speed(config: dict[str, Any]) -> dict[str, Any]:
    sample_seconds = float(config.get("sample_seconds", 2.0))
    client = build_client(config)
    login_client(client, config)
    return get_speed_with_client(client, sample_seconds=sample_seconds)


def main() -> int:
    args = parse_args()

    try:
        config = load_config(args.config)
    except ThreeXUIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    speed_config = {
        "base_url": setting(args, config, "base_url"),
        "username": setting(args, config, "username"),
        "password": setting(args, config, "password"),
        "two_factor_code": setting(args, config, "two_factor_code", ""),
        "bearer_token": setting(args, config, "bearer_token"),
        "sample_seconds": setting(args, config, "sample_seconds", 2.0),
        "timeout": setting(args, config, "timeout", 15.0),
        "insecure": setting(args, config, "insecure", False),
    }
    json_output = bool(setting(args, config, "json", False))

    try:
        result = get_speed(speed_config)
    except ThreeXUIError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if json_output:
        print(json.dumps(result, indent=2))
    else:
        print(f"Upload:   {result['upload']}")
        print(f"Download: {result['download']}")
        net_io = result["panel_reported_net_io"]
        if net_io["upload_bytes"] is not None or net_io["download_bytes"] is not None:
            print(
                "Panel netIO snapshot: "
                f"up={format_rate(net_io['upload_bytes'] or 0)}, "
                f"down={format_rate(net_io['download_bytes'] or 0)}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
