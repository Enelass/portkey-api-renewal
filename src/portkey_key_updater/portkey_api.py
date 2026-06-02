"""Portkey API helpers for listing, selecting, and creating API keys."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlencode

import requests

from .utils import obfuscate_key


def _request_cookies(cookies: dict) -> dict:
    """Convert browser-cookie records to requests-compatible cookies."""
    return {name: data["value"] for name, data in cookies.items() if data.get("value")}


def _host_from_url(url: str) -> str:
    return url.replace("https://", "").replace("http://", "").split("/")[0]


def _url(config: dict, endpoint_key: str, query: dict | None = None) -> str:
    base_url = config["oauth"]["base_url"].rstrip("/")
    endpoint = config["oauth"][endpoint_key]
    url = f"{base_url}{endpoint}"
    if query:
        url = f"{url}?{urlencode(query)}"
    return url


def build_headers(config: dict, bearer_token: str, include_content_type: bool = False) -> dict:
    """Build browser-like Portkey headers from config."""
    headers = {
        "Host": _host_from_url(config["oauth"]["base_url"]),
        "Authorization": f"Bearer {bearer_token}",
        "Accept": config["headers"]["accept"],
        "Accept-Language": config["headers"]["accept_language"],
        "Accept-Encoding": config["headers"]["accept_encoding"],
        "Connection": config["headers"]["connection"],
        "User-Agent": config["headers"]["user_agent"],
    }
    if include_content_type:
        headers["Content-Type"] = config["headers"]["content_type"]
        headers["Origin"] = config["oauth"]["base_url"].rstrip("/")
    return headers


def parse_portkey_timestamp(value: str | None) -> datetime | None:
    """Parse Portkey ISO-8601 timestamps as timezone-aware UTC datetimes."""
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).astimezone(timezone.utc)


def is_active_unexpired_key(key_info: dict, now: datetime | None = None) -> bool:
    """Return whether a Portkey key record is active, unexpired, and contains a key."""
    now = now or datetime.now(timezone.utc)
    if key_info.get("status") != "active":
        return False
    if not key_info.get("key"):
        return False
    expires_at = parse_portkey_timestamp(key_info.get("expires_at"))
    return expires_at is None or expires_at > now


def select_latest_active_key(keys: list[dict], now: datetime | None = None) -> dict | None:
    """Select the newest active unexpired key by created_at."""
    candidates = [key for key in keys if is_active_unexpired_key(key, now=now)]
    if not candidates:
        return None
    return max(candidates, key=lambda key: parse_portkey_timestamp(key.get("created_at")) or datetime.min.replace(tzinfo=timezone.utc))


def list_api_keys(config: dict, bearer_token: str, cookies: dict) -> tuple[bool, list[dict], str | None]:
    """List Portkey API keys for the configured workspace."""
    workspace_id = config["oauth"]["workspace_id"]
    response = requests.get(
        _url(config, "list_api_keys_endpoint", {"workspace_id": workspace_id}),
        headers=build_headers(config, bearer_token),
        cookies=_request_cookies(cookies),
        timeout=config["timeouts"]["api_request"],
    )
    if response.status_code != 200:
        return False, [], f"HTTP {response.status_code}: {response.text[:500]}"
    data = response.json()
    keys = data.get("data", [])
    if not isinstance(keys, list):
        return False, [], "Portkey list response did not contain a data array"
    return True, keys, None


def build_create_payload(config: dict) -> dict:
    """Build the configured Portkey create-key payload."""
    oauth = config["oauth"]
    return {
        "name": oauth["key_name"],
        "description": oauth.get("key_description", ""),
        "scopes": oauth["scopes"],
        "organisation_id": oauth["organisation_id"],
        "workspace_id": oauth["workspace_id"],
        "type": oauth.get("key_type", "workspace"),
        "expires_at": oauth.get("expires_at"),
        "defaults": oauth.get("defaults", {"config_id": None, "metadata": None}),
        "rotation_policy": oauth.get("rotation_policy"),
    }


def create_api_key(config: dict, bearer_token: str, cookies: dict) -> tuple[bool, str | None, str | None]:
    """Create a Portkey API key and return its raw key value."""
    response = requests.post(
        _url(config, "create_api_key_endpoint"),
        json=build_create_payload(config),
        headers=build_headers(config, bearer_token, include_content_type=True),
        cookies=_request_cookies(cookies),
        timeout=config["timeouts"]["api_request"],
    )
    if response.status_code not in (200, 201):
        return False, None, f"HTTP {response.status_code}: {response.text[:500]}"
    data = response.json()
    api_key = data.get("key")
    if not api_key:
        return False, None, "Portkey create response did not contain a key"
    return True, api_key, None


def describe_key(key_info: dict) -> str:
    """Return a safe one-line description of a Portkey key record."""
    return f"{obfuscate_key(key_info.get('key'))} created_at={key_info.get('created_at')} expires_at={key_info.get('expires_at')}"
