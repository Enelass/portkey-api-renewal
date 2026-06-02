"""Tests for Portkey API helper behavior."""

from datetime import datetime, timezone
from types import SimpleNamespace

from portkey_key_updater import portkey_api


def _key(value, status="active", created_at="2026-06-01T00:00:00.000Z", expires_at=None):
    return {
        "key": value,
        "status": status,
        "created_at": created_at,
        "expires_at": expires_at,
    }


def test_select_latest_active_unexpired_key_uses_created_at():
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    keys = [
        _key("pk-old", created_at="2026-05-30T00:00:00.000Z"),
        _key("pk-new", created_at="2026-06-01T00:00:00.000Z"),
    ]

    assert portkey_api.select_latest_active_key(keys, now=now)["key"] == "pk-new"


def test_select_latest_active_key_ignores_expired_and_inactive_keys():
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)
    keys = [
        _key("pk-revoked", status="revoked", created_at="2026-06-03T00:00:00.000Z"),
        _key("pk-expired", created_at="2026-06-02T00:00:00.000Z", expires_at="2026-06-01T00:00:00.000Z"),
        _key("pk-valid", created_at="2026-05-31T00:00:00.000Z", expires_at="2026-06-03T00:00:00.000Z"),
    ]

    assert portkey_api.select_latest_active_key(keys, now=now)["key"] == "pk-valid"


def test_select_latest_active_key_treats_null_expiry_as_unexpired():
    now = datetime(2026, 6, 2, tzinfo=timezone.utc)

    assert portkey_api.select_latest_active_key([_key("pk-no-expiry")], now=now)["key"] == "pk-no-expiry"


def test_select_latest_active_key_returns_none_for_empty_data():
    assert portkey_api.select_latest_active_key([]) is None


def test_create_api_key_sends_configured_portkey_payload(monkeypatch):
    calls = {}
    config = {
        "oauth": {
            "base_url": "https://portkey.example.com",
            "create_api_key_endpoint": "/albus/v2/api-keys/workspace/user",
            "key_name": "PortKey_NonProd",
            "key_description": "",
            "scopes": ["completions.write"],
            "organisation_id": "org-id",
            "workspace_id": "workspace-id",
            "key_type": "workspace",
            "expires_at": None,
            "defaults": {"config_id": None, "metadata": None},
            "rotation_policy": None,
        },
        "headers": {
            "content_type": "application/json",
            "accept": "application/json, text/plain, */*",
            "accept_language": "en-AU,en;q=0.9",
            "accept_encoding": "gzip, deflate, br",
            "connection": "keep-alive",
            "user_agent": "pytest",
        },
        "timeouts": {"api_request": 5},
    }

    def fake_post(url, json, headers, cookies, timeout):
        calls.update(url=url, json=json, headers=headers, cookies=cookies, timeout=timeout)
        return SimpleNamespace(status_code=201, json=lambda: {"id": "id", "key": "pk-created", "object": "api-key"})

    monkeypatch.setattr(portkey_api.requests, "post", fake_post)

    success, api_key, error = portkey_api.create_api_key(config, "token", {"token": {"value": "cookie-token"}})

    assert success is True
    assert api_key == "pk-created"
    assert error is None
    assert calls["url"] == "https://portkey.example.com/albus/v2/api-keys/workspace/user"
    assert calls["json"]["workspace_id"] == "workspace-id"
    assert calls["json"]["organisation_id"] == "org-id"
    assert calls["json"]["scopes"] == ["completions.write"]
    assert calls["headers"]["Authorization"] == "Bearer token"
    assert calls["cookies"] == {"token": "cookie-token"}
