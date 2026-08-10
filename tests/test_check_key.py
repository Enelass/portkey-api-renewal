"""Tests for Portkey check-key orchestration."""

import pytest

from portkey_key_updater import check_key


def test_check_current_api_key_opens_browser_when_jwt_expired(monkeypatch, capsys):
    calls = {}
    config = {
        "oauth": {
            "base_url": "https://portkey.example.com",
            "list_api_keys_endpoint": "/albus/v2/api-keys",
            "workspace_id": "workspace-id",
        }
    }

    monkeypatch.setattr(check_key, "load_config", lambda: config)
    monkeypatch.setattr(check_key, "list_api_keys", lambda *args, **kwargs: (False, [], 'HTTP 401: {"message":"jwt expired"}'))
    monkeypatch.setattr(check_key, "open_browser", lambda url: calls.setdefault("url", url))

    success, api_key = check_key.check_current_api_key("expired-token", {}, return_key=True)
    captured = capsys.readouterr()

    assert success is False
    assert api_key is None
    assert calls["url"] == "https://portkey.example.com"
    assert "session token has expired" in captured.out
    assert "wait about 20 seconds" in captured.out


def test_extract_session_opens_supported_default_browser_when_no_cookies(monkeypatch, capsys):
    calls = {}
    config = {"oauth": {"base_url": "https://portkey.example.com"}}

    monkeypatch.setattr(
        check_key,
        "get_browser_info",
        lambda: {"bundle_id": "com.microsoft.edgemac", "name": "Microsoft Edge"},
    )
    monkeypatch.setattr(check_key, "get_browser_cookies_for_domain", lambda *args, **kwargs: {})
    monkeypatch.setattr(check_key, "open_browser", lambda url: calls.setdefault("url", url))

    with pytest.raises(SystemExit) as exc_info:
        check_key._extract_session_token_and_cookies(config)

    captured = capsys.readouterr()

    assert exc_info.value.code == 1
    assert calls["url"] == "https://portkey.example.com"
    assert "I opened Portkey in Microsoft Edge" in captured.out
    assert "wait about 20 seconds" in captured.out


def test_extract_session_does_not_open_unsupported_default_browser_when_no_cookies(monkeypatch, capsys):
    calls = {}
    config = {"oauth": {"base_url": "https://portkey.example.com"}}

    monkeypatch.setattr(
        check_key,
        "get_browser_info",
        lambda: {"bundle_id": "com.apple.safari", "name": "Safari"},
    )
    monkeypatch.setattr(check_key, "get_browser_cookies_for_domain", lambda *args, **kwargs: {})
    monkeypatch.setattr(check_key, "open_browser", lambda url: calls.setdefault("url", url))

    with pytest.raises(SystemExit) as exc_info:
        check_key._extract_session_token_and_cookies(config)

    captured = capsys.readouterr()

    assert exc_info.value.code == 1
    assert calls == {}
    assert "Safari is not supported for automated cookie extraction" in captured.out
    assert "Chrome, Edge, Firefox, or Brave" in captured.out
