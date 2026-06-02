"""Tests for Portkey check-key orchestration."""

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
    assert "wait about 30 seconds" in captured.out
