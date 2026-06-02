"""Regression tests for renew-key output safety."""

from portkey_key_updater import renew_key


def test_request_api_key_with_token_does_not_print_raw_key(monkeypatch, capsys):
    """Interactive renew output should not echo the full API key."""
    api_key = "pk-dP9loLkhXJRxcm_53teJDg"

    monkeypatch.setattr(
        renew_key,
        "load_config",
        lambda: {
            "oauth": {
                "base_url": "https://example.com",
                "create_api_key_endpoint": "/albus/v2/api-keys/workspace/user",
            }
        },
    )
    monkeypatch.setattr(renew_key, "create_api_key", lambda *args, **kwargs: (True, api_key, None))

    success, returned_key = renew_key.request_api_key_with_token(
        "token",
        {"token": {"value": "token"}},
        silent=False,
        no_logging=True,
    )

    captured = capsys.readouterr()

    assert success is True
    assert returned_key == api_key
    assert api_key not in captured.out
    assert api_key not in captured.err
    assert renew_key.obfuscate_key(api_key) in captured.out
