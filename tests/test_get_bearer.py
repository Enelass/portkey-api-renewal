"""Tests for browser bearer-token extraction."""

from portkey_key_updater.get_bearer import extract_bearer_token_from_cookies


def test_extract_bearer_token_accepts_portkey_auth_token_cookie():
    token, cookie_name = extract_bearer_token_from_cookies(
        {
            "auth_token": {"value": "Bearer%20jwt-value"},
            "refresh_token": {"value": "refresh"},
        }
    )

    assert token == "jwt-value"
    assert cookie_name == "auth_token"
