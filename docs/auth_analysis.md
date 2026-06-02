# Portkey Authentication Analysis

The updater uses the existing authenticated Portkey browser session. It does not ask the user for a password or store the browser bearer token as the API key.

## Session Extraction

`get_bearer.py` detects the default macOS browser and uses `browser_cookie3` to read cookies for the configured Portkey domain. Supported browsers are Chrome, Edge, Firefox, and Brave. Safari is not supported because of sandboxing restrictions.

The required cookie is named `token`. Its value is sent as:

```text
Authorization: Bearer <token>
```

## Token Validation

Bearer-token validation uses the same endpoint as normal key discovery:

```text
GET {base_url}/albus/v2/api-keys?workspace_id={workspace_id}
```

A `200` response with a JSON `data` array means the browser token can read workspace keys. Non-`200` responses are treated as authentication or permission failures and the tool asks the user to refresh their Portkey browser session.

## API Key Validity

The updater validates Portkey API keys from key metadata rather than probing a model or gateway endpoint. A key is usable when:

- `status` is `active`
- `key` is present
- `expires_at` is null, missing, or later than the current UTC time

When several keys match, the newest `created_at` wins. If no key matches, the tool creates a new key with the configured Portkey payload.

## Local Secret Storage

The active API key is stored in macOS Keychain under `PORTKEY_API_KEY`. Shell integrations should read that service instead of hardcoding the key:

```bash
export PORTKEY_API_KEY=$(security find-generic-password -s "PORTKEY_API_KEY" -w)
export OPENAI_API_KEY="$PORTKEY_API_KEY"
```
