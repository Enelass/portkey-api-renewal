# Architecture

The Portkey Key Updater is a small Python CLI toolkit for keeping a local API key synchronized with the latest usable key in a Portkey workspace.

## Flow

1. The user runs `portkey-check` or the legacy `check-key` alias.
2. `get_bearer.py` extracts the authenticated Portkey `token` cookie from the default browser.
3. `check_key.py` lists workspace keys with `GET /albus/v2/api-keys?workspace_id=...`.
4. `portkey_api.py` filters for keys where `status == "active"` and `expires_at` is missing/null or in the future.
5. If multiple keys are usable, the key with the newest `created_at` is selected.
6. If no usable key exists, `renew_key.py` creates one with `POST /albus/v2/api-keys/workspace/user`.
7. The selected or created key is synchronized to macOS Keychain as `PORTKEY_API_KEY`.
8. Environment analysis checks whether local shell and tool configuration already point at the active key.

## Modules

- `portkey_api.py`: Portkey request construction, key selection, expiry parsing, and create payload building.
- `check_key.py`: User-facing orchestration for check, forced renewal, Keychain sync, clipboard copy, and environment analysis.
- `renew_key.py`: User-facing creation flow for new keys.
- `get_bearer.py`: Browser-cookie extraction and token validation against the Portkey key list endpoint.
- `utils.py`: Shared config paths, browser detection, logging helpers, and Keychain service naming.

## Key Selection

Portkey can keep multiple keys active. The updater does not assume array order. It always filters to active unexpired records and then sorts by `created_at` descending. Forced renewal creates a new key without revoking existing keys.
