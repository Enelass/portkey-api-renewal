# Standalone Commands

These commands are installed by `uv pip install -e .`. Portkey-first names are preferred; legacy names remain available for compatibility.

## `portkey-check`

Finds the newest active unexpired Portkey key for the configured workspace. If none exists, it creates a new key and stores it in Keychain as `PORTKEY_API_KEY`.

```bash
portkey-check
portkey-check --renew
```

`--renew` always creates a new Portkey key. Existing Portkey keys are not revoked.

Legacy alias:

```bash
check-key
```

## `portkey-renew`

Creates a new Portkey key using the configured create payload.

```bash
portkey-renew
portkey-renew --silent
```

Legacy alias:

```bash
renew-key
```

## `portkey-get-bearer`

Extracts and validates the Portkey browser bearer token by listing workspace API keys.

```bash
portkey-get-bearer
```

Legacy alias:

```bash
get-bearer
```

## Root Dispatcher

The root `main.py` dispatcher is useful when running from source:

```bash
python3 main.py check
python3 main.py renew
python3 main.py bearer
python3 main.py analyse
python3 main.py sync
python3 main.py report
```

## Supporting Commands

- `analyse-env`: scans local shell, Keychain, and editor storage for managed API keys.
- `update-secretmgr`: synchronizes the active key into Keychain.
- `generate-report`: writes the HTML security report under `logs/`.
