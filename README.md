# Portkey API Key Updater

[![macOS](https://img.shields.io/badge/macOS-Tested-green?style=flat-square)](https://www.apple.com/macos/)
[![zsh](https://img.shields.io/badge/zsh-Tested-blue?style=flat-square)](https://www.zsh.org/)
[![Python](https://img.shields.io/badge/Python-3.8--3.12-orange?style=flat-square)](https://www.python.org/)
[![Portkey](https://img.shields.io/badge/Portkey-Gateway-purple?style=flat-square)](https://portkey.ai/)
[![Tests](https://img.shields.io/github/actions/workflow/status/Enelass/portkey-api-renewal/changelog.yml?branch=main&label=checks&style=flat-square)](https://github.com/Enelass/portkey-api-renewal/actions/workflows/changelog.yml)
[![Release](https://img.shields.io/github/v/release/Enelass/portkey-api-renewal?style=flat-square)](https://github.com/Enelass/portkey-api-renewal/releases)

<p align="center">
  <img src="assets/Portkey_API_Logo.png" alt="Portkey API Key Updater Logo" width="160" />
</p>

Automate Portkey API key renewal on macOS. The tool reads your authenticated Portkey browser session, finds the newest active unexpired API key for a configured workspace, stores it in macOS Keychain, and creates a new key when no usable key exists.

## Quick Start

### 1. Install

```bash
git clone https://github.com/Enelass/portkey-api-renewal.git
cd portkey-api-renewal
uv venv && source .venv/bin/activate
uv pip install -e .
```

### 2. Configure

Copy the template and fill in your Portkey workspace details:

```bash
cp config/config.template.json config/config.json
```

Required values in `config/config.json`:

```json
{
  "oauth": {
    "base_url": "https://your-portkey-domain.com",
    "workspace_id": "your-workspace-id",
    "organisation_id": "your-organisation-id"
  }
}
```

The template also includes the key name, scopes, defaults, expiry policy, and Portkey endpoints used for listing and creating keys.

### 3. Store and expose the active key

Run the checker while logged in to Portkey in Chrome, Edge, Firefox, or Brave:

```bash
portkey-check
```

The active key is stored in Keychain as `PORTKEY_API_KEY`. Add shell exports as needed:

```bash
export PORTKEY_API_KEY=$(security find-generic-password -s "PORTKEY_API_KEY" -w)
```

## Commands

```bash
portkey-check              # Select newest active unexpired key, or create one if needed
portkey-check --renew      # Force creation of a new key
portkey-renew              # Create a new key interactively
portkey-get-bearer         # Validate browser bearer-token extraction
python3 main.py check      # Root dispatcher
```

Legacy aliases `check-key`, `renew-key`, and `get-bearer` remain available.

## Behavior

Portkey can keep multiple keys active. This tool always lists keys from `/albus/v2/api-keys?workspace_id=...`, ignores inactive or expired keys, and selects the active unexpired key with the newest `created_at`. If none exists, it creates a new key through `/albus/v2/api-keys/workspace/user`.

## Security Report

`portkey-check` runs a console environment verification after selecting the active key. To generate the HTML security report manually:

```bash
generate-report
python3 main.py report
```

The report is written to `logs/security_report.html`.

## Requirements

- macOS
- Python 3.8 through 3.12
- `uv` for the recommended local setup
- An active Portkey browser session in Chrome, Edge, Firefox, or Brave

Safari is not supported for automated cookie extraction.

## Troubleshooting

- `No bearer token found`: sign in to Portkey in a supported browser and rerun the command.
- `Portkey API key list failed`: verify `base_url`, `workspace_id`, and your browser session.
- Keychain prompts: allow Terminal access to macOS Keychain.
- Keep `config/config.json` private, for example `chmod 600 config/config.json`.

<p align="center">
  <img src="assets/Portkey_API_Banner.png" alt="Portkey API Key Updater Banner" />
</p>

## License

MIT License. See [LICENSE](LICENSE).
