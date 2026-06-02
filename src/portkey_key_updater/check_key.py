#!/usr/bin/env python3
"""Check the latest usable Portkey API key and renew when needed."""

import argparse
import os
import subprocess
import sys
from contextlib import redirect_stderr

from .get_bearer import extract_bearer_token_from_cookies, get_browser_cookies_for_domain
from .logger import log_end, log_error, log_info, log_start, log_success
from .portkey_api import describe_key, list_api_keys, select_latest_active_key
from .renew_key import copy_to_clipboard, request_api_key_with_token
from .utils import (
    Colors,
    build_subprocess_env,
    colored_print,
    get_browser_info,
    get_keychain_service_name,
    load_config,
    obfuscate_key,
    timestamp_print,
)


def update_keychain(api_key):
    """Synchronize the configured Keychain service with the active key."""
    service_name = get_keychain_service_name()
    try:
        keychain_result = subprocess.run(
            ["security", "find-generic-password", "-s", service_name, "-w"],
            capture_output=True,
            text=True,
            check=False,
        )
        keychain_key = keychain_result.stdout.strip() if keychain_result.returncode == 0 else None

        if keychain_key == api_key:
            return

        print("🔄 Keychain key differs from active key, updating...", file=sys.stderr)
        subprocess.run(
            ["security", "delete-generic-password", "-s", service_name],
            capture_output=True,
            check=False,
        )
        result = subprocess.run(
            [
                "security",
                "add-generic-password",
                "-s",
                service_name,
                "-a",
                os.getenv("USER", "user"),
                "-w",
                api_key,
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(f"🔐 Keychain synchronized with active API key ({service_name})", file=sys.stderr)
        else:
            print(f"⚠️  Failed to update keychain: {result.stderr.strip()}", file=sys.stderr)
    except Exception as keychain_error:
        print(f"⚠️  Keychain sync error: {keychain_error}", file=sys.stderr)


def check_current_api_key(final_token, cookies, return_key=False):
    """Return the newest active unexpired Portkey API key, creating one if needed."""
    config = load_config()

    list_url = (
        f"{config['oauth']['base_url'].rstrip('/')}"
        f"{config['oauth']['list_api_keys_endpoint']}?workspace_id={config['oauth']['workspace_id']}"
    )
    timestamp_print("[INFO] Checking Portkey API keys from: {}", Colors.CYAN, list_url)

    try:
        success, keys, error = list_api_keys(config, final_token, cookies)
    except Exception as exc:
        print(f"❌ Portkey API request error: {exc}", file=sys.stderr)
        if return_key:
            return False, None
        return False

    if not success:
        print(f"❌ Portkey API key list failed: {error}", file=sys.stderr)
        if return_key:
            return False, None
        return False

    latest_key = select_latest_active_key(keys)
    if latest_key:
        api_key = latest_key["key"]
        timestamp_print("[SUCCESS] Latest active Portkey key: {}", Colors.GREEN, describe_key(latest_key))
        log_success(f"Latest active Portkey API key retrieved: {obfuscate_key(api_key)}")
        if return_key:
            return True, api_key
        return True

    colored_print("[RENEW] No active unexpired Portkey key found; creating a new key...", Colors.YELLOW)
    log_info("No active unexpired Portkey key found; creating a new key")
    try:
        renewed, new_key = request_api_key_with_token(final_token, cookies, silent=True, no_logging=True)
    except Exception as exc:
        print(f"❌ Error during key renewal: {exc}", file=sys.stderr)
        if return_key:
            return False, None
        return False

    if renewed and new_key:
        print(f"✅ New Portkey API key generated: {obfuscate_key(new_key)}", file=sys.stderr)
        if return_key:
            return True, new_key
        return True

    print("❌ Failed to generate new Portkey API key", file=sys.stderr)
    if return_key:
        return False, None
    return False


def _extract_session_token_and_cookies(config):
    """Extract the browser token and cookies used for Portkey calls."""
    browser_info = get_browser_info()

    if not browser_info or not browser_info.get("bundle_id"):
        colored_print("[ERROR] Could not detect default browser", Colors.RED)
        log_error("Could not detect default browser")
        sys.exit(1)

    colored_print(
        f"[INFO] Default browser: {browser_info['name']} ({browser_info['bundle_id']})",
        Colors.CYAN,
    )
    log_info(f"Default browser: {browser_info['name']}", "utils.py")
    domain = config["oauth"]["base_url"].replace("https://", "").replace("http://", "").split("/")[0]
    colored_print(f"[INFO] Attempting to extract cookies for domain: {domain}", Colors.CYAN)

    with open(os.devnull, "w") as devnull:
        with redirect_stderr(devnull):
            cookies = get_browser_cookies_for_domain(browser_info["bundle_id"], domain)

    if not cookies:
        colored_print("[ERROR] No cookies found in browser session", Colors.RED)
        log_error("No cookies found in browser session")
        colored_print("[INFO] Please make sure you're logged in to Portkey in your browser", Colors.YELLOW)
        sys.exit(1)

    colored_print(f"[INFO] Found cookies: {', '.join(sorted(cookies))}", Colors.CYAN)
    token_value, token_cookie_name = extract_bearer_token_from_cookies(cookies)

    if not token_value:
        colored_print("[ERROR] No bearer token found in cookies", Colors.RED)
        log_error("No bearer token found in cookies")
        colored_print("[INFO] Expected one of: token, auth_token, access_token, id_token", Colors.YELLOW)
        colored_print("[INFO] Please make sure you're logged in and authenticated", Colors.YELLOW)
        sys.exit(1)

    timestamp_print(
        f"[SUCCESS] Found bearer token in {browser_info.get('name', 'browser')} cookie '{token_cookie_name}': {obfuscate_key(token_value)}",
        Colors.GREEN,
    )
    log_success(
        f"Found bearer token in {browser_info.get('name', 'browser')} cookie '{token_cookie_name}': {obfuscate_key(token_value)}",
        "get_bearer.py",
    )
    return token_value, cookies


def run_environment_analysis(current_api_key):
    """Run the existing environment analysis and optional keychain sync helper."""
    print("", file=sys.stderr)
    timestamp_print("[INFO] Cross-referencing with environment analysis...", Colors.CYAN)

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "portkey_key_updater.analyse_env",
                "--verify-key",
                current_api_key,
                "--no-logging",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            env=build_subprocess_env(),
        )

        if result.returncode == 0:
            log_success("Environment analysis completed", "analyse_env.py")

        if result.stdout.strip():
            print(result.stdout.strip())

        if "🔄 KEY UPDATE" in result.stdout:
            print("Attempting to synchronize environment with active key...", file=sys.stderr)
            sync_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "portkey_key_updater.update_secretmgr",
                    "--key",
                    current_api_key,
                    "--no-logging",
                ],
                capture_output=True,
                text=True,
                cwd=".",
                env=build_subprocess_env(),
            )
            if sync_result.returncode == 0:
                print("Environment synchronization completed successfully", file=sys.stderr)
            else:
                print(f"❌ Environment synchronization failed: {sync_result.stderr.strip()}", file=sys.stderr)

        if result.returncode != 0:
            print("⚠️  Environment analysis completed with warnings", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("⚠️  Environment analysis timed out", file=sys.stderr)
    except Exception as exc:
        print(f"⚠️  Could not run environment analysis: {exc}", file=sys.stderr)


def main():
    """Main function for standalone usage."""
    log_start()
    parser = argparse.ArgumentParser(
        description="Check the latest Portkey API key using bearer token from browser cookies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  portkey-check                       # Check latest active Portkey API key
  portkey-check --renew               # Force creation of a new Portkey API key
  check-key --renew                   # Legacy alias
        """,
    )

    parser.add_argument("--renew", action="store_true", help="Force creation of a new Portkey API key")

    args = parser.parse_args()
    log_info("Command line flag: --renew (forced renewal requested)" if args.renew else "Command line flag: none")

    colored_print("Portkey API Key Validation...", Colors.PURPLE + Colors.BOLD)
    print("")

    config = load_config()
    token_value, cookies = _extract_session_token_and_cookies(config)
    print("")

    if args.renew:
        timestamp_print("[FORCED] Creating new Portkey API key as requested...", Colors.YELLOW)
        success, current_api_key = request_api_key_with_token(token_value, cookies, silent=False, no_logging=True)
    else:
        success, current_api_key = check_current_api_key(token_value, cookies, return_key=True)

    if not success or not current_api_key:
        log_end()
        sys.exit(1)

    update_keychain(current_api_key)

    if copy_to_clipboard(current_api_key):
        print(f"✅ Active Portkey API key copied to clipboard: {obfuscate_key(current_api_key)}", file=sys.stderr)
    else:
        print(f"✅ Active Portkey API key found: {obfuscate_key(current_api_key)}", file=sys.stderr)
        print(f"📋 API Key: {current_api_key}")

    run_environment_analysis(current_api_key)

    log_end()
    sys.exit(0)


if __name__ == "__main__":
    main()


check_current_key_status = check_current_api_key
