#!/usr/bin/env python3
"""
Environment Analysis Tool for API Key Management
Identifies installed clients/CLI tools and finds API key declarations

This script:
1. Identifies which clients/CLI tools are installed and use API keys
2. Finds where API keys are declared (env vars, config files, etc.)
"""

import os
import re
import json
import subprocess
import sys
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime
from .logger import log_success, log_warning, log_error, log_info, log_start, log_end
from .utils import Colors, colored_print, get_security_report_path

def refresh_environment():
    """Refresh environment variables by sourcing shell config files"""
    try:
        # Get current shell
        current_shell = os.environ.get('SHELL', '/bin/bash')
        shell_name = os.path.basename(current_shell)
        
        # Determine config file based on shell
        home_dir = os.path.expanduser('~')
        if 'zsh' in shell_name:
            config_files = [f'{home_dir}/.zshrc', f'{home_dir}/.zprofile']
        elif 'bash' in shell_name:
            config_files = [f'{home_dir}/.bashrc', f'{home_dir}/.bash_profile', f'{home_dir}/.profile']
        elif 'fish' in shell_name:
            config_files = [f'{home_dir}/.config/fish/config.fish']
        else:
            config_files = [f'{home_dir}/.profile']
        
        # Find the first existing config file
        config_file = None
        for cf in config_files:
            if os.path.exists(cf):
                config_file = cf
                break
        
        if config_file:
            # Source the config file and capture updated environment
            cmd = f"source {config_file} && env"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, executable=current_shell)
            
            if result.returncode == 0:
                # Parse the environment output and update current process
                updated_count = 0
                for line in result.stdout.strip().split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key not in os.environ or os.environ[key] != value:
                            os.environ[key] = value
                            updated_count += 1
                
                if updated_count > 0:
                    colored_print(f"[ENV] Refreshed {updated_count} environment variables from {config_file}", Colors.INFO)
                return True
            else:
                colored_print(f"[ENV] Warning: Could not source {config_file}", Colors.WARNING)
                return False
        else:
            colored_print(f"[ENV] No shell config file found for {shell_name}", Colors.WARNING)
            return False
            
    except Exception as e:
        colored_print(f"[ENV] Error refreshing environment: {e}", Colors.WARNING)
        return False


def log_message(message, log_file=None):
    """Write message to both console and log file"""
    # Determine color based on message content
    if "[SUCCESS]" in message:
        colored_print(message, Colors.GREEN)
    elif "[ERROR]" in message or "❌" in message:
        colored_print(message, Colors.RED)
    elif "[WARNING]" in message:
        colored_print(message, Colors.YELLOW)
    elif "[INFO]" in message:
        colored_print(message, Colors.CYAN)
    elif "[KEYCHAIN]" in message:
        colored_print(message, Colors.PURPLE)
    elif "[SUMMARY]" in message:
        colored_print(message, Colors.PURPLE + Colors.BOLD)
    elif "[SECURITY]" in message:
        colored_print(message, Colors.RED)
    elif "[TARGET]" in message:
        colored_print(message, Colors.PURPLE + Colors.BOLD)
    elif "📦" in message or "🧩" in message or "🌍" in message:
        colored_print(message, Colors.CYAN)
    else:
        print(message)
    
    # File logging disabled - no file output
def check_command_exists(command):
    """Check if a command exists in PATH"""
    try:
        subprocess.run([command, '--version'], capture_output=True, timeout=5)
        return True
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        try:
            subprocess.run([command, '-v'], capture_output=True, timeout=5)
            return True
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
            try:
                subprocess.run(['which', command], capture_output=True, timeout=5)
                return True
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
                return False
    
def check_vscode_extension_installed(extension_id):
    """Check if a VSCode extension is installed using code CLI"""
    try:
        result = subprocess.run(['code', '--list-extensions'],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            installed_extensions = result.stdout.lower().split('\n')
            return extension_id.lower() in installed_extensions
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    return False
    
def get_vscode_extensions():
    """Get list of installed VSCode extensions from SQLite database"""
    extensions = []
    
    # Try CLI method first as fallback
    try:
        result = subprocess.run(['code', '--list-extensions'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            cli_extensions = [ext.strip() for ext in result.stdout.split('\n') if ext.strip()]
            extensions.extend(cli_extensions)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Query SQLite database for more comprehensive results
    import sqlite3
    import os
    
    vscode_db_path = os.path.expanduser("~/Library/Application Support/Code/User/globalStorage/state.vscode.sqlite")
    
    if os.path.exists(vscode_db_path):
        try:
            conn = sqlite3.connect(vscode_db_path)
            cursor = conn.cursor()
            
            # Query for extension information
            cursor.execute("SELECT key, value FROM ItemTable WHERE key LIKE '%extension%' OR key LIKE '%roo%' OR key LIKE '%cline%'")
            rows = cursor.fetchall()
            
            for key, value in rows:
                if 'roo' in key.lower() or 'roo' in str(value).lower():
                    if 'roo' not in [ext.lower() for ext in extensions]:
                        extensions.append('roo-code')
                if 'cline' in key.lower() or 'cline' in str(value).lower():
                    if 'cline' not in [ext.lower() for ext in extensions]:
                        extensions.append('cline')
            
            conn.close()
        except Exception as e:
            pass  # Silently continue if database access fails
    
    return extensions

def check_installed_clients(log_file=None):
    """Identify installed AI/API clients and CLI tools"""
    log_message(" Identifying Installed AI Clients & CLI Tools...", log_file)
    log_message("=" * 60, log_file)
    
    clients = {
        'Agentic AI CLI Tools': {
            'gemini': 'Gemini CLI',
            'claude': 'Claude CLI',
        }
    }
    
    installed_clients = {}
    
    # Build CLI tools line
    cli_found = []
    for category, tools in clients.items():
        installed_clients[category] = {}
        for command, description in tools.items():
            if check_command_exists(command):
                cli_found.append(f"{description} ({command})")
                installed_clients[category][command] = description
    
    # Build extensions line
    extensions = get_vscode_extensions()
    ai_extensions = []
    ext_found = []
    
    # Check for specific Agentic AI extensions based on storage detection
    ai_extension_patterns = [
        ('rooveterinaryinc.roo-cline', 'Roo-Cline'),
        ('saoudrizwan.claude-dev', 'Claude Dev'),
        ('kilocode.kilo-code', 'Kilo-Code'),
    ]
    
    for ext_id, ext_name in ai_extension_patterns:
        # Check if the extension is actually installed (using code CLI)
        installed = check_vscode_extension_installed(ext_id)
        if installed:
            ext_found.append(ext_name)
            ai_extensions.append((ext_id, ext_name))
    
    # Print compact 2-line format
    log_message(f"\n📦 Agentic AI CLI Tools: {', '.join(cli_found) if cli_found else 'None found'}", log_file)
    log_message(f"🧩 Agentic AI VSCode Extensions: {', '.join(ext_found) if ext_found else 'None found'}", log_file)
    
    installed_clients['VSCode Extensions'] = dict(ai_extensions)
    
    return installed_clients

def is_agentic_api_key(value):
    """Return whether a value looks like an agentic API key managed by this tool."""
    return isinstance(value, str) and (value.startswith('sk-') or value.startswith('pk-'))


def search_file_for_keys(file_path, patterns=None):
    """Search a single file for API keys."""
    if patterns is None:
        patterns = [
            r'sk-[A-Za-z0-9_\-]{20,}',  # OpenAI-compatible keys
            r'pk-[A-Za-z0-9_\-]{20,}',  # Portkey-style keys
            r'ghp_[A-Za-z0-9]{36}',  # GitHub Personal Access Token
        ]
    
    keys_found = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            for line_num, line in enumerate(lines, 1):
                for pattern in patterns:
                    matches = re.findall(pattern, line)
                    for match in matches:
                        # Filter out obvious non-keys
                        if len(match) >= 20 and not match.isdigit():
                            keys_found.append({
                                'key': match,
                                'location': str(file_path),
                                'line': line_num,
                                'context': line.strip(),
                                'type': 'file'
                            })
    except (IOError, OSError, PermissionError):
        pass
    return keys_found

def search_environment_variables(log_file=None):
    """Search environment variables for API keys."""
    log_message("🌍 Environment Variables:", log_file)
    keys_found = []
    
    # Focus on API key environment variable names that typically contain agentic API keys
    api_key_vars = [
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'CLAUDE_API_KEY', 'ANTHROPIC_AUTH_TOKEN',
        'GEMINI_API_KEY', 'GOOGLE_API_KEY', 'PORTKEY_API_KEY',
        'API_KEY', 'OPENAI_KEY', 'ANTHROPIC_KEY', 'CLAUDE_KEY',
    ]
    
    found_vars = []
    for var_name in api_key_vars:
        value = os.environ.get(var_name)
        if value and is_agentic_api_key(value):
            found_vars.append((var_name, value))
            keys_found.append({
                'key': value,
                'location': f'Environment variable: {var_name}',
                'type': 'environment',
                'var_name': var_name
            })
    
    if found_vars:
        for var_name, value in found_vars:
            log_message(f"  [SUCCESS] {var_name}: {obfuscate_key(value)}", log_file)
            log_success(f"Environment variable found: {var_name}: {obfuscate_key(value)}")
    else:
        log_message("  ❌ No managed API keys found in environment variables", log_file)
    
    return keys_found

def search_config_files(log_file=None):
    """Search common configuration files for API keys - only display if Agentic AI keys found"""
    keys_found = []
    home = Path.home()
    
    config_files = [
        # Shell configuration
        ('.bashrc', 'Bash configuration'),
        ('.bash_profile', 'Bash profile'),
        ('.zshrc', 'Zsh configuration'),
        ('.zsh_profile', 'Zsh profile'),
        ('.profile', 'Shell profile'),
        ('.env', 'Environment file'),
        
        # Application configs
        ('.openai/config', 'OpenAI CLI config'),
        ('.anthropic/config', 'Anthropic CLI config'),
        ('.config/gh/config.yml', 'GitHub CLI config'),
        ('.gitconfig', 'Git configuration'),
        
        # VSCode settings
        ('Library/Application Support/Code/User/settings.json', 'VSCode User Settings'),
        ('.vscode/settings.json', 'VSCode Workspace Settings'),
        
        # Project files
        ('.env.local', 'Local environment'),
        ('.env.development', 'Development environment'),
        ('.env.production', 'Production environment'),
        ('config/config.json', 'Generic config'),
        ('package.json', 'Node.js package config'),
    ]
    
    # First, collect all keys and check for Agentic AI keys
    agentic_ai_files = []
    for file_path, description in config_files:
        full_path = home / file_path
        if full_path.exists() and full_path.is_file():
            file_keys = search_file_for_keys(full_path)
            if file_keys:
                # Check if any keys are Agentic AI keys
                agentic_keys = [k for k in file_keys if is_agentic_api_key(k['key'])]
                if agentic_keys:
                    agentic_ai_files.append((description, file_path))
                    for key_info in file_keys:
                        key_info['description'] = description
                    keys_found.extend(file_keys)
    
    # Only show the section header if we found Agentic AI keys
    if agentic_ai_files:
        log_message("📄 Configuration Files:", log_file)
        for description, file_path in agentic_ai_files:
            log_message(f"  📄 Found keys in {description} ({file_path})", log_file)
    
    return keys_found

def search_vscode_storage(log_file=None):
    """Search VSCode extension storage for API keys via SQLite database"""
    log_message("🧩 VSCode Extension Storage:", log_file)
    keys_found = []
    home = Path.home()
    
    # Check the main VSCode SQLite database for extension API key storage
    vscode_db_path = home / "Library/Application Support/Code/User/globalStorage/state.vscdb"
    
    if vscode_db_path.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(str(vscode_db_path))
            cursor = conn.cursor()
            
            # Query for API key entries in extension storage
            cursor.execute("SELECT key FROM ItemTable WHERE key LIKE '%ApiKey%' OR key LIKE '%openAi%' OR key LIKE '%anthropic%' OR key LIKE '%claude%'")
            rows = cursor.fetchall()
            
            api_key_entries = []
            for row in rows:
                key = row[0]
                # Look for extension-specific API key patterns
                if any(ext in key for ext in ['rooveterinaryinc.roo-cline', 'saoudrizwan.claude-dev', 'kilocode.kilo-code']) and any(api in key.lower() for api in ['apikey', 'openai', 'anthropic', 'claude']):
                    api_key_entries.append(key)
            
            if api_key_entries:
                # Identify which extensions have API keys stored
                extensions_with_keys = set()
                for entry in api_key_entries:
                    if 'rooveterinaryinc.roo-cline' in entry:
                        extensions_with_keys.add('Roo-Cline')
                    elif 'saoudrizwan.claude-dev' in entry:
                        extensions_with_keys.add('Claude Dev')
                    elif 'kilocode.kilo-code' in entry:
                        extensions_with_keys.add('Kilo-Code')
                
                if extensions_with_keys:
                    log_message(f"  📄 API Key Storage found for: {', '.join(sorted(extensions_with_keys))} ({len(api_key_entries)} encrypted entries)", log_file)
                    keys_found.append({
                        'key': '[encrypted]',
                        'location': f'VSCode Extension Storage',
                        'type': 'extension_storage',
                        'extensions': list(extensions_with_keys),
                        'count': len(api_key_entries)
                    })
            else:
                log_message("  ❌ No extension API key storage found", log_file)
            
            conn.close()
        except Exception as e:
            log_message("  ❌ Could not access VSCode extension storage database", log_file)
    else:
        log_message("  ❌ VSCode storage database not found", log_file)
    
    return keys_found

def search_sqlite_database(db_path, log_file=None):
    """Search SQLite database for API keys"""
    keys_found = []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        for table in tables:
            table_name = table[0]
            try:
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                
                # Get column names
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [col[1] for col in cursor.fetchall()]
                
                for row in rows:
                    for i, value in enumerate(row):
                        if isinstance(value, str):
                            # Search for API key patterns
                            patterns = [
                                r'sk-[A-Za-z0-9_\-]{20,}',
                                r'pk-[A-Za-z0-9_\-]{20,}',
                                r'claude-[A-Za-z0-9_\-]{20,}',
                                r'gsk_[A-Za-z0-9_\-]{20,}',
                            ]
                            
                            for pattern in patterns:
                                matches = re.findall(pattern, value)
                                for match in matches:
                                    keys_found.append({
                                        'key': match,
                                        'location': f'SQLite DB: {db_path}',
                                        'table': table_name,
                                        'column': columns[i] if i < len(columns) else f'col_{i}',
                                        'type': 'database'
                                    })
            except sqlite3.Error:
                continue  # Skip tables we can't read
        
        conn.close()
    except (sqlite3.Error, OSError):
        pass
    
    return keys_found

def search_keychain(log_file=None):
    """Search macOS Keychain for API keys"""
    log_message("[KEYCHAIN] macOS Keychain:", log_file)
    keys_found = []
    
    # Common service names that might store API keys
    services_to_check = [
        'openai', 'anthropic', 'claude', 'gemini', 'portkey',
        'github', 'gitlab', 'aws', 'google', 'api-key',
        'roo', 'cline', 'continue', 'copilot',
        # Environment variable style service names
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'CLAUDE_API_KEY',
        'GEMINI_API_KEY', 'PORTKEY_API_KEY', 'GITHUB_TOKEN'
    ]
    
    found_services = []
    for service in services_to_check:
        try:
            result = subprocess.run([
                'security', 'find-generic-password', '-s', service, '-w'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                password = result.stdout.strip()
                if len(password) > 10:  # Reasonable minimum for API keys
                    found_services.append((service, password))
                    keys_found.append({
                        'key': password,
                        'location': f'macOS Keychain (service: {service})',
                        'type': 'keychain',
                        'service': service
                    })
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
    
    if found_services:
        for service, password in found_services:
            log_message(f"  [SUCCESS] '{service}': {obfuscate_key(password)}", log_file)
            log_success(f"Keychain service found: '{service}': {obfuscate_key(password)}")
    else:
        log_message("  ❌ No API keys found in keychain", log_file)
    
    return keys_found

def verify_api_key_in_environment(target_key, all_keys, log_file):
    """Verify if the provided API key matches what's found in the environment"""
    log_message("\n" + "=" * 60, log_file)
    log_message(" API Key Environment Verification", log_file)
    log_message("=" * 60, log_file)
    
    target_key_obfuscated = obfuscate_key(target_key)
    log_message(f"[TARGET] Target Key: {target_key_obfuscated}", log_file)
    
    # Find all managed API keys in the environment
    environment_keys = []
    for key_info in all_keys:
        key = key_info['key']
        if is_agentic_api_key(key) and key_info['type'] in ['keychain', 'environment', 'extension_storage']:
            environment_keys.append(key_info)
    
    if not environment_keys:
        log_message("❌ No managed API keys found in environment configuration", log_file)
        log_message("[WARNING]  This suggests the active key is not properly stored in secure locations", log_file)
        log_warning("Active key is not properly stored in secure locations")
        return
    
    # Check if target key matches any environment key
    matching_keys = []
    different_keys = []
    
    for key_info in environment_keys:
        if key_info['key'] == target_key:
            matching_keys.append(key_info)
        else:
            different_keys.append(key_info)
    
    if matching_keys:
        log_message(f"[SUCCESS] Active key matches environment configuration", log_file)
        log_success("Active key matches environment configuration")
        log_message(f" Found in {len(matching_keys)} location(s):", log_file)
        for match in matching_keys:
            location_desc = f"{match['type'].replace('_', ' ').title()}"
            if match.get('source'):
                location_desc += f" ({match['source']})"
            log_message(f"   • {location_desc}", log_file)
    else:
        log_message("[INFO] Active key differs from stored environment keys", log_file)
    
    if different_keys:
        if matching_keys:
            log_message(f"\n📋 Additional keys found in environment:", log_file)
        else:
            log_message(f"\n📋 Environment keys detected:", log_file)
        
        for key_info in different_keys:
            key_obfuscated = obfuscate_key(key_info['key'])
            location_desc = f"{key_info['type'].replace('_', ' ').title()}"
            if key_info.get('source'):
                location_desc += f" ({key_info['source']})"
            log_message(f"   • {key_obfuscated} in {location_desc}", log_file)
        
        if not matching_keys:
            log_message(f"\n🔄 KEY UPDATE: Active key is newer than environment configuration", log_file)
            log_message(f"   Current:     {target_key_obfuscated}", log_file)
            log_message(f"   Previous:    {len(different_keys)} older key(s) found in environment", log_file)
    
    log_message("\n Environment verification complete", log_file)

def main():
    """Main function to analyze environment for API key usage"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Analyze environment for API key usage')
    parser.add_argument('--verify-key', type=str, help='Verify if this API key matches environment configuration')
    parser.add_argument('--no-browser', action='store_true', help='Do not open browser for HTML report')
    parser.add_argument('--no-logging', action='store_true', help='Skip START/END logging (for subprocess calls)')
    args = parser.parse_args()
    
    # Only log start if not called as subprocess
    if not args.no_logging:
        log_start()
    
    # Refresh environment variables from shell config
    refresh_environment()
    
    # Clear screen for clean output (only if not verifying a key)
    if not args.verify_key:
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
    
    # Log to console only (no file output)
    log_file = None
    
    if False:  # Disabled file logging
        # Write header
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message("=" * 60, log_file)
        log_message("                       Analyzing environment for Agentic AI API key usage...", log_file)
        log_message(f"                       Environment Analysis Report - {timestamp}", log_file)
        log_message("=" * 60, log_file)
        log_message("", log_file)
        
        # Step 1: Identify installed clients
        installed_clients = check_installed_clients(log_file)
        
        log_message("\n" + "=" * 60, log_file)
        log_message("🔑 Agentic AI API Key Discovery", log_file)
        log_message("=" * 60, log_file)
        
        # Step 2: Search for API keys in various locations
        all_keys = []
        all_keys.extend(search_keychain(log_file))
        log_message("", log_file)
        all_keys.extend(search_environment_variables(log_file))
        log_message("", log_file)
        all_keys.extend(search_config_files(log_file))
        log_message("", log_file)
        all_keys.extend(search_vscode_storage(log_file))
        
        # Step 2.5: Verify provided API key if specified
        if args.verify_key:
            verify_api_key_in_environment(args.verify_key, all_keys, log_file)
            # Log report generation for verification mode
            log_success("Environment analysis completed", "analyse_env.py")
            
            if not args.no_logging:
                log_end()
            return  # Exit early when just verifying a key
        
        # Step 3: Summarize findings
        log_message("\n" + "=" * 60, log_file)
        log_message("[SUMMARY] SUMMARY", log_file)
        log_message("=" * 60, log_file)
        
        # Analyze key locations and security status
        if all_keys:
            # Filter for Agentic AI keys (sk- keys that are properly secured)
            agentic_keys = {}
            hardcoded_keys = []
            
            for key_info in all_keys:
                key = key_info['key']
                # Only include managed keys that are in keychain or environment variables
                if is_agentic_api_key(key) and key_info['type'] in ['keychain', 'environment']:
                    if key not in agentic_keys:
                        agentic_keys[key] = []
                    agentic_keys[key].append(key_info)
                # Store hardcoded keys for security recommendations
                elif key_info['type'] == 'file':
                    hardcoded_keys.append(key_info)
            
            # Count VSCode extension encrypted keys
            vscode_encrypted_count = len([k for k in all_keys if k.get('type') == 'extension_storage'])
            
            total_secure_keys = len(agentic_keys)
            if vscode_encrypted_count > 0:
                total_secure_keys += 1  # Count VSCode extension storage as one secure location
            
            log_message(f"🔑 Agentic AI Keys found: {total_secure_keys}", log_file)
            
            # Determine key storage locations for summary
            has_keychain = any(any(loc['type'] == 'keychain' for loc in locations) for locations in agentic_keys.values())
            has_environment = any(any(loc['type'] == 'environment' for loc in locations) for locations in agentic_keys.values())
            has_vscode_storage = vscode_encrypted_count > 0
            
            # Create location summary
            location_summary = []
            if has_keychain:
                location_summary.append("macOS Keychain")
            if has_environment:
                location_summary.append("Environment variable (Shell config)")
            if has_vscode_storage:
                location_summary.append("VSCode Extension Storage")
            
            if location_summary:
                if len(location_summary) == 1:
                    log_message(f"🧩 Keys stored in {location_summary[0]}", log_file)
                elif len(location_summary) == 2:
                    log_message(f"🧩 Keys stored in {location_summary[0]} and {location_summary[1]}", log_file)
                else:
                    log_message(f"🧩 Keys stored in {', '.join(location_summary[:-1])}, and {location_summary[-1]}", log_file)
                
        else:
            log_message("[INFO] Agentic AI Keys found: 0", log_file)
        
        # Step 4: Run comprehensive security scan
        try:
            from .report import SecurityScanner
            scanner = SecurityScanner()
            scanner.scan_common_locations()
            report_path = scanner.save_report(get_security_report_path())
            log_message(f"[SECURITY] Security report saved to: {report_path}", log_file)
            
            # Determine recommendation based on scan results
            if scanner.secrets_found:
                secrets_count = len(scanner.secrets_found)
                if secrets_count > 0:
                    log_message("[WARNING] Recommendation: Do not hardcode credentials - use secure storage methods", log_file)
                    log_warning("Hardcoded credentials detected - use secure storage methods")
                if not args.no_browser:
                    import webbrowser
                    webbrowser.open(f'file://{Path(report_path).absolute()}')
            else:
                log_message("[SUCCESS] Recommendation: Nil", log_file)
                log_success("Security scan completed - no issues found")
        except Exception as e:
            log_message(f"[SECURITY] Security report saved to: {get_security_report_path()}", log_file)
            log_message("[WARNING] Recommendation: Review security configuration", log_file)
        
        log_message("[SUMMARY] Analysis Complete!", log_file)
        # Log report generation
        log_success("Environment report generated and analysed", "analyse_env.py")
        
        if not args.no_logging:
            log_end()

if __name__ == "__main__":
    main()
