#!/usr/bin/env python3
"""
Security Recommendations Generator
Variable name-based secrets detection with regex validation
"""

import os
import re
import json
import subprocess
import getpass
import argparse
from pathlib import Path
from datetime import datetime
import webbrowser
import tempfile
import sys
from .logger import log_success, log_warning, log_error, log_info, log_start, log_end
from .utils import Colors, colored_print, get_security_report_path

def sanitize_path(path_str):
    """Replace full user paths with ~/ for privacy"""
    import os
    home_path = str(Path.home())
    return path_str.replace(home_path, "~")

def obfuscate_secret(secret, show_chars=4):
    """Obfuscate a secret showing only first few characters"""
    if len(secret) <= show_chars:
        return '*' * len(secret)
    return secret[:show_chars] + '*' * (len(secret) - show_chars)

def obfuscate_context(context):
    """Obfuscate secrets in context lines while preserving structure"""
    # Common patterns for secrets in context
    patterns = [
        # Environment variables: VAR="secret" or VAR=secret
        (r'(\w*(?:token|key|secret|password|pwd|passwd|creds|credentials|auth|hash)\w*\s*=\s*["\']?)([^"\';\s]+)(["\']?)', r'\1***REDACTED***\3'),
        # GitHub tokens
        (r'(gh[pousr]_)([A-Za-z0-9]{36})', r'\1***REDACTED***'),
        # NTLM hashes
        (r'([a-fA-F0-9]{8})([a-fA-F0-9]{24})', r'\1***REDACTED***'),
        # General long alphanumeric strings that could be secrets
        (r'(["\']?)([A-Za-z0-9\-_\.]{20,})(["\']?)', lambda m: m.group(1) + (m.group(2)[:4] + '***REDACTED***' if len(m.group(2)) > 10 else m.group(2)) + m.group(3))
    ]
    
    redacted_context = context
    for pattern, replacement in patterns[:-1]:  # Skip the lambda one for now
        redacted_context = re.sub(pattern, replacement, redacted_context, flags=re.IGNORECASE)
    
    # Handle the lambda pattern separately
    def replace_long_strings(match):
        if len(match.group(2)) > 10:
            return match.group(1) + match.group(2)[:4] + '***REDACTED***' + match.group(3)
        return match.group(0)
    
    redacted_context = re.sub(patterns[-1][0], replace_long_strings, redacted_context)
    return redacted_context


class SecurityScanner:
    def __init__(self):
        self.secrets_found = []
        # Only keep essential secret patterns
        self.patterns = {
            'github_token': r'gh[pousr]_[A-Za-z0-9]{36}',
            'ntlm_hash': r'[a-fA-F0-9]{32}',
            'sk_api_key': r'sk-[A-Za-z0-9\-_]{20,}',
            'pk_api_key': r'pk-[A-Za-z0-9\-_]{20,}',
        }
        
        # Variable names that suggest secrets
        self.secret_variable_names = [
            'creds', 'credentials', 'token', 'password', 'passwd', 'pwd', 'secret',
            'api_key', 'apikey', 'access_key', 'private_key', 'auth', 'authorization'
        ]
        
        # Regex patterns to validate if a value looks like a secret
        self.secret_value_patterns = {
            'token': r'^[A-Za-z0-9\-_\.]{20,}$',  # Long alphanumeric strings
            'password': r'^.{8,}$',  # At least 8 characters
            'hash': r'^[a-fA-F0-9]{16,}$',  # Hex strings
            'key': r'^[A-Za-z0-9\+/=]{16,}$',  # Base64-like strings
            'secret': r'^[A-Za-z0-9\-_\.]{12,}$',  # Medium length alphanumeric
        }

    def scan_file(self, file_path):
        """Scan a single file for secrets"""
        try:
            # Get file permissions and ACLs
            file_permissions = self._get_file_permissions(file_path)
            file_acls = self._get_file_acls(file_path)
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    # Skip comments and empty lines
                    stripped_line = line.strip()
                    if not stripped_line or stripped_line.startswith('#'):
                        continue
                    
                    # First check for specific patterns (GitHub tokens, NTLM hashes)
                    for secret_type, pattern in self.patterns.items():
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            secret_value = match.group(0)
                            
                            # Filter out false positives
                            if self._is_false_positive(secret_value, secret_type, line.strip()):
                                continue
                            
                            permission_rec = self._get_permission_recommendation(file_permissions, str(file_path))
                            acl_rec = self._get_acl_recommendation(str(file_path)) if file_acls['has_acls'] else None
                            self.secrets_found.append({
                                'type': secret_type,
                                'value': secret_value,
                                'file': sanitize_path(str(file_path)),
                                'line': line_num,
                                'context': line.strip(),
                                'permissions': file_permissions,
                                'permission_issue': permission_rec,
                                'acls': file_acls,
                                'acl_recommendation': acl_rec
                            })
                    
                    # Then check for variable name-based secrets
                    self._scan_variable_based_secrets(line, line_num, file_path, file_permissions, file_acls)
                            
        except (IOError, OSError, PermissionError) as e:
            pass  # Skip files we can't read

    def _get_file_permissions(self, file_path):
        """Get file permissions in octal format"""
        try:
            import stat
            file_stat = os.stat(file_path)
            permissions = oct(file_stat.st_mode)[-3:]
            return permissions
        except (OSError, IOError):
            return "unknown"
    
    def _get_file_acls(self, file_path):
        """Get file ACLs using ls -le command"""
        try:
            import subprocess
            result = subprocess.run(['ls', '-le', str(file_path)],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output = result.stdout.strip()
                # Check if there are ACLs (indicated by + at the end of permissions)
                if '+' in output.split()[0]:
                    return {'has_acls': True, 'output': output}
                else:
                    return {'has_acls': False, 'output': output}
            return {'has_acls': False, 'output': 'unknown'}
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
            return {'has_acls': False, 'output': 'unknown'}
    
    def _get_acl_recommendation(self, file_path):
        """Get ACL recommendations for secure file access"""
        username = os.getenv('USER', 'username')
        return {
            'set_secure_posix': f'chmod 600 {sanitize_path(file_path)}',
            'set_user_acl': f'chmod +a "{username} allow read,write" {sanitize_path(file_path)}',
            'set_group_acl': f'chmod +a "group:admin allow read" {file_path}',
            'check_acls': f'ls -le {file_path}',
            'reason': 'Use POSIX 600 as baseline, then add specific ACLs for granular access control when needed'
        }
    
    def _is_insecure_permissions(self, permissions, file_path):
        """Check if file permissions are insecure for files containing secrets"""
        if permissions == "unknown":
            return False
        
        # Files containing secrets should have restrictive permissions (600 or 700)
        secure_permissions = ['600', '700']
        
        # Check if this is a sensitive file type
        sensitive_files = ['.env', '.bashrc', '.zshrc', '.bash_profile', '.zsh_profile', '.profile', '.zprofile']
        file_name = os.path.basename(file_path)
        
        # If it's a sensitive file or contains secrets, it should have secure permissions
        if any(sensitive in file_name for sensitive in sensitive_files) or any(sensitive in file_path for sensitive in sensitive_files):
            return permissions not in secure_permissions
        
        return False
    
    def _get_permission_recommendation(self, permissions, file_path):
        """Get specific recommendation for fixing file permissions"""
        if self._is_insecure_permissions(permissions, file_path):
            return {
                'current': permissions,
                'recommended': '600',
                'command': f'chmod 600 {sanitize_path(file_path)}',
                'reason': 'Files containing secrets should only be readable by the owner'
            }
        return None

    def _scan_variable_based_secrets(self, line, line_num, file_path, file_permissions, file_acls):
        """Look for variables with secret-like names and validate their values"""
        # Pattern to match variable assignments: VAR=value or VAR="value" or export VAR=value
        var_patterns = [
            r'(\w*(?:' + '|'.join(self.secret_variable_names) + r')\w*)\s*=\s*["\']?([^"\'\s]+)["\']?',
            r'export\s+(\w*(?:' + '|'.join(self.secret_variable_names) + r')\w*)\s*=\s*["\']?([^"\'\s]+)["\']?'
        ]
        
        for var_pattern in var_patterns:
            matches = re.finditer(var_pattern, line, re.IGNORECASE)
            for match in matches:
                var_name = match.group(1)
                var_value = match.group(2)
                
                # Skip obvious non-secrets
                if self._is_obvious_non_secret(var_value):
                    continue
                
                # Determine the type of secret based on variable name and value
                secret_type = self._classify_secret_type(var_name, var_value)
                if secret_type and self._looks_like_secret(var_value, secret_type):
                    permission_rec = self._get_permission_recommendation(file_permissions, str(file_path))
                    acl_rec = self._get_acl_recommendation(str(file_path)) if file_acls['has_acls'] else None
                    self.secrets_found.append({
                        'type': f'variable_{secret_type}',
                        'value': var_value,
                        'file': sanitize_path(str(file_path)),
                        'line': line_num,
                        'context': line.strip(),
                        'variable_name': var_name,
                        'permissions': file_permissions,
                        'permission_issue': permission_rec,
                        'acls': file_acls,
                        'acl_recommendation': acl_rec
                    })

    def _classify_secret_type(self, var_name, var_value):
        """Classify the type of secret based on variable name and value patterns"""
        var_name_lower = var_name.lower()
        
        if any(keyword in var_name_lower for keyword in ['token', 'auth']):
            return 'token'
        elif any(keyword in var_name_lower for keyword in ['password', 'passwd', 'pwd']):
            return 'password'
        elif any(keyword in var_name_lower for keyword in ['key', 'secret']):
            return 'key'
        elif any(keyword in var_name_lower for keyword in ['creds', 'credentials']):
            return 'credentials'
        elif re.match(r'^[a-fA-F0-9]+$', var_value) and len(var_value) >= 16:
            return 'hash'
        else:
            return 'secret'

    def _looks_like_secret(self, value, secret_type):
        """Check if a value looks like a secret using regex patterns"""
        if secret_type in self.secret_value_patterns:
            return re.match(self.secret_value_patterns[secret_type], value) is not None
        return len(value) >= 8  # Default minimum length for secrets

    def _is_obvious_non_secret(self, value):
        """Check if a value is obviously not a secret"""
        non_secrets = [
            'true', 'false', 'yes', 'no', 'on', 'off', 'enabled', 'disabled',
            'localhost', '127.0.0.1', 'example.com', 'test', 'demo', 'sample',
            'placeholder', 'your_token', 'your_key', 'changeme', 'default'
        ]
        
        value_lower = value.lower()
        
        # Skip common non-secret values
        if value_lower in non_secrets:
            return True
        
        # Skip numeric values
        if value.isdigit():
            return True
        
        # Skip very short values (likely not secrets)
        if len(value) < 6:
            return True
        
        # Skip obvious file paths
        if '/' in value and any(ext in value for ext in ['.sh', '.py', '.js', '.txt', '.log']):
            return True
        
        return False

    def _is_false_positive(self, value, secret_type, context=""):
        """Filter out common false positives for specific patterns"""
        # Skip obvious placeholders
        placeholders = ['example', 'placeholder', 'your_token', 'your_key', 'sample', 'test123', 'dummy']
        value_lower = value.lower()
        
        for placeholder in placeholders:
            if placeholder in value_lower:
                return True
        
        # GitHub token specific filtering
        if secret_type == 'github_token':
            # Skip if it's in a comment or documentation
            if any(indicator in context.lower() for indicator in ['example', 'sample', 'demo', 'test']):
                return True
        
        # NTLM hash specific filtering
        if secret_type == 'ntlm_hash':
            # Skip values that are all the same character repeated
            if len(set(value.lower())) == 1:
                return True
            # Skip obvious non-NTLM hex patterns
            if value.lower() in ['00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff']:
                return True
                
        return False

    def scan_common_locations(self):
        """Scan common locations for secrets"""
        home = Path.home()
        
        # Configuration files to scan
        config_files = [
            # Shell configurations
            home / '.bashrc',
            home / '.bash_profile',
            home / '.zshrc',
            home / '.zsh_profile',
            home / '.profile',
            home / '.zprofile',
            
            # Environment files
            home / '.env',
            Path('.env'),
            Path('.env.local'),
            Path('.env.production'),
            
            # Git configurations
            home / '.gitconfig',
            
            # SSH configurations
            home / '.ssh' / 'config',
        ]
        
        # Project configuration files
        project_configs = [
            'config/config.json',
            'package.json',
            'settings.json',
            '.npmrc',
            'requirements.txt',
            'Dockerfile',
            'docker-compose.yml',
        ]
        
        # Add project configs to scan list
        for config in project_configs:
            config_files.append(Path(config))
        
        for config_file in config_files:
            if config_file.exists() and config_file.is_file():
                self.scan_file(config_file)

    def has_hardcoded_sk_keys(self):
        """Check if any hardcoded managed API keys were found."""
        managed_keys = [secret for secret in self.secrets_found if secret['type'] in ('sk_api_key', 'pk_api_key')]
        return len(managed_keys) > 0, managed_keys

    def generate_report(self):
        """Generate an HTML security report"""
        
        # Remove duplicates by creating unique secrets based on semantic content
        unique_secrets = []
        seen_secrets = set()
        seen_contexts = set()
        
        for secret in self.secrets_found:
            # Create a unique identifier based on file location and context
            context_key = (secret['file'], secret['line'], secret['context'])
            
            # Skip if we've already seen this exact context (same line, same file)
            if context_key in seen_contexts:
                continue
                
            seen_contexts.add(context_key)
            unique_secrets.append(secret)
        
        # Update self.secrets_found to use unique secrets for accurate counting
        self.secrets_found = unique_secrets
        
        # Group secrets by type
        secrets_by_type = {}
        files_affected = set()
        
        for secret in self.secrets_found:
            secret_type = secret['type']
            if secret_type not in secrets_by_type:
                secrets_by_type[secret_type] = []
            secrets_by_type[secret_type].append(secret)
            files_affected.add(secret['file'])
        
        # Analyze system status
        system_status = analyze_system_status(self.secrets_found)
        
        # Generate HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }}
                .summary {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .summary-box {{ background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); min-width: 150px; }}
                .summary-number {{ font-size: 2em; font-weight: bold; color: #dc3545; }}
                .alert {{ background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                .secret-section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .secret-type {{ font-size: 1.2em; font-weight: bold; color: #495057; margin-bottom: 15px; }}
                .secret-item {{ background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #dc3545; border-radius: 5px; }}
                .secret-value {{ font-family: monospace; background: #e9ecef; padding: 5px; border-radius: 3px; font-weight: bold; }}
                .file-path {{ color: #0066cc; font-weight: bold; }}
                .context {{ background: #f1f3f4; padding: 10px; margin-top: 10px; border-radius: 3px; font-family: monospace; font-size: 0.9em; }}
                .files-section {{ background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .file-list {{ list-style-type: none; padding: 0; }}
                .file-item {{ background: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 5px; }}
                .file-secrets {{ color: #28a745; font-weight: bold; }}
                .permission-warning {{ background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 10px; margin-top: 10px; border-radius: 5px; }}
                .permission-fix {{ background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 8px; margin-top: 5px; border-radius: 3px; font-family: monospace; font-size: 0.9em; }}
                .insecure-permissions {{ color: #dc3545; font-weight: bold; }}
                .secure-permissions {{ color: #28a745; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Analysis Report</h1>
                <h2>System Analysis and Security Recommendations</h2>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            {generate_system_analysis_html(system_status)}
            
            {generate_secure_storage_html()}
            
        """
        
        # Only show detailed security findings if there are actual secrets found
        if self.secrets_found:
            html_content += f"""
            <div class="summary">
                <div class="summary-box">
                    <div class="summary-number">{len(self.secrets_found)}</div>
                    <div>Total Secrets Found</div>
                </div>
                <div class="summary-box">
                    <div class="summary-number">{len(secrets_by_type)}</div>
                    <div>Secret Types</div>
                </div>
                <div class="summary-box">
                    <div class="summary-number">{len(files_affected)}</div>
                    <div>Files Affected</div>
                </div>
            </div>
            
            <div class="alert">
                <strong>[WARNING] Security Risk Detected</strong><br>
                {len(self.secrets_found)} hardcoded secrets were found across {len(files_affected)} files. These credentials should be removed from your codebase immediately and stored securely.
            </div>
            
            <div class="secret-section">
                <h2> Detected Secrets by Type</h2>
            """
        
        for secret_type, secrets in secrets_by_type.items():
            # Format the secret type name
            display_type = secret_type.replace('_', ' ').title()
            html_content += f"""
                <div class="secret-type">🔑 {display_type} ({len(secrets)} found)</div>
            """
            
            for secret in secrets:
                obfuscated_value = obfuscate_secret(secret['value'])
                variable_info = f"<br><strong>Variable:</strong> {secret['variable_name']}" if 'variable_name' in secret else ""
                
                # Format permissions with security indication
                permissions_class = "insecure-permissions" if secret.get('permission_issue') else "secure-permissions"
                permissions_info = f"<br><strong>Permissions:</strong> <span class=\"{permissions_class}\">{secret['permissions']}</span>" if 'permissions' in secret else ""
                
                # Add ACL information
                acl_info = ""
                if secret.get('acls', {}).get('has_acls'):
                    acl_info = "<br><strong>ACLs:</strong> <span class=\"insecure-permissions\">Present (potential security risk)</span>"
                
                # Add permission warning if there's an issue
                permission_warning = ""
                if secret.get('permission_issue'):
                    perm_issue = secret['permission_issue']
                    permission_warning = f"""
                        <div class="permission-warning">
                            <strong>[WARNING] Insecure File Permissions Detected</strong><br>
                            Current permissions ({perm_issue['current']}) allow other users to read this file containing secrets.<br>
                            <strong>Recommendation:</strong> {perm_issue['reason']}
                            <div class="permission-fix">
                                <strong>Fix command:</strong> {perm_issue['command']}
                            </div>
                        </div>
                    """
                
                # Add ACL guidance if there are ACLs or if ACLs could be useful
                acl_guidance = ""
                if secret.get('acl_recommendation'):
                    acl_rec = secret['acl_recommendation']
                    if secret.get('acls', {}).get('has_acls'):
                        acl_guidance = f"""
                            <div class="permission-warning">
                                <strong>ℹ️ Access Control Lists (ACLs) Present</strong><br>
                                This file has ACLs for granular access control. Ensure they're properly configured.<br>
                                <strong>Best Practice:</strong> {acl_rec['reason']}
                                <div class="permission-fix">
                                    <strong>Check current ACLs:</strong> {acl_rec['check_acls']}<br>
                                    <strong>Set secure baseline:</strong> {acl_rec['set_secure_posix']}<br>
                                    <strong>Add user ACL:</strong> {acl_rec['set_user_acl']}<br>
                                    <strong>Add group ACL:</strong> {acl_rec['set_group_acl']}
                                </div>
                            </div>
                        """
                    else:
                        acl_guidance = f"""
                            <div style="background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 10px; margin-top: 10px; border-radius: 5px;">
                                <strong>[INFO] ACL Recommendation</strong><br>
                                Consider using ACLs for granular access if this file needs to be shared securely.<br>
                                <div class="permission-fix">
                                    <strong>Set secure baseline:</strong> {acl_rec['set_secure_posix']}<br>
                                    <strong>Add specific user access:</strong> {acl_rec['set_user_acl']}<br>
                                    <strong>Add group access:</strong> {acl_rec['set_group_acl']}
                                </div>
                            </div>
                        """
                
                # Obfuscate the context to prevent showing full secrets
                safe_context = obfuscate_context(secret['context'])
                
                html_content += f"""
                    <div class="secret-item">
                        <strong>{secret_type.upper()}</strong><br>
                        <strong>File:</strong> <span class="file-path">{secret['file']}</span><br>
                        <strong>Line:</strong> {secret['line']}<br>
                        <strong>Value:</strong> <span class="secret-value">{obfuscated_value}</span>
                        {variable_info}
                        {permissions_info}
                        {acl_info}
                        {permission_warning}
                        {acl_guidance}
                        <div class="context"><strong>Context:</strong> {safe_context}</div>
                    </div>
                """
        
        html_content += """
            </div>
            
            <div class="files-section">
                <h2>📁 Files Affected</h2>
                <ul class="file-list">
        """
        
        # Group secrets by file
        files_with_secrets = {}
        for secret in self.secrets_found:
            file_path = secret['file']
            if file_path not in files_with_secrets:
                files_with_secrets[file_path] = []
            files_with_secrets[file_path].append(secret)
        
        for file_path, file_secrets in files_with_secrets.items():
            secret_types = list(set(s['type'] for s in file_secrets))
            html_content += f"""
                    <li class="file-item">
                        <strong>📄 {file_path}</strong> <span class="file-secrets">({len(file_secrets)} secrets)</span>
                        <ul>
            """
            for secret_type in secret_types:
                count = len([s for s in file_secrets if s['type'] == secret_type])
                lines = [str(s['line']) for s in file_secrets if s['type'] == secret_type]
                html_content += f"<li>Line {', '.join(lines)}: {secret_type.replace('_', ' ')} - {obfuscate_secret([s['value'] for s in file_secrets if s['type'] == secret_type][0])}</li>"
            
            html_content += """
                        </ul>
                    </li>
            """
        
        # Only show files affected section if there are secrets
        if self.secrets_found:
            html_content += """
                </ul>
            </div>
        """
        
        html_content += """
            <div class="recommendations">
                <h3>[SECURITY] Security Recommendations</h3>
                
                <h4>📁 File Permissions (Critical)</h4>
                <div class="permission-warning">
                    Files containing secrets should have restrictive permissions (600) to prevent unauthorized access:
                    <div class="permission-fix">
                        chmod 600 ~/.env ~/.zshrc ~/.bashrc ~/.bash_profile<br>
                        # This ensures only you can read/write these files
                    </div>
                </div>
                
                <h4>[SECURITY] Access Control Lists (ACLs) - Granular Permission Management</h4>
                <div style="background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <strong>Best Practice:</strong> Use POSIX 600 as secure baseline, then add ACLs for granular access when sharing is required:
                    <div class="permission-fix">
                        # 1. Set secure POSIX baseline first<br>
                        chmod 600 ~/.env ~/.zshrc<br><br>
                        # 2. Check current ACLs (look for + symbol)<br>
                        ls -le ~/.env ~/.zshrc<br><br>
                        # 3. Add specific user access if needed<br>
                        chmod +a "username allow read" ~/.env<br><br>
                        # 4. Add group access if needed<br>
                        chmod +a "group:admin allow read" ~/.env<br><br>
                        # 5. Verify final permissions<br>
                        ls -le ~/.env
                    </div>
                </div>
                
                <h4>[SECURITY] Secret Management Best Practices</h4>
                <ul>
                    <li><strong>Fix File Permissions Immediately:</strong>
                        <br>• 644 permissions allow others to read your secrets
                        <br>• Use 600 (owner read/write only) as secure POSIX baseline for files with credentials
                        <br>• Use 700 for directories containing sensitive files
                        <br>• Use ACLs for granular access control when specific users/groups need access
                        <br>• Always start with secure POSIX permissions (600), then add ACLs as needed
                    </li>
                    <li><strong>Use macOS Keychain</strong> for secure local credential storage:
                        <br><code>security add-generic-password -a "username" -s "service_name" -w "password"</code>
                        <br><code>security find-generic-password -a "username" -s "service_name" -w</code>
                    </li>
                    <li><strong>Environment Variables:</strong> Load from secure files outside your project directory</li>
                    <li><strong>Password Managers:</strong> Consider 1Password CLI, Bitwarden CLI, or macOS Keychain for cross-application sharing</li>
                    <li><strong>Version Control:</strong> Review .gitignore patterns to prevent committing sensitive files</li>
                </ul>
                
                <h4>[ALERT] Immediate Actions Required</h4>
                <ol>
                    <li>Set secure POSIX baseline: <code>chmod 600</code> for all files with secrets</li>
                    <li>Remove hardcoded secrets from files and use secure storage instead</li>
                </ol>
            </div>
        </body>
        </html>
        """
        
        return html_content

    def save_report(self, output_file):
        """Save the security report to an HTML file"""
        report_content = self.generate_report()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return output_file


def get_secure_storage_info():
    """Get information about securely stored credentials"""
    secure_storage = {
        'keychain_entries': [],
        'env_vars': [],
        'vscode_encrypted': []
    }
    
    # Check macOS Keychain
    services_to_check = [
        'openai', 'anthropic', 'claude', 'gemini', 'portkey',
        'github', 'gitlab', 'aws', 'google', 'api-key',
        'roo', 'cline', 'continue', 'copilot',
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'CLAUDE_API_KEY',
        'GEMINI_API_KEY', 'PORTKEY_API_KEY', 'GITHUB_TOKEN'
    ]
    
    for service in services_to_check:
        try:
            result = subprocess.run([
                'security', 'find-generic-password', '-s', service, '-w'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                password = result.stdout.strip()
                if len(password) > 10:  # Reasonable minimum for API keys
                    secure_storage['keychain_entries'].append({
                        'service': service,
                        'value': password[:8] + "***" + password[-4:],  # Obfuscated
                        'type': 'macOS Keychain'
                    })
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass
    
    # Check environment variables that reference keychain
    env_vars_to_check = [
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'CLAUDE_API_KEY',
        'GEMINI_API_KEY', 'PORTKEY_API_KEY', 'GITHUB_TOKEN'
    ]
    
    for var in env_vars_to_check:
        if var in os.environ:
            value = os.environ[var]
            # Check if it's a keychain reference or actual value
            if '$(' in value or len(value) > 50:  # Likely keychain reference or actual key
                display_value = value if '$(' in value else value[:8] + "***" + value[-4:]
                storage_type = "Environment Variable (Keychain Reference)" if '$(' in value else "Environment Variable"
                secure_storage['env_vars'].append({
                    'variable': var,
                    'value': display_value,
                    'type': storage_type
                })
    
    # Check VSCode encrypted storage - detect AI-related extensions that may store secrets
    try:
        # Get list of installed VSCode extensions
        result = subprocess.run(['code', '--list-extensions'],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            installed_extensions = result.stdout.strip().split('\n')
            
            # AI-related extensions that typically store API keys
            ai_extensions = {
                'rooveterinaryinc.roo-cline': 'Roo-Cline',
                'continue.continue': 'Continue',
                'github.copilot': 'GitHub Copilot',
                'github.copilot-chat': 'GitHub Copilot Chat',
                'ms-vscode.vscode-ai': 'Visual Studio IntelliCode',
                'tabnine.tabnine-vscode': 'Tabnine',
                'anthropic.claude-dev': 'Claude Dev',
                'saoudrizwan.claude-dev': 'Claude Dev',
                'openai.chatgpt': 'ChatGPT',
                'codeium.codeium': 'Codeium',
                'amazon.aws-toolkit-vscode': 'AWS Toolkit',
                'ms-python.python': 'Python (may store API keys)',
                'anthropic.claude-code': 'Claude Code'
            }
            
            # Check which AI extensions are installed
            for extension_id in installed_extensions:
                if extension_id.strip() in ai_extensions:
                    display_name = ai_extensions[extension_id.strip()]
                    secure_storage['vscode_encrypted'].append({
                        'extension_id': extension_id.strip(),
                        'extension_name': display_name,
                        'type': 'VSCode Encrypted Storage',
                        'note': 'May contain encrypted API keys - inaccessible to external tools'
                    })
                # Also check for any extension with AI-related keywords
                elif any(keyword in extension_id.lower() for keyword in
                        ['ai', 'gpt', 'claude', 'copilot', 'assistant', 'anthropic', 'openai']):
                    # Extract a cleaner name from the extension ID
                    clean_name = extension_id.strip().split('.')[-1].replace('-', ' ').title()
                    secure_storage['vscode_encrypted'].append({
                        'extension_id': extension_id.strip(),
                        'extension_name': clean_name,
                        'type': 'VSCode Encrypted Storage',
                        'note': 'Potential extension with encrypted secret storage'
                    })
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to directory-based detection if code CLI not available
        vscode_dirs = [
            Path.home() / "Library/Application Support/Code/User/globalStorage",
            Path.home() / "Library/Application Support/Code - Insiders/User/globalStorage"
        ]
        
        for vscode_dir in vscode_dirs:
            if vscode_dir.exists():
                for ext_dir in vscode_dir.glob("*"):
                    if ext_dir.is_dir() and any(keyword in ext_dir.name.lower()
                                             for keyword in ['roo', 'cline', 'anthropic', 'openai', 'copilot', 'ai']):
                        secure_storage['vscode_encrypted'].append({
                            'extension_id': ext_dir.name,
                            'extension_name': f"Extension: {ext_dir.name}",
                            'type': 'VSCode Encrypted Storage',
                            'note': 'Detected from storage directory - encrypted by VSCode Electron'
                        })
    
    return secure_storage

def analyze_system_status(secrets_found):
    """Analyze system status and provide clear user guidance"""
    import os
    from pathlib import Path
    
    # Check for hardcoded managed API keys
    managed_keys = [s for s in secrets_found if s['type'] in ('sk_api_key', 'pk_api_key')]
    has_hardcoded_keys = len(managed_keys) > 0
    
    # Check keychain status
    try:
        import subprocess
        keychain_result = subprocess.run(['security', 'find-generic-password', '-a', os.getenv('USER', 'user'), '-s', 'PORTKEY_API_KEY', '-w'],
                                       capture_output=True, text=True, timeout=5)
        has_keychain_key = keychain_result.returncode == 0
    except:
        has_keychain_key = False
    
    # Check environment variables
    has_env_vars = any(key in os.environ for key in ['PORTKEY_API_KEY', 'OPENAI_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'GEMINI_API_KEY'])
    
    # Check shell config files for hardcoded values
    shell_files = ['.zshrc', '.bashrc', '.bash_profile', '.zsh_profile']
    hardcoded_in_shell = False
    for shell_file in shell_files:
        shell_path = Path.home() / shell_file
        if shell_path.exists():
            try:
                with open(shell_path, 'r') as f:
                    content = f.read()
                    if 'sk-' in content and not '$(' in content:  # Hardcoded, not keychain reference
                        hardcoded_in_shell = True
                        break
            except:
                pass
    
    # Determine system status and guidance
    if not has_hardcoded_keys and has_keychain_key and has_env_vars and not hardcoded_in_shell:
        status = "optimal"
        title = "Portkey Virtual Key Management: Optimal"
        message = "Nothing to do - your Portkey API key is securely stored in macOS Keychain and properly configured in the environment."
        recommendations = []
    elif has_hardcoded_keys or hardcoded_in_shell:
        status = "critical"
        title = "[ALERT] Portkey Virtual Key Management: Critical Security Issue"
        if has_hardcoded_keys:
            message = f"Found {len(managed_keys)} hardcoded Portkey API keys in configuration files. Immediate action required."
        else:
            message = "Found hardcoded Portkey API keys in shell configuration files. Immediate action required."
        recommendations = [
            "Remove all hardcoded API keys from configuration files",
            "Store API key securely in macOS Keychain",
            "Update shell configuration with keychain-based setup"
        ]
    elif not has_keychain_key and not has_env_vars:
        status = "missing"
        title = "[WARNING] Portkey Virtual Key Management: No Configuration Found"
        message = "No Portkey API key found in keychain or environment variables. Setup required."
        recommendations = [
            "Obtain a valid API key from your organization",
            "Store it securely in macOS Keychain",
            "Configure environment variables to reference keychain"
        ]
    else:
        status = "needs_improvement"
        title = "[WARNING] Portkey Virtual Key Management: Configuration Needs Improvement"
        message = "Portkey API key found but configuration could be more secure."
        recommendations = [
            "Ensure API key is stored in macOS Keychain",
            "Update shell configuration for optimal security"
        ]
    
    return {
        'status': status,
        'title': title,
        'message': message,
        'recommendations': recommendations,
        'has_keychain_key': has_keychain_key,
        'has_env_vars': has_env_vars,
        'hardcoded_count': len(managed_keys)
    }


def generate_system_analysis_html(system_status):
    """Generate HTML for system analysis section"""
    status_colors = {
        'optimal': '#28a745',
        'critical': '#dc3545',
        'missing': '#ffc107',
        'needs_improvement': '#fd7e14'
    }
    
    color = status_colors.get(system_status['status'], '#6c757d')
    
    html = f"""
    <div class="system-analysis" style="background: white; margin: 20px 0; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-left: 5px solid {color};">
        <h2 style="color: {color}; margin-top: 0;">{system_status['title']}</h2>
        <p style="font-size: 1.1em; margin: 15px 0; color: #495057;">{system_status['message']}</p>
    """
    
    if system_status['recommendations']:
        html += """
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="color: #495057; margin-top: 0;">📝 Recommended Actions:</h3>
            <ol style="margin: 10px 0; padding-left: 20px;">
        """
        for rec in system_status['recommendations']:
            html += f"<li style='margin: 8px 0; color: #495057;'>{rec}</li>"
        html += "</ol></div>"
    
    # Add shell configuration commands if needed
    if system_status['status'] in ['critical', 'needs_improvement']:
        html += f"""
        <div style="background: #e7f3ff; border: 1px solid #b3d9ff; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h4 style="color: #0066cc; margin-top: 0;">🔧 Shell Configuration Setup (One-Time):</h4>
            <p style="color: #495057; margin: 10px 0;">Add these lines to your shell configuration file (e.g., ~/.zshrc):</p>
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: 'Monaco', 'Menlo', monospace; font-size: 0.9em; overflow-x: auto; border: 1px solid #dee2e6; color: #495057;">export PORTKEY_API_KEY=$(security find-generic-password -s "PORTKEY_API_KEY" -w)
export OPENAI_API_KEY="$PORTKEY_API_KEY"
export ANTHROPIC_AUTH_TOKEN="$PORTKEY_API_KEY"
export GEMINI_API_KEY="$PORTKEY_API_KEY"</pre>
            <p style="color: #495057; margin: 10px 0; font-size: 0.9em;">
                <strong>Note:</strong> This configuration securely references your keychain-stored API key without hardcoding any secrets.
            </p>
        </div>
        """
    
    html += "</div>"
    return html


def generate_secure_storage_html():
    """Generate HTML for secure storage section"""
    secure_storage = get_secure_storage_info()
    
    # Count total secure items
    total_secure = (len(secure_storage['keychain_entries']) +
                   len(secure_storage['env_vars']) +
                   len(secure_storage['vscode_encrypted']))
    
    if total_secure == 0:
        return ""  # Don't show section if no secure storage found
    
    html = f"""
    <div class="secure-section" style="background: white; margin: 20px 0; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-left: 5px solid #28a745;">
        <h2 style="color: #28a745; margin-top: 0;">✅ Securely Stored Credentials ({total_secure} found)</h2>
        <p style="color: #495057; margin-bottom: 20px;">The following credentials are stored securely and follow security best practices:</p>
    """
    
    # Keychain entries
    if secure_storage['keychain_entries']:
        html += f"""
        <div style="margin: 20px 0;">
            <h3 style="color: #495057; margin-bottom: 15px;">🔐 macOS Keychain ({len(secure_storage['keychain_entries'])} entries)</h3>
        """
        for entry in secure_storage['keychain_entries']:
            html += f"""
            <div style="background: #d4edda; padding: 15px; margin: 10px 0; border-left: 4px solid #28a745; border-radius: 5px;">
                <strong>Service:</strong> {entry['service']}<br>
                <strong>Value:</strong> <span style="font-family: monospace; background: #c3e6cb; padding: 3px 6px; border-radius: 3px;">{entry['value']}</span><br>
                <strong>Storage:</strong> {entry['type']} ✓
            </div>
            """
        html += "</div>"
    
    # Environment variables
    if secure_storage['env_vars']:
        html += f"""
        <div style="margin: 20px 0;">
            <h3 style="color: #495057; margin-bottom: 15px;">🌍 Environment Variables ({len(secure_storage['env_vars'])} entries)</h3>
        """
        for entry in secure_storage['env_vars']:
            html += f"""
            <div style="background: #d4edda; padding: 15px; margin: 10px 0; border-left: 4px solid #28a745; border-radius: 5px;">
                <strong>Variable:</strong> {entry['variable']}<br>
                <strong>Value:</strong> <span style="font-family: monospace; background: #c3e6cb; padding: 3px 6px; border-radius: 3px;">{entry['value']}</span><br>
                <strong>Storage:</strong> {entry['type']} ✓
            </div>
            """
        html += "</div>"
    
    # VSCode encrypted storage
    if secure_storage['vscode_encrypted']:
        html += f"""
        <div style="margin: 20px 0;">
            <h3 style="color: #495057; margin-bottom: 15px;">🔒 VSCode Encrypted Storage ({len(secure_storage['vscode_encrypted'])} entries)</h3>
            <div style="background: #d4edda; padding: 15px; margin: 10px 0; border-left: 4px solid #28a745; border-radius: 5px;">
                <strong>Storage:</strong> VSCode Encrypted Storage ✓<br>
                <strong>Note:</strong> May contain encrypted API keys - inaccessible to external tools<br><br>
                <strong>Extensions:</strong><br>
        """
        
        for entry in secure_storage['vscode_encrypted']:
            extension_display = entry.get('extension_name', entry.get('extension_id', entry.get('extension', 'Unknown Extension')))
            extension_id = entry.get('extension_id', entry.get('extension', 'N/A'))
            html += f"• {extension_display} (<code>{extension_id}</code>)<br>"
        
        html += """
            </div>
        </div>
        """
    
    html += "</div>"
    return html


def main():
    """Main function to run the security scanner"""
    log_start()
    parser = argparse.ArgumentParser(
        description="Generate the Portkey security report",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  generate-report                    # Scan common locations and write logs/security_report.html
        """
    )
    parser.parse_args()

    scanner = SecurityScanner()
    scanner.scan_common_locations()
    
    # Analyze system status
    system_status = analyze_system_status(scanner.secrets_found)
    
    if scanner.secrets_found:
        report_file = get_security_report_path()
        scanner.save_report(report_file)
        
        colored_print(f"[SECURITY] Report saved to: {report_file}", Colors.PURPLE)
        colored_print(f"[REPORT] Found {len(scanner.secrets_found)} potential secrets", Colors.CYAN)
        
        # Open the report in the default browser
        webbrowser.open(f'file://{report_file.absolute()}')
    else:
        colored_print("[SUCCESS] No secrets found in scanned locations", Colors.GREEN)
        log_success("Security scan completed - no secrets found in scanned locations")
        # Still show system status even if no secrets found
        print(f"{system_status['title']}")
        print(f"{system_status['message']}")
    
    log_end()


if __name__ == "__main__":
    main()
