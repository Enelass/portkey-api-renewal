#!/usr/bin/env python3
"""
Centralized logging utility for Portkey Key Updater
Logs important events (SUCCESS, WARNING, ERROR) to shared log file
"""

import os
import sys
from datetime import datetime
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
LOG_FILE = PACKAGE_ROOT.parent.parent / "logs" / "portkey-key-updater.log"

class PortkeyLogger:
    def __init__(self, script_name=None):
        """Initialize logger with script name"""
        if script_name is None:
            # Get the calling script name from the frame that called get_logger()
            frame = sys._getframe(2)  # Go up 2 frames: _write_log -> log_* -> actual script
            script_name = os.path.basename(frame.f_globals.get('__file__', 'unknown'))
        
        self.script_name = script_name
        self.log_file_path = LOG_FILE
    
    def _write_log(self, level, message):
        """Write log entry with timestamp and script name"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - {self.script_name} - [{level}] {message}\n"
        
        try:
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file_path.open('a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            # Fallback to console if file write fails
            print(f"[LOGGER ERROR] Could not write to {self.log_file_path}: {e}")
            print(log_entry.strip())
    
    def success(self, message):
        """Log success message"""
        self._write_log("SUCCESS", message)
    
    def warning(self, message):
        """Log warning message"""
        self._write_log("WARNING", message)
    
    def error(self, message):
        """Log error message"""
        self._write_log("ERROR", message)
    
    def info(self, message):
        """Log info message"""
        self._write_log("INFO", message)
    
    def start(self, message):
        """Log start message with separator"""
        # Add separator before START
        separator = "=" * 50 + "\n"
        try:
            self.log_file_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_file_path.open('a', encoding='utf-8') as f:
                f.write(separator)
        except Exception as e:
            print(f"[LOGGER ERROR] Could not write separator to {self.log_file_path}: {e}")
        
        self._write_log("START", message)
    
    def end(self, message):
        """Log end message"""
        self._write_log("END", message)

# Global logger instance
_global_logger = None

def get_logger(script_name=None):
    """Get logger instance for current script"""
    global _global_logger
    if script_name is None:
        # Get the calling script name from the frame that called the log_* function
        frame = sys._getframe(1)
        script_name = os.path.basename(frame.f_globals.get('__file__', 'unknown'))
    
    if _global_logger is None or _global_logger.script_name != script_name:
        _global_logger = PortkeyLogger(script_name)
    return _global_logger

# Convenience functions
def log_success(message, script_name=None):
    """Log success message"""
    if script_name is None:
        frame = sys._getframe(1)
        script_name = os.path.basename(frame.f_globals.get('__file__', 'unknown'))
    get_logger(script_name).success(message)

def log_warning(message, script_name=None):
    """Log warning message"""
    if script_name is None:
        frame = sys._getframe(1)
        script_name = os.path.basename(frame.f_globals.get('__file__', 'unknown'))
    get_logger(script_name).warning(message)

def log_error(message, script_name=None):
    """Log error message"""
    if script_name is None:
        frame = sys._getframe(1)
        script_name = os.path.basename(frame.f_globals.get('__file__', 'unknown'))
    get_logger(script_name).error(message)

def log_info(message, script_name=None):
    """Log info message for important steps"""
    if script_name is None:
        frame = sys._getframe(1)
        script_name = os.path.basename(frame.f_globals.get('__file__', 'unknown'))
    get_logger(script_name).info(message)

def log_start(message="Script execution started", script_name=None):
    """Log script start"""
    if script_name is None:
        frame = sys._getframe(1)
        script_name = os.path.basename(frame.f_globals.get('__file__', 'unknown'))
    get_logger(script_name).start(message)

def log_end(message="Script execution completed", script_name=None):
    """Log script end"""
    if script_name is None:
        frame = sys._getframe(1)
        script_name = os.path.basename(frame.f_globals.get('__file__', 'unknown'))
    get_logger(script_name).end(message)
