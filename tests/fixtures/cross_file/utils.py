"""Utility functions — passes data through to db layer."""
from .db import run_query, run_safe_query


def process_query(user_input):
    """Passes tainted input directly to DB — VULNERABLE."""
    return run_query(user_input)


def safe_process(user_input):
    """Sanitizes input before passing to DB — SAFE."""
    sanitized = user_input.replace("'", "''") if user_input else ""
    return run_safe_query(sanitized)
