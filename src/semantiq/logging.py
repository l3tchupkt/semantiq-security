"""Structured logging with automated credential redaction."""

from __future__ import annotations

import logging
import re
from typing import Any

# Patterns to automatically redact from all logs
REDACTION_PATTERNS = [
    re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{15,}", re.IGNORECASE),
    re.compile(r"(sk-[A-Za-z0-9_\-]{20,})", re.IGNORECASE),
    re.compile(r"(ghp_[A-Za-z0-9]{20,})", re.IGNORECASE),
    re.compile(r"(AKIA[0-9A-Z]{16})", re.IGNORECASE),
    re.compile(r"(api[_\-]?key['\":\s=]+)[A-Za-z0-9_\-]{16,}", re.IGNORECASE),
    re.compile(r"(secret['\":\s=]+)[A-Za-z0-9_\-]{16,}", re.IGNORECASE),
    re.compile(r"(password['\":\s=]+)[^\s'\"]{6,}", re.IGNORECASE),
]


class SecretRedactingFilter(logging.Filter):
    """Log filter that automatically scrubs sensitive credentials from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._sanitize_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._sanitize_value(v) for v in record.args)
        return True

    def redact(self, text: str) -> str:
        for pattern in REDACTION_PATTERNS:
            text = pattern.sub(r"\1[REDACTED_CREDENTIAL]", text)
        return text

    def _sanitize_value(self, val: Any) -> Any:
        if isinstance(val, str):
            return self.redact(val)
        return val


def get_logger(name: str = "semantiq") -> logging.Logger:
    """Obtain a logger configured with the credential redaction filter."""
    logger = logging.getLogger(name)
    if not any(isinstance(f, SecretRedactingFilter) for f in logger.filters):
        logger.addFilter(SecretRedactingFilter())
    return logger
