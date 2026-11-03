"""Structured logging with secret redaction."""
from __future__ import annotations

import json
import logging
import re
from logging.handlers import RotatingFileHandler

from config.settings import logs_dir

_REDACT_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[^\s,;\"']+"),
    re.compile(r"(?i)((?:password|passwd|pwd|token|api[_-]?key|secret|cookie|set-cookie|session)\s*[\"']?\s*[:=]\s*[\"']?)[^\s,;\"'&]+"),
    re.compile(r"(?i)([?&](?:key|token|access_token|api_key|password)=)[^&\s]+"),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
]
_known_secrets: set[str] = set()


def register_secret(value: str | None) -> None:
    if value and len(value) >= 4:
        _known_secrets.add(value)


def redact(text: str) -> str:
    if not text:
        return text
    for secret in sorted(_known_secrets, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    for pat in _REDACT_PATTERNS:
        if pat.groups:
            text = pat.sub(lambda m: (m.group(1) or "") + "[REDACTED]", text)
        else:
            text = pat.sub("[REDACTED]", text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload)


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    root = logging.getLogger()
    if any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        return root
    root.setLevel(level)
    fh = RotatingFileHandler(logs_dir() / "audit.log", maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    fh.setFormatter(JsonFormatter())
    fh.addFilter(RedactingFilter())
    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    sh.addFilter(RedactingFilter())
    root.addHandler(fh)
    root.addHandler(sh)
    return root
