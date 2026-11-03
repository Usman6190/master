"""Encrypted local credential storage.

Secrets are encrypted with Fernet (AES-128-CBC + HMAC-SHA256). The Fernet key is
itself protected with Windows DPAPI (per-user) on Windows; on other platforms it
is stored in a file readable only by the current user.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from config.settings import app_data_dir
from utils.logging_setup import register_secret

SECRET_FIELDS = ("api_token", "login_password", "pagespeed_api_key", "admin_password", "secondary_password")


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DataBlob()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), None, None, None, None, 0x01, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI operation failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


class CredentialManager:
    def __init__(self, base_dir: Path | None = None):
        self.base = base_dir or app_data_dir()
        self.base.mkdir(parents=True, exist_ok=True)
        self.key_file = self.base / "master.key"
        self.store_file = self.base / "credentials.enc"
        self._fernet = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        if self.key_file.exists():
            raw = self.key_file.read_bytes()
            return _dpapi(raw, protect=False) if sys.platform == "win32" else raw
        key = Fernet.generate_key()
        stored = _dpapi(key, protect=True) if sys.platform == "win32" else key
        self.key_file.write_bytes(stored)
        if sys.platform != "win32":
            os.chmod(self.key_file, 0o600)
        return key

    def encrypt(self, value: str) -> str:
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self._fernet.decrypt(token.encode()).decode()

    def save(self, secrets: dict[str, str]) -> None:
        payload = {k: self.encrypt(v) for k, v in secrets.items() if v}
        self.store_file.write_text(json.dumps(payload), encoding="utf-8")
        if sys.platform != "win32":
            os.chmod(self.store_file, 0o600)
        for v in secrets.values():
            register_secret(v)

    def load(self) -> dict[str, str]:
        if not self.store_file.exists():
            return {}
        try:
            payload = json.loads(self.store_file.read_text(encoding="utf-8"))
            out = {k: self.decrypt(v) for k, v in payload.items()}
        except (InvalidToken, ValueError, json.JSONDecodeError):
            return {}
        for v in out.values():
            register_secret(v)
        return out

    def clear(self) -> None:
        if self.store_file.exists():
            self.store_file.unlink()

    @staticmethod
    def mask(value: str | None) -> str:
        if not value:
            return ""
        return "•" * 8 + (value[-2:] if len(value) > 6 else "")


def b64(s: bytes) -> str:
    return base64.b64encode(s).decode()
