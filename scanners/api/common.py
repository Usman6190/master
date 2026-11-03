"""Helpers shared by authenticated API modules."""
from __future__ import annotations

import json
from urllib.parse import urljoin

from scanners.base import AuditContext


def api_base(ctx: AuditContext) -> str:
    return (ctx.config.get("api_base_url") or ctx.target_url).rstrip("/") + "/"


def api_url(ctx: AuditContext, path: str) -> str:
    if path.startswith("http"):
        return path
    return urljoin(api_base(ctx), path.lstrip("/"))


def lines(value) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [ln.strip() for ln in str(value or "").replace(",", "\n").splitlines() if ln.strip()]


def auth_headers(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def get_token(ctx: AuditContext) -> str | None:
    """Return configured API token, or obtain one via the configured login endpoint (once per audit)."""
    if ctx.shared.get("auth_token"):
        return ctx.shared["auth_token"]
    tok = ctx.secrets.get("api_token")
    if not tok and ctx.config.get("login_username") and ctx.secrets.get("login_password") and ctx.config.get("login_endpoint"):
        try:
            r = ctx.client.post(api_url(ctx, ctx.config["login_endpoint"]),
                                json={ctx.config.get("login_user_field", "email"): ctx.config["login_username"],
                                      ctx.config.get("login_pass_field", "password"): ctx.secrets["login_password"]})
            if r.ok:
                data = r.json()
                for key in ("token", "access_token", "accessToken", "jwt", "id_token"):
                    if isinstance(data, dict) and data.get(key):
                        tok = data[key]
                        break
                    if isinstance(data, dict) and isinstance(data.get("data"), dict) and data["data"].get(key):
                        tok = data["data"][key]
                        break
        except (ValueError, json.JSONDecodeError, Exception):  # noqa: BLE001
            tok = None
    if tok:
        from utils.logging_setup import register_secret
        register_secret(tok)
        ctx.shared["auth_token"] = tok
    return tok


def load_openapi_paths(ctx: AuditContext) -> list[tuple[str, str]]:
    """Return [(method, path)] from a configured OpenAPI/Swagger document (GET-only paths used by scanners)."""
    if "openapi_paths" in ctx.shared:
        return ctx.shared["openapi_paths"]
    out: list[tuple[str, str]] = []
    src = ctx.config.get("openapi_url")
    if src:
        try:
            if src.startswith("http"):
                spec = ctx.client.get(src).json()
            else:
                with open(src, encoding="utf-8") as fh:
                    spec = json.load(fh)
            for path, ops in (spec.get("paths") or {}).items():
                for method in ops:
                    if method.lower() in ("get", "post", "put", "patch", "delete"):
                        out.append((method.upper(), path))
        except Exception:  # noqa: BLE001
            out = []
    ctx.shared["openapi_paths"] = out
    return out
