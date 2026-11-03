"""AuthenticationTester and SessionSecurityTester."""
from __future__ import annotations

import secrets
from http.cookies import SimpleCookie

from core.models import Category, CheckStatus, Severity, VerificationStatus
from scanners.api.common import api_url, auth_headers, get_token
from scanners.base import AuditContext, BaseScanner


class AuthenticationTester(BaseScanner):
    name = "AuthenticationTester"
    category = Category.API_SECURITY
    description = "Login validation, invalid credentials, account enumeration, brute-force / rate limiting."
    requires = ("login_endpoint",)

    def execute(self, ctx: AuditContext) -> None:
        url = api_url(ctx, ctx.config["login_endpoint"])
        ufield = ctx.config.get("login_user_field", "email")
        pfield = ctx.config.get("login_pass_field", "password")
        known_user = ctx.config.get("login_username")
        fake_user = f"csab-nonexistent-{secrets.token_hex(4)}@example.com"
        bad_pw = "Wrong-" + secrets.token_hex(6)

        r_unknown = ctx.client.post(url, json={ufield: fake_user, pfield: bad_pw})
        self.check("Invalid credentials rejected", CheckStatus.PASSED if r_unknown.status_code in (400, 401, 403)
                   else CheckStatus.FAILED, f"HTTP {r_unknown.status_code}")
        if r_unknown.status_code == 200 and "token" in r_unknown.text.lower():
            self.finding("Login accepts invalid credentials", Severity.CRITICAL, url,
                         "A login with a non-existent user and random password returned a token.",
                         f"POST {url} ({ufield}=<random>) -> 200 with token", "Full authentication bypass.",
                         "Fix credential validation logic.", reproduction_steps="Submit random credentials to the login API.")

        if known_user:
            r_known = ctx.client.post(url, json={ufield: known_user, pfield: bad_pw})
            diff_status = r_known.status_code != r_unknown.status_code
            diff_body = _normalize(r_known.text) != _normalize(r_unknown.text.replace(fake_user, known_user))
            evidence = (f"Unknown user -> HTTP {r_unknown.status_code}: {r_unknown.text[:150]}\n"
                        f"Known user (wrong password) -> HTTP {r_known.status_code}: {r_known.text[:150]}")
            if diff_status or diff_body:
                self.check("No account enumeration via login responses", CheckStatus.FAILED, evidence)
                self.finding("Account enumeration via login response", Severity.MEDIUM, url,
                             "The login API responds differently for existing vs non-existing accounts.", evidence,
                             "Attackers can build lists of valid marketplace accounts for credential stuffing.",
                             "Return an identical generic error and status for all failed logins.",
                             reproduction_steps="Submit a wrong password for a known and an unknown email; compare.")
            else:
                self.check("No account enumeration via login responses", CheckStatus.PASSED, evidence)
        else:
            self.check("No account enumeration via login responses", CheckStatus.NOT_TESTED, "No test username configured")

        attempts = max(3, min(int(ctx.config.get("bruteforce_attempts", 8)), 20))
        target_user = known_user or fake_user
        codes = []
        for _ in range(attempts):
            r = ctx.client.post(url, json={ufield: target_user, pfield: "Wrong-" + secrets.token_hex(6)})
            codes.append(r.status_code)
            if r.status_code in (423, 429) or "captcha" in r.text.lower() or "locked" in r.text.lower():
                break
        throttled = any(c in (423, 429) for c in codes)
        evidence = f"{len(codes)} failed attempts for one account -> status codes {codes}"
        if throttled:
            self.check("Brute-force protection / login rate limiting", CheckStatus.PASSED, evidence)
        else:
            self.check("Brute-force protection / login rate limiting", CheckStatus.FAILED, evidence)
            self.finding("No observable login rate limiting", Severity.HIGH, url,
                         f"{len(codes)} consecutive failed logins were accepted without throttling, lockout or CAPTCHA.",
                         evidence, "Enables brute-force and credential-stuffing attacks against marketplace accounts.",
                         "Add per-account and per-IP throttling, progressive delays and CAPTCHA after repeated failures.",
                         verification_status=VerificationStatus.UNVERIFIED,
                         reproduction_steps=f"Send {attempts} wrong-password logins for one account and observe responses.")

        tok = get_token(ctx)
        self.check("Configured test account can authenticate", CheckStatus.PASSED if tok else CheckStatus.NOT_TESTED,
                   "Token obtained" if tok else "No token configured/obtained")
        self.check("Password reset security", CheckStatus.MANUAL,
                   "Verify reset tokens are single-use, expire quickly and responses do not enumerate accounts.")
        self.check("OAuth (Microsoft/Google) state & redirect_uri validation", CheckStatus.MANUAL,
                   "Verify state parameter, strict redirect_uri allow-list and account-linking behaviour manually.")


def _normalize(t: str) -> str:
    return "".join(t.lower().split())[:300]


class SessionSecurityTester(BaseScanner):
    name = "SessionSecurityTester"
    category = Category.API_SECURITY
    description = "Cookie flags, token acceptance after logout, invalid/expired token handling."

    def execute(self, ctx: AuditContext) -> None:
        cookies = []
        resp = ctx.shared.get("landing_response") or ctx.client.get(ctx.target_url)
        cookies += resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist") else []
        if not cookies and resp.headers.get("Set-Cookie"):
            cookies.append(resp.headers["Set-Cookie"])
        if ctx.config.get("login_endpoint") and ctx.config.get("login_username") and ctx.secrets.get("login_password"):
            r = ctx.client.post(api_url(ctx, ctx.config["login_endpoint"]),
                                json={ctx.config.get("login_user_field", "email"): ctx.config["login_username"],
                                      ctx.config.get("login_pass_field", "password"): ctx.secrets["login_password"]})
            if r.headers.get("Set-Cookie"):
                cookies.append(r.headers["Set-Cookie"])
        self._cookies(ctx, cookies)
        self._token_handling(ctx)

    def _cookies(self, ctx, raw_cookies):
        if not raw_cookies:
            self.check("Session cookie attributes", CheckStatus.NOT_APPLICABLE, "No cookies set by observed responses")
            return
        secure_site = ctx.target_url.startswith("https")
        for raw in raw_cookies:
            c = SimpleCookie()
            try:
                c.load(raw)
            except Exception:  # noqa: BLE001
                continue
            low = raw.lower()
            for name in c:
                missing = []
                if secure_site and "secure" not in low:
                    missing.append("Secure")
                if "httponly" not in low:
                    missing.append("HttpOnly")
                if "samesite" not in low:
                    missing.append("SameSite")
                label = f"Cookie '{name}' attributes"
                if missing:
                    self.check(label, CheckStatus.FAILED, "Missing: " + ", ".join(missing))
                    sensitive = any(k in name.lower() for k in ("sess", "auth", "token", "asp", "jwt", "id"))
                    self.finding(f"Cookie '{name}' missing {', '.join(missing)}",
                                 Severity.MEDIUM if sensitive else Severity.LOW, ctx.target_url,
                                 f"The cookie '{name}' is set without: {', '.join(missing)}.",
                                 f"Set-Cookie: {name}=[REDACTED]; flags observed: "
                                 f"{[f for f in ('Secure', 'HttpOnly', 'SameSite') if f.lower() in low]}",
                                 "Session cookies may be stolen via XSS, sent over HTTP, or used in CSRF.",
                                 "Set Secure; HttpOnly; SameSite=Lax (or Strict) on session/auth cookies.")
                else:
                    self.check(label, CheckStatus.PASSED, "Secure, HttpOnly, SameSite present")

    def _token_handling(self, ctx):
        probe = ctx.config.get("auth_probe_endpoint") or "/api/me"
        url = api_url(ctx, probe)
        tok = get_token(ctx)
        if not tok:
            self.check("Invalid token rejected", CheckStatus.NOT_TESTED, "No API token configured")
            self.check("Session invalidated after logout", CheckStatus.NOT_TESTED, "No API token configured")
            return
        ok = ctx.client.get(url, headers=auth_headers(tok))
        if ok.status_code >= 400:
            self.check("Authenticated probe endpoint reachable", CheckStatus.NOT_TESTED,
                       f"{probe} returned HTTP {ok.status_code} with token; set 'auth_probe_endpoint'")
            return
        bad = ctx.client.get(url, headers=auth_headers(tok[:-4] + "abcd" if len(tok) > 8 else "invalid"))
        none = ctx.client.get(url)
        for label, r in (("Tampered token rejected", bad), ("Request without token rejected", none)):
            if r.status_code in (401, 403):
                self.check(label, CheckStatus.PASSED, f"HTTP {r.status_code}")
            else:
                self.check(label, CheckStatus.FAILED, f"HTTP {r.status_code}")
                self.finding(f"API accepts {'tampered' if r is bad else 'missing'} token", Severity.CRITICAL, url,
                             "The authenticated endpoint returned data without a valid token.",
                             f"GET {url} -> HTTP {r.status_code}: {r.text[:150]}", "Authentication bypass on the API.",
                             "Validate token signature, expiry and presence on every protected endpoint.")
        logout = ctx.config.get("logout_endpoint")
        if logout:
            ctx.client.post(api_url(ctx, logout), headers=auth_headers(tok))
            after = ctx.client.get(url, headers=auth_headers(tok))
            if after.status_code in (401, 403):
                self.check("Session invalidated after logout", CheckStatus.PASSED, f"HTTP {after.status_code}")
            else:
                self.check("Session invalidated after logout", CheckStatus.FAILED, f"HTTP {after.status_code}")
                self.finding("Token remains valid after logout", Severity.MEDIUM, url,
                             "The access token still works after calling the logout endpoint.",
                             f"POST {logout}; then GET {url} -> HTTP {after.status_code}",
                             "Stolen tokens stay usable; users cannot terminate sessions.",
                             "Revoke server-side sessions/refresh tokens on logout and use short-lived access tokens.",
                             verification_status=VerificationStatus.UNVERIFIED)
            ctx.shared.pop("auth_token", None)
        else:
            self.check("Session invalidated after logout", CheckStatus.NOT_TESTED, "No logout_endpoint configured")
        self.check("Session expiration", CheckStatus.MANUAL,
                   "Verify access-token lifetime (JWT exp) and idle timeout against policy.")
