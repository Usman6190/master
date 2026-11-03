"""CORSScanner: tests origin reflection, null origin, credentials with wildcard."""
from __future__ import annotations

from core.models import Category, CheckStatus, Severity
from scanners.base import AuditContext, BaseScanner

EVIL = "https://cors-audit-probe.example"


class CORSScanner(BaseScanner):
    name = "CORSScanner"
    description = "Checks whether arbitrary or null origins are trusted by the site and API."

    def execute(self, ctx: AuditContext) -> None:
        targets = [ctx.target_url]
        api = ctx.config.get("api_base_url")
        if api:
            targets.append(api)
        for path in ctx.shared.get("api_paths", [])[:3]:
            targets.append((api or ctx.target_url).rstrip("/") + path if path.startswith("/") else path)
        for url in dict.fromkeys(targets):
            self._test(ctx, url)

    def _test(self, ctx: AuditContext, url: str) -> None:
        cat = Category.API_SECURITY if url != ctx.target_url else Category.SECURITY
        try:
            for origin in (EVIL, "null"):
                r = ctx.client.get(url, headers={"Origin": origin}, allow_redirects=False)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                pre = ctx.client.options(url, headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
                                         allow_redirects=False)
                p_acao = pre.headers.get("Access-Control-Allow-Origin", "")
                p_acac = pre.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
                reflected = origin in (acao, p_acao)
                creds = acac or p_acac
                evidence = (f"Request Origin: {origin}\nGET -> ACAO: {acao or '-'}, ACAC: {acac}\n"
                            f"OPTIONS -> ACAO: {p_acao or '-'}, ACAC: {p_acac}")
                name = f"CORS rejects untrusted origin '{origin}' ({url})"
                if reflected and creds:
                    self.check(name, CheckStatus.FAILED, evidence, cat)
                    self.finding("CORS trusts arbitrary origin with credentials", Severity.HIGH, url,
                                 f"The server reflects the untrusted Origin '{origin}' and allows credentials.",
                                 evidence, "Any website can read authenticated responses on behalf of a logged-in user.",
                                 "Use a strict allow-list of origins; never reflect Origin with Allow-Credentials: true.",
                                 category=cat, reproduction_steps=f"curl -sI -H 'Origin: {origin}' {url}")
                elif reflected or "*" in (acao, p_acao) and creds:
                    self.check(name, CheckStatus.FAILED, evidence, cat)
                    self.finding("Permissive CORS policy", Severity.MEDIUM, url,
                                 f"The server trusts the untrusted Origin '{origin}'.", evidence,
                                 "Cross-origin sites can read responses (unauthenticated data, API structure).",
                                 "Restrict Access-Control-Allow-Origin to an explicit allow-list.", category=cat,
                                 reproduction_steps=f"curl -sI -H 'Origin: {origin}' {url}")
                elif "*" in (acao, p_acao):
                    self.check(name, CheckStatus.PASSED, evidence + "\n(wildcard without credentials)", cat)
                else:
                    self.check(name, CheckStatus.PASSED, evidence, cat)
        except Exception as exc:  # noqa: BLE001
            self.check(f"CORS test ({url})", CheckStatus.ERROR, str(exc), cat)
