"""TLSScanner: certificate validity, protocol versions, weak ciphers (local socket checks, optional SSL Labs)."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from core.models import CheckStatus, Severity
from scanners.base import AuditContext, BaseScanner

WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon")


def _probe(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> tuple[bool, str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, ssl.SSLError) as exc:
        return False, f"unsupported locally: {exc}"
    if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return True, f"{tls.version()} {tls.cipher()[0] if tls.cipher() else ''}"
    except (ssl.SSLError, OSError) as exc:
        return False, str(exc)


class TLSScanner(BaseScanner):
    name = "TLSScanner"
    description = "Certificate validity/expiry, hostname match, supported TLS versions and negotiated cipher."

    def execute(self, ctx: AuditContext) -> None:
        p = urlparse(ctx.target_url)
        host, port = p.hostname or "", p.port or 443
        timeout = float(ctx.config.get("timeout", 15))
        ctx.client.check_control()
        self._certificate(host, port, timeout)
        self._protocols(host, port, timeout)

    def _certificate(self, host: str, port: int, timeout: float) -> None:
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher()
                    version = tls.version()
        except ssl.SSLCertVerificationError as exc:
            self.check("Certificate valid and trusted", CheckStatus.FAILED, str(exc))
            self.finding("TLS certificate validation failed", Severity.HIGH, f"https://{host}",
                         "The certificate chain could not be validated by a standard trust store.", str(exc),
                         "Browsers will show warnings; users may be trained to accept MITM certificates.",
                         "Install a valid certificate chain from a trusted CA including intermediates.")
            return
        except OSError as exc:
            self.check("Certificate valid and trusted", CheckStatus.ERROR, f"Connection failed: {exc}")
            self.result.error = f"TLS connection failed: {exc}"
            return
        self.check("Certificate valid and trusted", CheckStatus.PASSED, f"Negotiated {version} / {cipher[0]}")
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (not_after - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        self.metric("Certificate days to expiry", days, "days")
        self.metric("Certificate issuer", issuer.get("organizationName", issuer.get("commonName", "?")))
        self.metric("Negotiated TLS version", version)
        self.metric("Negotiated cipher", cipher[0])
        if days < 14:
            sev, st = Severity.HIGH, CheckStatus.FAILED
        elif days < 30:
            sev, st = Severity.MEDIUM, CheckStatus.FAILED
        else:
            sev, st = None, CheckStatus.PASSED
        self.check("Certificate expiry > 30 days", st, f"{days} days remaining (notAfter {cert['notAfter']})")
        if sev:
            self.finding("TLS certificate expiring soon", sev, f"https://{host}", f"Certificate expires in {days} days.",
                         f"notAfter={cert['notAfter']}", "Expiry causes full site outage and browser errors.",
                         "Renew the certificate and enable automated renewal.")
        if any(m in cipher[0] for m in WEAK_CIPHER_MARKERS):
            self.check("Negotiated cipher is strong", CheckStatus.FAILED, cipher[0])
            self.finding("Weak TLS cipher negotiated", Severity.MEDIUM, f"https://{host}",
                         "The default negotiated cipher suite is considered weak.", cipher[0],
                         "Traffic may be decryptable by capable attackers.", "Disable weak cipher suites.")
        else:
            self.check("Negotiated cipher is strong", CheckStatus.PASSED, cipher[0])

    def _protocols(self, host: str, port: int, timeout: float) -> None:
        legacy = []
        for label, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            ok, detail = _probe(host, port, ver, timeout)
            if "unsupported locally" in detail:
                self.check(f"{label} disabled", CheckStatus.NOT_TESTED,
                           "Local OpenSSL cannot offer this protocol; verify with SSL Labs/testssl.sh")
            elif ok:
                legacy.append(label)
                self.check(f"{label} disabled", CheckStatus.FAILED, detail)
            else:
                self.check(f"{label} disabled", CheckStatus.PASSED, "Handshake refused")
        for label, ver in (("TLS 1.2", ssl.TLSVersion.TLSv1_2), ("TLS 1.3", ssl.TLSVersion.TLSv1_3)):
            ok, detail = _probe(host, port, ver, timeout)
            self.metric(f"{label} supported", "yes" if ok else "no", context=detail[:120])
        if legacy:
            self.finding("Legacy TLS protocol versions enabled", Severity.MEDIUM, f"https://{host}",
                         "The server accepts deprecated TLS versions.", "Accepted: " + ", ".join(legacy),
                         "Deprecated protocols have known weaknesses (BEAST, POODLE-class) and fail PCI DSS.",
                         "Disable TLS 1.0 and 1.1; support TLS 1.2 and 1.3 only.",
                         reproduction_steps=f"openssl s_client -connect {host}:{port} -tls1")
