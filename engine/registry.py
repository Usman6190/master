"""Module registry and audit-type profiles."""
from __future__ import annotations

from scanners.api.access import APISecurityScanner, IDORTester, RateLimitTester, RBACScanner
from scanners.api.auth import AuthenticationTester, SessionSecurityTester
from scanners.assets.marketplace import AssetProtectionScanner, BotProtectionScanner, UploadSecurityTester
from scanners.base import BaseScanner
from scanners.infrastructure.infrastructure import InfrastructureScanner
from scanners.performance.performance import (APIResponseAnalyzer, AssetDeliveryAnalyzer, JMeterController,
                                              LighthouseAnalyzer, PageSpeedAnalyzer)
from scanners.security.cors import CORSScanner
from scanners.security.csp import CSPScanner
from scanners.security.discovery import WebsiteDiscovery
from scanners.security.exposure import PublicExposureScanner
from scanners.security.headers import SecurityHeadersScanner
from scanners.security.injection import InjectionScanner, XSSScanner
from scanners.security.tls import TLSScanner

from scanners.security.external_tools import TLSDeepScanner, ZAPScanner  # noqa: E402

SECURITY_MODULES: list[type[BaseScanner]] = [
    WebsiteDiscovery, SecurityHeadersScanner, TLSScanner, TLSDeepScanner, CORSScanner, CSPScanner,
    PublicExposureScanner, ZAPScanner,
]
API_MODULES: list[type[BaseScanner]] = [
    AuthenticationTester, SessionSecurityTester, APISecurityScanner, RBACScanner, IDORTester,
    InjectionScanner, XSSScanner, RateLimitTester,
]
MARKETPLACE_MODULES: list[type[BaseScanner]] = [AssetProtectionScanner, UploadSecurityTester, BotProtectionScanner]
PERFORMANCE_MODULES: list[type[BaseScanner]] = [
    PageSpeedAnalyzer, LighthouseAnalyzer, APIResponseAnalyzer, AssetDeliveryAnalyzer, JMeterController,
]
INFRA_MODULES: list[type[BaseScanner]] = [InfrastructureScanner]


def modules_for(audit_type: str) -> list[type[BaseScanner]]:
    if audit_type == "security":
        mods = SECURITY_MODULES + API_MODULES + MARKETPLACE_MODULES + INFRA_MODULES
    elif audit_type == "performance":
        mods = [WebsiteDiscovery] + PERFORMANCE_MODULES
    else:
        mods = SECURITY_MODULES + API_MODULES + MARKETPLACE_MODULES + PERFORMANCE_MODULES + INFRA_MODULES
    return list(dict.fromkeys(mods))


def all_modules() -> list[type[BaseScanner]]:
    return modules_for("full")
