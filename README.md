# CreativeStall Security & Performance Audit Bot

Windows desktop app (PySide6) that runs a non-destructive security, API, marketplace, infrastructure and performance
audit of a website you are authorized to test, stores results in SQLite, and produces PDF + Excel reports.

## Install (end user, Windows 10/11 x64)
1. Run `CreativeStallAuditBot-Setup-1.0.0.exe` (built by `installer/build_windows.ps1`, see below).
2. Launch from the Desktop / Start Menu shortcut.
3. **New Audit** page: enter target URL, tick *I am authorized to test this target*, add test-account credentials,
   API token, PageSpeed API key and endpoint paths. Click **Save configuration** (secrets are encrypted with Windows DPAPI).
4. Click **Start Full Audit**. Progress, current module and elapsed time are shown live; Pause/Resume/Cancel work at any time.
5. When finished, PDF and Excel reports are written to `%LOCALAPPDATA%\CreativeStallAuditBot\reports` and listed on **Reports**.

## What runs
| Profile | Modules |
|---|---|
| Security | Discovery, security headers, TLS, deep TLS (testssl/SSL Labs, opt-in), OWASP ZAP passive (opt-in), CORS, CSP, public exposure, auth/session, API security, RBAC, IDOR, SQLi indicators, XSS, rate limit, asset protection, upload, bot protection, infrastructure |
| Performance | PageSpeed Insights (mobile+desktop), Lighthouse (if installed), API response times, asset delivery, JMeter (only if enabled) |
| Full | Both |

Modules with missing configuration are recorded as **Not Tested** (never as Passed). A module that crashes is recorded
as **failed** with its error and the audit continues.

## Safety guarantees
- Requests are restricted to the target's registrable domain (plus configured extra hosts) and throttled (default 5 req/s).
- SQL injection checks are error/boolean indicators only — no UNION, stacked queries, data extraction or modification.
- Upload tests use harmless files and are off unless explicitly allowed; stored XSS is manual-only.
- JMeter load tests are disabled by default; production requires explicit confirmation, a user ceiling and an emergency
  stop on error rate.
- Secrets never appear in logs, the database or reports (registered-secret + token/password redaction).

## Optional dependencies
| Component | Purpose | Install |
|---|---|---|
| Google PageSpeed API key | Avoids HTTP 429 quota errors | Google Cloud console → PageSpeed Insights API |
| Playwright Chromium | DOM XSS checks | bundled by installer; or Settings → *Install Playwright Chromium* |
| Node.js + Lighthouse | Local Lighthouse | `npm install -g lighthouse` |
| Java + Apache JMeter | Load tests | install JMeter, add `bin` to PATH or set `JMETER_HOME` |
| OWASP ZAP | Spider + passive scan (no active attacks) | install ZAP, run `zap.bat -daemon -port 8080 -config api.key=<key>`, enable in New Audit → External security tools |
| testssl.sh | Deep TLS checks | needs bash (Git Bash/WSL); set its path in External security tools |
| Qualys SSL Labs | Public TLS grade (publish=off) | register an email at https://api.ssllabs.com/api/v4/register |

**Settings → Validate environment** shows what is present and how to fix anything missing.

## Build from source
```powershell
# Windows, from repo root (requires Python 3.10+ x64 and Inno Setup 6)
powershell -ExecutionPolicy Bypass -File installer\build_windows.ps1
```
Runs the test suite, builds `dist\CreativeStallAuditBot\CreativeStallAuditBot.exe` with PyInstaller, bundles Chromium,
self-tests the exe (`--self-test`) and compiles `dist\installer\CreativeStallAuditBot-Setup-1.0.0.exe`.

Development / tests (any OS):
```bash
python -m venv .venv && . .venv/bin/activate && pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen python -m pytest      # all tests use a local mock marketplace, no live site
python main.py
```

## Troubleshooting
| Symptom | Fix |
|---|---|
| "Cannot start audit: Internet connectivity" | Check proxy/firewall; the target must be reachable on its port |
| PageSpeed "quota exceeded (HTTP 429)" | Add a PageSpeed API key in New Audit → Credentials |
| Many auth/API checks "Not Tested" | Fill API base URL, login endpoint, test account and endpoint paths |
| "Lighthouse CLI not found" / "JMeter not found" | Optional — install per table above or ignore |
| Credentials lost after copying profile to another PC | Expected: DPAPI keys are per Windows user; re-enter them |
| Logs | `%LOCALAPPDATA%\CreativeStallAuditBot\logs` (Settings → Open logs folder) |

## Interpreting results
Findings carry a verification status: **Confirmed** (direct evidence captured), **Unverified/Needs Manual Verification**
(indicator only). Prior-assessment items (26 gaps) are shown as context in reports and are not counted as newly
confirmed unless a module reproduced them. Category scores = pass rate of executed checks minus severity penalties;
categories with no executed checks show "Not tested".
