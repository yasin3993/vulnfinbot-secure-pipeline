# Mini-VulnFinBot — Secure CI/CD Pipeline

Mini-VulnFinBot is a simplified AI-powered financial assistant (Flask REST API with a
mock LLM) used to demonstrate a production-grade CI/CD pipeline with integrated
security testing: SAST, dependency scanning, container scanning, DAST and
AI-specific (prompt-injection) tests.

## Technologies

| Technology | Purpose |
|---|---|
| Python 3.12, Flask, gunicorn | Application |
| pytest | Unit and AI security tests |
| GitHub Actions | CI/CD automation |
| Bandit, Semgrep (custom rules) | SAST |
| pip-audit | Dependency vulnerability scanning |
| Docker, Trivy | Containerization and image scanning |
| OWASP ZAP baseline | DAST |
| GitHub Actions Artifacts | Security report storage |

## Architecture

```
Client ──HTTP/JSON──▶ Flask app (app/routes.py)
                       ├─ input validation (type, empty, length ≤ 500, JSON)
                       ├─ prompt-injection filter (detect_injection)
                       ├─ tool allow-list (authorize_tool)  ──▶ 403 for privileged tools
                       ├─ mock LLM (mock_llm)
                       └─ output validator (validate_output: HTML escape, secret redaction)
                     + security headers, generic error handlers (no stack traces)
```

```
app/                      Flask application (factory + routes)
tests/test_app.py         Functional/validation unit tests
tests/test_ai_security.py AI-specific security tests
security/semgrep/rules.yml Custom Semgrep rules
security/generate_ai_report.py Generates reports/ai-security-report.md
.github/workflows/security-pipeline.yml CI/CD pipeline
Dockerfile, .dockerignore Container build (non-root user, gunicorn)
```

## API

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | `{"status": "healthy"}` |
| POST | `/api/chat` | body `{"message": "..."}` → `{"response": "..."}` |

Error codes: `400` invalid/missing/empty/wrong type, `413` message too long,
`415` wrong content type, `403` tool not permitted, `404/405` generic JSON errors.

## Install & run

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python run.py                   # http://localhost:5000/health
```

Docker:

```bash
docker build -t vulnfinbot:latest .
docker run -d -p 5000:5000 vulnfinbot:latest
curl http://localhost:5000/health
```

## Tests

```bash
pytest -v                               # all tests
pytest tests/test_ai_security.py -v     # AI security tests
python security/generate_ai_report.py   # AI security report
```

## Security scans (local)

```bash
bandit -r app/ -f json -o reports/bandit-report.json
semgrep scan --config security/semgrep/rules.yml --json --output reports/semgrep-report.json app/
pip-audit -r requirements.txt -f json -o reports/dependency-report.json
trivy image --format json --output reports/trivy-report.json vulnfinbot:latest
docker run --rm --network host -v "$(pwd)/reports:/zap/wrk/:rw" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:5000 -J zap-report.json
```

## CI/CD pipeline

`.github/workflows/security-pipeline.yml` runs on every push and pull request to `main`:

1. **tests** — checkout, Python 3.12, install deps, unit tests, AI security tests,
   AI report (also written to the job summary), upload `test-reports` artifact.
2. **security-scans** — Bandit, Semgrep, pip-audit, Docker build, Trivy, start the
   container, OWASP ZAP baseline, upload `vulnfinbot-security-reports` artifact.

Scanner steps use `continue-on-error: true` and the upload step uses `if: always()`
so that reports from earlier steps are always uploaded.

## Accessing reports

GitHub → **Actions** → select a run → **Artifacts** → download
`vulnfinbot-security-reports` (bandit, semgrep, dependency, trivy, zap, ai-security).

## Identified vulnerabilities and remediation

| Tool | Finding | Remediation |
|---|---|---|
| pip-audit | Old Flask/Werkzeug/gunicorn pins had known CVEs | Upgraded to patched versions |
| Bandit / Semgrep (vuln-test branch) | `eval()`, `shell=True`, hardcoded password, MD5, `debug=True` | Removed / replaced with safe APIs |
| Trivy | OS package CVEs in `python:3.12-slim` base image | Rebuild regularly on latest slim base, non-root user |
| OWASP ZAP | Missing security headers | Added CSP, X-Frame-Options, nosniff, etc. |
| AI tests | Prompt injection, prompt leakage, excessive agency, XSS in output | Input filter, server-side tool allow-list, output escaping and redaction |

> The mock LLM only proves application-level controls. Real prompt-injection
> resistance must be tested against a real model in an isolated environment.
