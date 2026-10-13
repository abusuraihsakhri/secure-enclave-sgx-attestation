# Secure Enclave SGX Attestation

A Python research demonstrator for **rule-based security telemetry classification**, with a separate browser-only interface. Despite the historical repository name, **this code does not perform Intel SGX or AMD SEV-SNP hardware attestation**. It does not validate quotes, MRENCLAVE/MRSIGNER, collateral, certificate chains, report data, revocation status, freshness, or attested TLS. Do not use classification results as trust evidence.

## What works

- Three deterministic checks in `agents/workers.py`: primary metric above 25, secondary metric above 12 or an explicit critical flag, and anomaly keywords in a status descriptor.
- Classification as `ROUTINE`, `ELEVATED_RISK` or `CRITICAL_STAT_PANIC`, with machine-readable dossiers.
- CLI single evaluation, CSV batch mode, interactive query-mock command, simulation, and a FastAPI interface.
- Process-local HMAC-SHA256 chained audit entries, verified by recalculating signatures. The chain is **not persistent, externally anchored, or protected by an enclave**.
- Best-effort sensitive-identifier pattern screening; **not** complete PHI detection, HIPAA de-identification, or compliance certification.
- Self-contained browser demo in `web/`; no remote API, login, data upload, or WebAssembly runtime.

The older `enclave_guard/` entry points remain for compatibility and use **different secondary thresholds**. The browser matches the newer `agents/` implementation only. The `enrichment.py` modules provide generic numerical threshold examples, not formal security or NIST compliance verification.

## Use the browser demo

The static browser application is in `web/index.html`. Run a local static server, then open `http://localhost:8080/`:

```bash
python -m http.server 8080 --directory web
```

Enter non-sensitive demonstration values, select **Evaluate locally**, and optionally export the JSON result. Everything is computed in-browser by `web/rules.mjs`; the export explicitly states that no cryptographic attestation occurred. The repository includes a GitHub Pages deployment workflow for `master`; a public Pages URL should only be advertised after the repository's Pages settings and live deployment are verified.

## Install and use Python

Python 3.9 or newer is required.

```bash
python -m pip install -e ".[api,test]"
python cli.py audit --task-id DEMO-01 --target SAMPLE-01 --primary 29.4 --secondary 14.8 --status DISCORDANT --critical
python cli.py chat Explain specifications
python cli.py batch --input sample.csv --output results.csv
python cli.py verify-audit
python simulator.py 100
```

CSV columns are `task_id,target_identifier,primary_metric,secondary_metric,is_critical_flag,status_descriptor`. Boolean values accept `true/false`, `yes/no` and `1/0`. Batch results contain classifications and **process-local** HMAC audit hashes. `verify-audit` checks only audit entries created in the current Python process, not earlier CLI executions.

The installed command `enclave-threshold-demo` invokes the root CLI. The historical `secure-enclave-sgx-attestation` entry point and `python enclave_guard_app.py` invoke the separate legacy CLI.

## Start the API

All endpoints other than `GET /health` require an `x-api-key` header equal to the `API_TOKEN` environment variable. No default token is supplied; without a configured token, protected routes return HTTP 503.

```bash
export API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
python cli.py serve --host 127.0.0.1 --port 8000
curl -H "x-api-key: $API_TOKEN" \
  -H "content-type: application/json" \
  -d '{"task_id":"DEMO","target_identifier":"TEST","primary_metric":10,"secondary_metric":4,"status_descriptor":"NOMINAL","is_critical_flag":false}' \
  http://127.0.0.1:8000/api/audit
```

Other endpoints: `POST /api/chat` (deterministic mock), `GET /metrics` (JSON), `GET /api/audit/logs` (in-memory chain), and `GET /health`. Neither mock chat nor the API performs enclave attestation.

## Docker

```bash
export API_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build
```

Compose publishes the API on `127.0.0.1:8000` only. For anything exposed beyond localhost, use TLS, authentication and network controls; the demo has no rate limiting or durable storage. The optional `AUDIT_SECRET_KEY` environment variable sets a stable HMAC key for the current process; otherwise a random key is generated at startup. **A stable key does not provide cross-process audit persistence** because no trail is saved. Replace any key previously copied from older repository configurations.

## Testing

```bash
python -m pytest -q
python -m compileall -q agents enclave_guard cli.py enrichment.py simulator.py
node --test web/tests/*.test.mjs
```

GitHub Actions tests Python 3.10–3.12 and the standalone browser rule module. A passing test suite demonstrates correct behavior of these **simulated rules**, not the security of SGX hardware or attestation infrastructure.

## Privacy and limitations

The browser version performs local calculations and retains only session-local state until reload. The Python API stores dossiers and hashed audit metadata in process memory; it is not suitable for protected health information or secrets. Identifier screening is regex-based and incomplete. Neither the browser nor the Python API should be treated as a secure enclave, confidential computing runtime, healthcare compliance control, or remote attestation verifier.

## Technology and license

Python, Pydantic 2, FastAPI, optional Uvicorn, plain HTML/CSS/JavaScript, and GitHub Actions. The browser demo uses modern ES modules supported by current Chrome, Firefox, Safari and Edge. Licensed under [MIT](LICENSE).
