# Cassette

**Cassette** is a command-line deterministic HTTP/Webhook interaction recorder, credential sanitizer, contract differ, and local replay mock server for Python integration suites.

Integration tests that hit live third-party APIs (Stripe, GitHub, Twilio, internal microservices) are slow, rate-limited, brittle in offline CI, and prone to leaking live bearer tokens when developers commit raw HTTP fixtures. **Cassette** canonicalizes HTTP requests into deterministic SHA-256 fingerprints, replays recorded responses in <1ms over a local HTTP server with nearest-miss diagnostics, audits cassettes for leaked credentials or stale recordings, and diffs cassette versions to catch silent upstream API contract drift.

---

## Who It's For

- **Backend and integration engineers** replaying external REST and Webhook interactions deterministically in local development and CI pipelines.
- **Platform and QA teams** auditing recorded HTTP test fixtures for leaked secrets (`CS001`), stale recordings (`CS003`), and upstream response schema drift.

---

## What It's Built With

- **Language:** Python 3.10+
- **Core Architecture:** Pure Python standard library (`http.server`, `urllib.parse`, `hashlib`, `json`, `argparse`, `unittest`) with **zero external runtime dependencies**.
- **Test Suite:** Compatible with both `pytest` and `python -m unittest`.

---

## Features

- **Order-Insensitive SHA-256 Request Fingerprinting (`matcher.py`):** Normalizes HTTP methods, URL paths, sorted query parameters, and canonicalized JSON request bodies so equivalent payloads always produce the same 16-char digest.
- **Local Multi-Threaded HTTP Replay Server (`cassette serve`):** Serves recorded interactions over `http.server.ThreadingHTTPServer` with optional latency simulation (`--latency-ms`) and fault injection (`--chaos-status 503`), returning structured nearest-match diff diagnostics on a `404` cache miss.
- **Automated Credential Redaction (`cassette sanitize`):** Scrubs `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Bearer` tokens, and sensitive query parameters (`api_key`, `access_token`, `client_secret`) into `[REDACTED]`.
- **Built-in Cassette Hygiene Rules (`CS001` – `CS005`):**
  - `CS001` (`CRITICAL` / `unredacted-auth-secret`): Detects unmasked `Authorization`, `Cookie`, `X-Api-Key`, or `Bearer` credentials inside cassette headers or query strings.
  - `CS002` (`HIGH` / `nondeterministic-duplicate-request`): Flags identical request fingerprints recorded multiple times with conflicting status codes or response bodies.
  - `CS003` (`HIGH` / `stale-cassette-recording`): Flags interactions older than `--max-age-days` (default `90` days) that risk silent upstream drift.
  - `CS004` (`MEDIUM` / `captured-5xx-server-error`): Flags unintentional upstream `5xx` responses stored without `"chaos_expected": true`.
  - `CS005` (`LOW` / `missing-content-type-header`): Flags non-empty response bodies missing an explicit `Content-Type` header.
- **Cassette-to-Cassette Contract Differ (`cassette diff`):** Compares baseline and candidate cassettes to highlight status code mutations, removed endpoints, and dropped JSON response keys.

---

## CLI Preview

```text
$ cassette audit cassettes/stripe_checkout.json
Cassette Hygiene Audit: cassettes/stripe_checkout.json (2 interaction(s) scanned)
================================================================================
[CS001] (CRITICAL | unredacted-auth-secret) step-001 @ POST /v1/charges
  Issue:  Unredacted credential(s) in header:Authorization.
  Advice: Run `cassette sanitize` to mask sensitive headers and query parameters.
--------------------------------------------------------------------------------
[CS003] (HIGH | stale-cassette-recording) step-001 @ POST /v1/charges
  Issue:  Interaction recorded 321 days ago (2026-01-01T00:00:00Z) exceeds max age of 90 days.
  Advice: Refresh the cassette against the current upstream service.
--------------------------------------------------------------------------------
Summary: 2 finding(s) (critical=1, high=1, medium=0, low=0)
```

---

## How to Run It

### 1. Install

```bash
git clone https://github.com/Dharmogata/cassette.git
cd cassette
pip install -e .
```

### 2. Inspect, Sanitize, Audit, Diff, and Replay

```bash
# Inspect recorded HTTP interactions
cassette inspect cassettes/stripe_checkout.json

# Mask leaked Authorization headers and query tokens in place
cassette sanitize cassettes/stripe_checkout.json

# Audit a directory of cassettes in CI
cassette audit cassettes/ --max-age-days 90 --fail-on-findings

# Compare two cassette versions for API contract drift
cassette diff cassettes/v1.json cassettes/v2.json --format markdown

# Start local HTTP replay server on port 8080
cassette serve cassettes/stripe_checkout.json --port 8080 --latency-ms 25
```

### 3. Run the Test Suite

```bash
python -m unittest discover -s tests -v
```

---

## License

MIT License — see [LICENSE](LICENSE).
