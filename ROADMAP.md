# Cassette Engineering Roadmap (200+ Hours)

This roadmap outlines the planned evolution of **Cassette** from a deterministic HTTP cassette auditor, contract differ, and local replay server into a full-featured transparent recording proxy, stateful sequence machine, HAR/OpenAPI importer, and pytest fixture plugin.

---

## Phase 1: Core Fingerprint Matcher, Hygiene Auditor & Replay Server (Completed - v0.1.0)
- [x] Core data models (`RecordedRequest`, `RecordedResponse`, `CassetteInteraction`, `CassetteFile`, `MatchResult`, `CassetteFinding`, `ContractDiffItem`).
- [x] Deterministic SHA-256 request canonicalizer with order-insensitive query and JSON body normalization, plus nearest-miss diff diagnostics (`matcher.py`).
- [x] Credential sanitizer masking `Authorization`, `Cookie`, `X-Api-Key`, `Bearer` tokens, and sensitive query parameters.
- [x] Hygiene audit rules `CS001`–`CS005` and cassette-to-cassette contract differ (`audit.py`).
- [x] Multi-threaded local HTTP replay server (`CassetteReplayServer`) with latency and chaos fault injection (`server.py`).
- [x] CLI (`inspect`, `audit`, `sanitize`, `diff`, `serve`, `rules`) with `text`, `json`, and `markdown` outputs.

---

## Phase 2: Transparent Forward Proxy & Live Recording Mode (~40 Hours)
- [ ] **Pass-Through Recording Proxy (`cassette record --upstream https://api.stripe.com`):** Forward unmatched incoming requests to the live upstream origin, stream back responses, and append sanitized interactions to the cassette file on disk.
- [ ] **Record Modes (`once`, `new_episodes`, `none`, `all`):** Control whether new endpoints are recorded automatically or rejected in strict CI runs.
- [ ] **Binary & Compressed Payload Handling:** Support `gzip`/`deflate`/`br` decoding and base64-encoded binary response bodies (PDFs, images, protobufs).

---

## Phase 3: Stateful Sequence Replay & Dynamic Template Interpolation (~35 Hours)
- [ ] **Stateful Transition Chains:** Replay sequential responses for identical request signatures (e.g., polling `GET /v1/jobs/123` returning `PENDING` -> `RUNNING` -> `COMPLETED`).
- [ ] **Dynamic Response Templating:** Interpolate request path parameters, timestamps, and UUIDs into replayed response bodies.
- [ ] **Custom Field Ignore Rules:** Allow per-endpoint ignore lists for volatile request fields (e.g., `idempotency_key`, `timestamp`, `nonce`) during fingerprint calculation.

---

## Phase 4: HAR, cURL, and OpenAPI 3.1 Interoperability (~40 Hours)
- [ ] **Browser HAR Importer (`cassette import-har`):** Convert Chrome/Firefox DevTools `.har` archives directly into sanitized Cassette JSON files.
- [ ] **cURL Reproducer Generator (`cassette export-curl`):** Export any recorded interaction as a ready-to-run `curl` command.
- [ ] **OpenAPI 3.1 Schema Validator:** Cross-check recorded cassette responses against an OpenAPI specification to flag undocumented fields or status codes.

---

## Phase 5: Native `pytest` Plugin & `urllib`/`httpx` In-Process Interceptor (~45 Hours)
- [ ] **`@pytest.mark.cassette("checkout.json")` Fixture:** Automatic per-test cassette loading and assertion helpers without binding a TCP socket.
- [ ] **Transport-Level Hook (`urllib.request`, `http.client`):** Intercept outbound Python stdlib HTTP calls directly in memory.

---

## Phase 6: Interactive HTML Traffic Inspector & SARIF Export (~40 Hours)
- [ ] **Standalone HTML Cassette Explorer:** Single-file visual waterfall timeline showing request/response headers, formatted JSON diffs, and audit findings.
- [ ] **SARIF v2.1.0 Reporter (`--format sarif`):** Native integration with GitHub Code Scanning for leaked secret (`CS001`) and contract drift alerts.
