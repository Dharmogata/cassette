"""Cassette hygiene auditor (CS001-CS005) and cassette-to-cassette contract differ."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cassette.matcher import (
    BEARER_PATTERN,
    SENSITIVE_HEADER_NAMES,
    SENSITIVE_QUERY_KEYS,
    compute_request_fingerprint,
    load_cassette,
)
from cassette.models import (
    AuditReport,
    CassetteFile,
    CassetteFinding,
    ContractDiffItem,
    Severity,
)

RULES_CATALOG: list[dict[str, str]] = [
    {
        "rule_id": "CS001",
        "severity": "CRITICAL",
        "category": "unredacted-auth-secret",
        "description": "Unredacted authentication header, cookie, or secret token stored in cassette.",
        "remediation": "Run `cassette sanitize <file>` before committing cassettes to version control.",
    },
    {
        "rule_id": "CS002",
        "severity": "HIGH",
        "category": "nondeterministic-duplicate-request",
        "description": "Identical request fingerprint recorded multiple times with conflicting responses.",
        "remediation": "Deduplicate interactions or split distinct state transitions into separate cassettes.",
    },
    {
        "rule_id": "CS003",
        "severity": "HIGH",
        "category": "stale-cassette-recording",
        "description": "Recorded interaction timestamp is older than the configured maximum age threshold.",
        "remediation": "Re-record the cassette against the current upstream API to prevent contract drift.",
    },
    {
        "rule_id": "CS004",
        "severity": "MEDIUM",
        "category": "captured-5xx-server-error",
        "description": "Cassette contains a 5xx server error response without `chaos_expected: true`.",
        "remediation": "Mark intentional fault-injection steps with `\"chaos_expected\": true` or re-record.",
    },
    {
        "rule_id": "CS005",
        "severity": "LOW",
        "category": "missing-content-type-header",
        "description": "Non-empty HTTP response body is missing an explicit `Content-Type` header.",
        "remediation": "Include `Content-Type` (e.g. `application/json`) in recorded response headers.",
    },
]


def _parse_iso_date(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def audit_cassette(
    cassette: CassetteFile,
    *,
    target_name: str = "",
    reference_date: str = "2026-11-18T00:00:00Z",
    max_age_days: int = 90,
) -> AuditReport:
    """Run CS001-CS005 hygiene and determinism checks against a CassetteFile."""
    findings: list[CassetteFinding] = []
    ref_dt = _parse_iso_date(reference_date) or datetime(2026, 11, 18, tzinfo=timezone.utc)
    seen_by_fp: dict[str, tuple[str, int, str]] = {}

    for item in cassette.interactions:
        endpoint = f"{item.request.method} {item.request.path}"
        fp = item.fingerprint or compute_request_fingerprint(item.request)

        # CS001: unredacted secrets in headers or query
        leaked_keys: list[str] = []
        for k, v in {**item.request.headers, **item.response.headers}.items():
            if v != "[REDACTED]" and (
                k.lower() in SENSITIVE_HEADER_NAMES or BEARER_PATTERN.search(v)
            ):
                leaked_keys.append(f"header:{k}")
        for k, v in item.request.query.items():
            if v != "[REDACTED]" and k.lower() in SENSITIVE_QUERY_KEYS:
                leaked_keys.append(f"query:{k}")
        if leaked_keys:
            findings.append(
                CassetteFinding(
                    rule_id="CS001",
                    severity=Severity.CRITICAL,
                    category="unredacted-auth-secret",
                    interaction_id=item.interaction_id,
                    endpoint=endpoint,
                    message=f"Unredacted credential(s) in {', '.join(leaked_keys)}.",
                    advice="Run `cassette sanitize` to mask sensitive headers and query parameters.",
                )
            )

        # CS002: duplicate request fingerprint with conflicting response
        if fp in seen_by_fp:
            prev_id, prev_status, prev_body = seen_by_fp[fp]
            if prev_status != item.response.status or prev_body != item.response.body:
                findings.append(
                    CassetteFinding(
                        rule_id="CS002",
                        severity=Severity.HIGH,
                        category="nondeterministic-duplicate-request",
                        interaction_id=item.interaction_id,
                        endpoint=endpoint,
                        message=(
                            f"Duplicate request fingerprint '{fp}' conflicts with '{prev_id}' "
                            f"(status {prev_status} vs {item.response.status})."
                        ),
                        advice="Keep one deterministic response per request signature or separate stateful scenarios.",
                    )
                )
        else:
            seen_by_fp[fp] = (item.interaction_id, item.response.status, item.response.body)

        # CS003: stale recording
        rec_dt = _parse_iso_date(item.recorded_at)
        if rec_dt is not None:
            age_days = (ref_dt - rec_dt).days
            if age_days > max_age_days:
                findings.append(
                    CassetteFinding(
                        rule_id="CS003",
                        severity=Severity.HIGH,
                        category="stale-cassette-recording",
                        interaction_id=item.interaction_id,
                        endpoint=endpoint,
                        message=(
                            f"Interaction recorded {age_days} days ago ({item.recorded_at}) "
                            f"exceeds max age of {max_age_days} days."
                        ),
                        advice="Refresh the cassette against the current upstream service.",
                    )
                )

        # CS004: unexpected 5xx response
        if 500 <= item.response.status <= 599 and not item.chaos_expected:
            findings.append(
                CassetteFinding(
                    rule_id="CS004",
                    severity=Severity.MEDIUM,
                    category="captured-5xx-server-error",
                    interaction_id=item.interaction_id,
                    endpoint=endpoint,
                    message=f"Recorded upstream {item.response.status} error without `chaos_expected: true`.",
                    advice="Set `\"chaos_expected\": true` if testing fault recovery, or re-record a healthy response.",
                )
            )

        # CS005: missing Content-Type on non-empty body
        has_ct = any(k.lower() == "content-type" for k in item.response.headers)
        if item.response.body.strip() and not has_ct:
            findings.append(
                CassetteFinding(
                    rule_id="CS005",
                    severity=Severity.LOW,
                    category="missing-content-type-header",
                    interaction_id=item.interaction_id,
                    endpoint=endpoint,
                    message="Response has a non-empty body but no `Content-Type` header.",
                    advice="Add `Content-Type: application/json` (or appropriate MIME type) to response headers.",
                )
            )

    return AuditReport(
        target=target_name or cassette.name,
        total_interactions=len(cassette.interactions),
        findings=findings,
    )


def audit_path(
    path: Path,
    *,
    reference_date: str = "2026-11-18T00:00:00Z",
    max_age_days: int = 90,
) -> AuditReport:
    """Audit a single cassette JSON file or a directory of `.json` cassettes."""
    files = sorted(path.rglob("*.json")) if path.is_dir() else [path]
    all_findings: list[CassetteFinding] = []
    total_interactions = 0
    for f in files:
        cassette = load_cassette(f)
        report = audit_cassette(
            cassette,
            target_name=str(f),
            reference_date=reference_date,
            max_age_days=max_age_days,
        )
        total_interactions += report.total_interactions
        all_findings.extend(report.findings)
    return AuditReport(
        target=str(path),
        total_interactions=total_interactions,
        findings=all_findings,
    )


def _extract_json_keys(body: str) -> set[str] | None:
    stripped = (body or "").strip()
    if not stripped.startswith("{"):
        return None
    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            return set(data.keys())
    except json.JSONDecodeError:
        pass
    return None


def diff_cassettes(baseline: CassetteFile, candidate: CassetteFile) -> list[ContractDiffItem]:
    """Compare two cassettes to detect removed endpoints, status shifts, and dropped JSON keys."""
    diffs: list[ContractDiffItem] = []
    base_map: dict[str, Any] = {
        f"{i.request.method} {i.request.path}": i for i in baseline.interactions
    }
    cand_map: dict[str, Any] = {
        f"{i.request.method} {i.request.path}": i for i in candidate.interactions
    }

    for endpoint, base_item in sorted(base_map.items()):
        if endpoint not in cand_map:
            diffs.append(
                ContractDiffItem(
                    endpoint=endpoint,
                    change_type="endpoint-removed",
                    severity=Severity.HIGH,
                    old_value=f"status={base_item.response.status}",
                    new_value="<missing>",
                    message=f"Endpoint '{endpoint}' present in baseline is missing in candidate cassette.",
                )
            )
            continue

        cand_item = cand_map[endpoint]
        if base_item.response.status != cand_item.response.status:
            diffs.append(
                ContractDiffItem(
                    endpoint=endpoint,
                    change_type="status-code-changed",
                    severity=Severity.CRITICAL,
                    old_value=str(base_item.response.status),
                    new_value=str(cand_item.response.status),
                    message=(
                        f"Status code for '{endpoint}' changed from "
                        f"{base_item.response.status} to {cand_item.response.status}."
                    ),
                )
            )

        base_keys = _extract_json_keys(base_item.response.body)
        cand_keys = _extract_json_keys(cand_item.response.body)
        if base_keys is not None and cand_keys is not None:
            removed_keys = sorted(base_keys - cand_keys)
            added_keys = sorted(cand_keys - base_keys)
            if removed_keys:
                diffs.append(
                    ContractDiffItem(
                        endpoint=endpoint,
                        change_type="response-keys-removed",
                        severity=Severity.HIGH,
                        old_value=", ".join(sorted(base_keys)),
                        new_value=", ".join(sorted(cand_keys)),
                        message=f"Response JSON dropped key(s): {', '.join(removed_keys)}.",
                    )
                )
            if added_keys:
                diffs.append(
                    ContractDiffItem(
                        endpoint=endpoint,
                        change_type="response-keys-added",
                        severity=Severity.LOW,
                        old_value=", ".join(sorted(base_keys)),
                        new_value=", ".join(sorted(cand_keys)),
                        message=f"Response JSON added key(s): {', '.join(added_keys)}.",
                    )
                )

    for endpoint, cand_item in sorted(cand_map.items()):
        if endpoint not in base_map:
            diffs.append(
                ContractDiffItem(
                    endpoint=endpoint,
                    change_type="endpoint-added",
                    severity=Severity.LOW,
                    old_value="<none>",
                    new_value=f"status={cand_item.response.status}",
                    message=f"New endpoint '{endpoint}' recorded in candidate cassette.",
                )
            )

    return diffs
