"""Deterministic HTTP request canonicalizer, SHA-256 matcher, nearest-miss diagnostician, and sanitizer."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from cassette.models import (
    CassetteFile,
    CassetteInteraction,
    MatchResult,
    RecordedRequest,
    RecordedResponse,
)

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "api-key",
}

SENSITIVE_QUERY_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "token",
    "secret",
    "password",
    "client_secret",
}

BEARER_PATTERN = re.compile(r"\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)


def canonicalize_body(body: str) -> str:
    """Canonicalize JSON request/response bodies with sorted keys; preserve raw text otherwise."""
    stripped = (body or "").strip()
    if not stripped:
        return ""
    if stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(stripped)
            return json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        except json.JSONDecodeError:
            return stripped
    return stripped


def compute_request_fingerprint(req: RecordedRequest) -> str:
    """Compute a deterministic SHA-256 digest over method, path, sorted query, and canonical body."""
    norm_method = req.method.upper().strip()
    parsed = urlsplit(req.path)
    norm_path = parsed.path or "/"
    merged_query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    merged_query.update(req.query)
    sorted_query = "&".join(f"{k}={merged_query[k]}" for k in sorted(merged_query))
    canon_body = canonicalize_body(req.body)
    payload = f"{norm_method}|{norm_path}|{sorted_query}|{canon_body}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def load_cassette(path: Path) -> CassetteFile:
    """Load a CassetteFile from JSON on disk and compute interaction fingerprints."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    interactions: list[CassetteInteraction] = []
    for index, item in enumerate(raw.get("interactions", []), 1):
        req_raw = item.get("request", {})
        resp_raw = item.get("response", {})
        parsed_url = urlsplit(str(req_raw.get("path", "/")))
        merged_q = dict(parse_qsl(parsed_url.query, keep_blank_values=True))
        if isinstance(req_raw.get("query"), dict):
            merged_q.update({str(k): str(v) for k, v in req_raw["query"].items()})
        req = RecordedRequest(
            method=str(req_raw.get("method", "GET")).upper(),
            path=parsed_url.path or "/",
            query=merged_q,
            headers={str(k): str(v) for k, v in (req_raw.get("headers") or {}).items()},
            body=str(req_raw.get("body", "")),
        )
        resp = RecordedResponse(
            status=int(resp_raw.get("status", 200)),
            headers={str(k): str(v) for k, v in (resp_raw.get("headers") or {}).items()},
            body=str(resp_raw.get("body", "")),
            latency_ms=float(resp_raw.get("latency_ms", 0.0)),
        )
        fp = compute_request_fingerprint(req)
        interactions.append(
            CassetteInteraction(
                interaction_id=str(item.get("interaction_id") or f"step-{index:03d}"),
                request=req,
                response=resp,
                recorded_at=str(item.get("recorded_at", "2026-11-18T00:00:00Z")),
                chaos_expected=bool(item.get("chaos_expected", False)),
                fingerprint=fp,
            )
        )
    return CassetteFile(
        name=str(raw.get("name") or path.stem),
        version=str(raw.get("version", "1.0")),
        interactions=interactions,
    )


def save_cassette(cassette: CassetteFile, path: Path) -> None:
    """Serialize a CassetteFile to formatted JSON."""
    payload: dict[str, Any] = {
        "name": cassette.name,
        "version": cassette.version,
        "interactions": [
            {
                "interaction_id": item.interaction_id,
                "recorded_at": item.recorded_at,
                "chaos_expected": item.chaos_expected,
                "fingerprint": item.fingerprint or compute_request_fingerprint(item.request),
                "request": {
                    "method": item.request.method,
                    "path": item.request.path,
                    "query": item.request.query,
                    "headers": item.request.headers,
                    "body": item.request.body,
                },
                "response": {
                    "status": item.response.status,
                    "headers": item.response.headers,
                    "body": item.response.body,
                    "latency_ms": item.response.latency_ms,
                },
            }
            for item in cassette.interactions
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def match_request(cassette: CassetteFile, incoming: RecordedRequest) -> MatchResult:
    """Match an incoming HTTP request or diagnose why the nearest interaction missed."""
    incoming_fp = compute_request_fingerprint(incoming)
    for item in cassette.interactions:
        fp = item.fingerprint or compute_request_fingerprint(item.request)
        if fp == incoming_fp:
            return MatchResult(
                matched=True,
                interaction=item,
                incoming_fingerprint=incoming_fp,
            )

    best_item: CassetteInteraction | None = None
    best_score = -1
    for item in cassette.interactions:
        score = 0
        if item.request.method.upper() == incoming.method.upper():
            score += 2
        if item.request.path == incoming.path:
            score += 4
        elif item.request.path.split("/")[:3] == incoming.path.split("/")[:3]:
            score += 1
        if score > best_score:
            best_score = score
            best_item = item

    reasons: list[str] = []
    if best_item is not None:
        if best_item.request.method.upper() != incoming.method.upper():
            reasons.append(
                f"method mismatch (expected {best_item.request.method}, got {incoming.method})"
            )
        if best_item.request.path != incoming.path:
            reasons.append(f"path mismatch (nearest '{best_item.request.path}' vs '{incoming.path}')")
        if best_item.request.query != incoming.query:
            reasons.append(
                f"query params differed (expected {sorted(best_item.request.query.keys())}, "
                f"got {sorted(incoming.query.keys())})"
            )
        if canonicalize_body(best_item.request.body) != canonicalize_body(incoming.body):
            reasons.append("request body payload differed")

    return MatchResult(
        matched=False,
        interaction=None,
        incoming_fingerprint=incoming_fp,
        nearest_interaction_id=best_item.interaction_id if best_item else None,
        mismatch_reasons=reasons or ["no recorded interactions in cassette"],
    )


def sanitize_cassette(cassette: CassetteFile) -> tuple[CassetteFile, int]:
    """Redact credentials in request/response headers and query parameters."""
    redacted_count = 0
    cleaned_interactions: list[CassetteInteraction] = []
    for item in cassette.interactions:
        req_headers: dict[str, str] = {}
        for k, v in item.request.headers.items():
            if k.lower() in SENSITIVE_HEADER_NAMES or BEARER_PATTERN.search(v):
                if v != "[REDACTED]":
                    redacted_count += 1
                req_headers[k] = "[REDACTED]"
            else:
                req_headers[k] = v

        req_query: dict[str, str] = {}
        for k, v in item.request.query.items():
            if k.lower() in SENSITIVE_QUERY_KEYS and v != "[REDACTED]":
                redacted_count += 1
                req_query[k] = "[REDACTED]"
            else:
                req_query[k] = v

        resp_headers: dict[str, str] = {}
        for k, v in item.response.headers.items():
            if k.lower() in SENSITIVE_HEADER_NAMES or BEARER_PATTERN.search(v):
                if v != "[REDACTED]":
                    redacted_count += 1
                resp_headers[k] = "[REDACTED]"
            else:
                resp_headers[k] = v

        new_req = RecordedRequest(
            method=item.request.method,
            path=item.request.path,
            query=req_query,
            headers=req_headers,
            body=item.request.body,
        )
        new_resp = RecordedResponse(
            status=item.response.status,
            headers=resp_headers,
            body=item.response.body,
            latency_ms=item.response.latency_ms,
        )
        cleaned_interactions.append(
            CassetteInteraction(
                interaction_id=item.interaction_id,
                request=new_req,
                response=new_resp,
                recorded_at=item.recorded_at,
                chaos_expected=item.chaos_expected,
                fingerprint=compute_request_fingerprint(new_req),
            )
        )
    return (
        CassetteFile(
            name=cassette.name,
            version=cassette.version,
            interactions=cleaned_interactions,
        ),
        redacted_count,
    )
