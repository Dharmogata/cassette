"""Command-line interface for Cassette."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from cassette.audit import audit_path, diff_cassettes
from cassette.formatters import (
    format_audit_report,
    format_diff_report,
    format_inspect,
    format_rules,
)
from cassette.matcher import load_cassette, sanitize_cassette, save_cassette
from cassette.models import SEVERITY_RANK, Severity
from cassette.server import CassetteReplayServer


def build_parser() -> argparse.ArgumentParser:
    """Construct the Cassette CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="cassette",
        description="Deterministic HTTP/Webhook cassette recorder, sanitizer, contract differ, and replay server.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="Inspect recorded HTTP interactions in a cassette")
    p_inspect.add_argument("path", type=Path, help="Path to cassette JSON file")
    p_inspect.add_argument("--format", choices=("text", "json", "markdown"), default="text")

    p_audit = sub.add_parser("audit", help="Audit cassette(s) for leaked secrets, staleness, and nondeterminism")
    p_audit.add_argument("path", type=Path, help="Cassette file or directory")
    p_audit.add_argument("--reference-date", default="2026-11-18T00:00:00Z")
    p_audit.add_argument("--max-age-days", type=int, default=90)
    p_audit.add_argument(
        "--min-severity",
        choices=("low", "medium", "high", "critical"),
        default="low",
    )
    p_audit.add_argument("--select", help="Comma-separated rule IDs (e.g. CS001,CS002)")
    p_audit.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    p_audit.add_argument("--fail-on-findings", action="store_true")

    p_sanitize = sub.add_parser("sanitize", help="Redact sensitive headers and query tokens in a cassette")
    p_sanitize.add_argument("path", type=Path, help="Input cassette JSON file")
    p_sanitize.add_argument("--output", type=Path, help="Output path (defaults to overwriting input)")

    p_diff = sub.add_parser("diff", help="Compare two cassettes for HTTP status and JSON contract drift")
    p_diff.add_argument("baseline", type=Path, help="Baseline cassette JSON file")
    p_diff.add_argument("candidate", type=Path, help="Candidate cassette JSON file")
    p_diff.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    p_diff.add_argument("--fail-on-drift", action="store_true")

    p_serve = sub.add_parser("serve", help="Run a local HTTP replay mock server from a cassette")
    p_serve.add_argument("path", type=Path, help="Cassette JSON file to replay")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8080)
    p_serve.add_argument("--latency-ms", type=float, default=0.0)
    p_serve.add_argument("--chaos-status", type=int, help="Optional HTTP error status to inject")

    p_rules = sub.add_parser("rules", help="List built-in cassette audit rules (CS001-CS005)")
    p_rules.add_argument("--format", choices=("text", "json", "markdown"), default="text")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Execute a Cassette CLI command."""
    args = build_parser().parse_args(argv)

    if args.command == "rules":
        print(format_rules(args.format))
        return 0

    if args.command == "inspect":
        cassette = load_cassette(args.path)
        print(format_inspect(cassette, args.format))
        return 0

    if args.command == "sanitize":
        cassette = load_cassette(args.path)
        cleaned, redacted = sanitize_cassette(cassette)
        target = args.output or args.path
        save_cassette(cleaned, target)
        print(
            json.dumps(
                {
                    "cassette": cleaned.name,
                    "output": str(target),
                    "redacted_fields": redacted,
                    "interactions": len(cleaned.interactions),
                },
                indent=2,
            )
        )
        return 0

    if args.command == "audit":
        report = audit_path(
            args.path,
            reference_date=args.reference_date,
            max_age_days=args.max_age_days,
        )
        min_rank = SEVERITY_RANK[Severity(args.min_severity.upper())]
        selected = (
            {item.strip().upper() for item in args.select.split(",") if item.strip()}
            if args.select
            else None
        )
        report.findings = [
            f
            for f in report.findings
            if SEVERITY_RANK[f.severity] >= min_rank
            and (selected is None or f.rule_id in selected)
        ]
        print(format_audit_report(report, args.format))
        return 1 if (args.fail_on_findings and report.findings) else 0

    if args.command == "diff":
        base = load_cassette(args.baseline)
        cand = load_cassette(args.candidate)
        diffs = diff_cassettes(base, cand)
        print(format_diff_report(diffs, args.format))
        return 1 if (args.fail_on_drift and diffs) else 0

    if args.command == "serve":
        cassette = load_cassette(args.path)
        server = CassetteReplayServer(
            cassette,
            host=args.host,
            port=args.port,
            extra_latency_ms=args.latency_ms,
            chaos_status=args.chaos_status,
        )
        print(f"Cassette replay server listening on http://{args.host}:{args.port}")
        server.serve_forever()
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
