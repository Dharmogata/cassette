"""Text, JSON, and Markdown formatters for Cassette inspection, audits, diffs, and rules."""

from __future__ import annotations

import json
from typing import Any

from cassette.audit import RULES_CATALOG
from cassette.models import AuditReport, CassetteFile, ContractDiffItem


def format_inspect(cassette: CassetteFile, fmt: str = "text") -> str:
    """Format a summary table of recorded interactions in a cassette."""
    if fmt == "json":
        return json.dumps(
            {
                "name": cassette.name,
                "version": cassette.version,
                "total_interactions": len(cassette.interactions),
                "interactions": [
                    {
                        "interaction_id": i.interaction_id,
                        "fingerprint": i.fingerprint,
                        "method": i.request.method,
                        "path": i.request.path,
                        "status": i.response.status,
                        "latency_ms": i.response.latency_ms,
                        "recorded_at": i.recorded_at,
                    }
                    for i in cassette.interactions
                ],
            },
            indent=2,
        )
    if fmt == "markdown":
        lines = [
            f"# Cassette Summary: `{cassette.name}`",
            "",
            f"- **Version:** `{cassette.version}` | **Interactions:** {len(cassette.interactions)}",
            "",
            "| ID | Fingerprint | Request | Status | Latency (ms) | Recorded At |",
            "| :--- | :--- | :--- | ---: | ---: | :--- |",
        ]
        for i in cassette.interactions:
            lines.append(
                f"| `{i.interaction_id}` | `{i.fingerprint}` | `{i.request.method} {i.request.path}` "
                f"| `{i.response.status}` | {i.response.latency_ms:.1f} | `{i.recorded_at}` |"
            )
        return "\n".join(lines)

    lines = [
        f"Cassette: {cassette.name} (v{cassette.version} · {len(cassette.interactions)} interaction(s))",
        "=" * 80,
    ]
    for i in cassette.interactions:
        lines.append(
            f"  [{i.interaction_id}] {i.request.method:<6} {i.request.path:<30} "
            f"-> {i.response.status} ({i.response.latency_ms:.1f}ms) [fp:{i.fingerprint}]"
        )
    lines.append("=" * 80)
    return "\n".join(lines)


def format_audit_report(report: AuditReport, fmt: str = "text") -> str:
    """Format an AuditReport as text, json, or markdown."""
    data = report.to_dict()
    if fmt == "json":
        return json.dumps(data, indent=2)
    if fmt == "markdown":
        lines = [
            f"# Cassette Audit Report: `{report.target}`",
            "",
            f"- **Interactions Scanned:** {report.total_interactions}",
            f"- **Findings:** {len(report.findings)}",
            "",
            "| Rule | Severity | Interaction | Endpoint | Message | Advice |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for f in report.findings:
            lines.append(
                f"| `{f.rule_id}` | **{f.severity.value}** | `{f.interaction_id}` "
                f"| `{f.endpoint}` | {f.message} | {f.advice} |"
            )
        return "\n".join(lines)

    lines = [
        f"Cassette Hygiene Audit: {report.target} ({report.total_interactions} interaction(s) scanned)",
        "=" * 80,
    ]
    if not report.findings:
        lines.append("No cassette hygiene or contract issues detected.")
    else:
        for f in report.findings:
            lines.extend(
                [
                    f"[{f.rule_id}] ({f.severity.value} | {f.category}) {f.interaction_id} @ {f.endpoint}",
                    f"  Issue:  {f.message}",
                    f"  Advice: {f.advice}",
                    "-" * 80,
                ]
            )
    s = data["summary"]
    lines.append(
        f"Summary: {s['total_findings']} finding(s) "
        f"(critical={s['critical']}, high={s['high']}, medium={s['medium']}, low={s['low']})"
    )
    return "\n".join(lines)


def format_diff_report(diffs: list[ContractDiffItem], fmt: str = "text") -> str:
    """Format cassette contract diff items as text, json, or markdown."""
    if fmt == "json":
        return json.dumps(
            [
                {
                    "endpoint": d.endpoint,
                    "change_type": d.change_type,
                    "severity": d.severity.value,
                    "old_value": d.old_value,
                    "new_value": d.new_value,
                    "message": d.message,
                }
                for d in diffs
            ],
            indent=2,
        )
    if fmt == "markdown":
        lines = [
            "# Cassette Contract Diff",
            "",
            "| Endpoint | Change Type | Severity | Baseline | Candidate | Message |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for d in diffs:
            lines.append(
                f"| `{d.endpoint}` | `{d.change_type}` | **{d.severity.value}** "
                f"| `{d.old_value}` | `{d.new_value}` | {d.message} |"
            )
        return "\n".join(lines)

    lines = ["Cassette Contract Diff", "=" * 80]
    if not diffs:
        lines.append("No contract drift detected between cassettes.")
    else:
        for d in diffs:
            lines.extend(
                [
                    f"[{d.severity.value}] {d.endpoint} ({d.change_type})",
                    f"  Baseline:  {d.old_value}",
                    f"  Candidate: {d.new_value}",
                    f"  Detail:    {d.message}",
                    "-" * 80,
                ]
            )
    lines.append(f"Summary: {len(diffs)} contract difference(s) detected.")
    return "\n".join(lines)


def format_rules(fmt: str = "text") -> str:
    """Format the built-in CS001-CS005 rule catalog."""
    if fmt == "json":
        return json.dumps(RULES_CATALOG, indent=2)
    if fmt == "markdown":
        lines = [
            "# Cassette Rules Catalog",
            "",
            "| Rule ID | Severity | Category | Description | Remediation |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]
        for r in RULES_CATALOG:
            lines.append(
                f"| `{r['rule_id']}` | **{r['severity']}** | `{r['category']}` "
                f"| {r['description']} | {r['remediation']} |"
            )
        return "\n".join(lines)

    lines = ["Cassette Built-in Rules (CS001 - CS005)", "=" * 80]
    for r in RULES_CATALOG:
        lines.extend(
            [
                f"[{r['rule_id']}] ({r['severity']} | {r['category']})",
                f"  Description: {r['description']}",
                f"  Remediation: {r['remediation']}",
                "-" * 80,
            ]
        )
    return "\n".join(lines)
