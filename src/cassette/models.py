"""Core data models for HTTP cassette interactions, matching, auditing, and contract diffs."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity level for cassette hygiene and contract findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class RecordedRequest:
    """Normalized HTTP request stored in a cassette interaction."""

    method: str
    path: str
    query: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


@dataclass
class RecordedResponse:
    """Normalized HTTP response stored in a cassette interaction."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    latency_ms: float = 0.0


@dataclass
class CassetteInteraction:
    """Single HTTP request/response interaction inside a cassette."""

    interaction_id: str
    request: RecordedRequest
    response: RecordedResponse
    recorded_at: str = "2026-11-18T00:00:00Z"
    chaos_expected: bool = False
    fingerprint: str = ""


@dataclass
class CassetteFile:
    """Top-level cassette archive containing recorded HTTP interactions."""

    name: str
    version: str = "1.0"
    interactions: list[CassetteInteraction] = field(default_factory=list)


@dataclass
class MatchResult:
    """Result of matching an incoming HTTP request against a cassette."""

    matched: bool
    interaction: CassetteInteraction | None = None
    incoming_fingerprint: str = ""
    nearest_interaction_id: str | None = None
    mismatch_reasons: list[str] = field(default_factory=list)


@dataclass
class CassetteFinding:
    """Static hygiene or contract finding discovered in a cassette file."""

    rule_id: str
    severity: Severity
    category: str
    interaction_id: str
    endpoint: str
    message: str
    advice: str


@dataclass
class ContractDiffItem:
    """Difference detected between two cassette versions for the same endpoint."""

    endpoint: str
    change_type: str
    severity: Severity
    old_value: str
    new_value: str
    message: str


@dataclass
class AuditReport:
    """Aggregated audit report for one or more cassette files."""

    target: str
    total_interactions: int
    findings: list[CassetteFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "total_interactions": self.total_interactions,
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "category": f.category,
                    "interaction_id": f.interaction_id,
                    "endpoint": f.endpoint,
                    "message": f.message,
                    "advice": f.advice,
                }
                for f in self.findings
            ],
        }
