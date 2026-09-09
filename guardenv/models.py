"""Core data structures shared by every GuardEnv subsystem.

The models here are intentionally dependency-free (stdlib only) so that they can
be imported by the rule engine, the scanner, the reporters and the test-suite
without dragging in the CLI layer.
"""

from __future__ import annotations

import enum
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    """Severity ladder used across the CLI, the JSON report and SARIF."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric weight, higher is worse. Useful for sorting and thresholds."""
        return _SEVERITY_RANK[self]

    @property
    def sarif_level(self) -> str:
        """Map the ladder onto SARIF's much smaller ``level`` vocabulary."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self is Severity.MEDIUM:
            return "warning"
        return "note"

    @property
    def sarif_security_severity(self) -> str:
        """GitHub Code Scanning sorts alerts with this 0.0-10.0 property."""
        return _SEVERITY_SECURITY_SCORE[self]

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls(raw.strip().upper())
        except ValueError as exc:  # pragma: no cover - argument validation
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"Unknown severity {raw!r}. Expected one of: {valid}") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

_SEVERITY_SECURITY_SCORE: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


class DetectorKind(str, enum.Enum):
    """How a finding was produced."""

    REGEX = "regex"
    ENTROPY = "entropy"


def redact(secret: str, keep: int = 4) -> str:
    """Return a display-safe version of ``secret``.

    Keeps a short prefix/suffix so a human can correlate the finding with the
    real credential without the report itself becoming a secret.
    """
    if not secret:
        return ""
    if len(secret) <= keep * 2:
        return secret[0] + "*" * (len(secret) - 1) if len(secret) > 1 else "*"
    return f"{secret[:keep]}{'*' * 8}{secret[-keep:]}"


def fingerprint(*parts: Any) -> str:
    """Stable short hash used to deduplicate findings across runs."""
    digest = hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8"))
    return digest.hexdigest()[:16]


@dataclass(slots=True)
class Finding:
    """A single potential credential leak."""

    rule_id: str
    rule_name: str
    severity: Severity
    detector: DetectorKind
    path: str
    line: int
    column: int
    match: str
    redacted: str
    entropy: float | None = None
    line_preview: str = ""
    description: str = ""
    tags: tuple[str, ...] = ()
    verified: bool = False

    @property
    def id(self) -> str:
        """Deterministic identity of the finding (path + rule + secret hash)."""
        return fingerprint(self.path, self.rule_id, self.line, self.match)

    def to_dict(self, *, include_secret: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "ruleId": self.rule_id,
            "ruleName": self.rule_name,
            "severity": self.severity.value,
            "detector": self.detector.value,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "redacted": self.redacted,
            "entropy": round(self.entropy, 4) if self.entropy is not None else None,
            "linePreview": self.line_preview,
            "description": self.description,
            "tags": list(self.tags),
            "verified": self.verified,
        }
        if include_secret:
            payload["match"] = self.match
        return payload


@dataclass(slots=True)
class ScanError:
    """A file that could not be read or decoded, surfaced instead of swallowed."""

    path: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "reason": self.reason}


@dataclass(slots=True)
class ScanSummary:
    """Aggregate outcome of a scan."""

    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    duration_ms: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def has_at_least(self, threshold: Severity) -> bool:
        return any(f.severity.rank >= threshold.rank for f in self.findings)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.path, f.line, f.column, f.rule_id),
        )

    def extend(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    def to_dict(self, *, include_secret: bool = False) -> dict[str, Any]:
        return {
            "schemaVersion": "1.0",
            "tool": "guardenv",
            "summary": {
                "filesScanned": self.files_scanned,
                "filesSkipped": self.files_skipped,
                "bytesScanned": self.bytes_scanned,
                "durationMs": round(self.duration_ms, 3),
                "totalFindings": len(self.findings),
                "countsBySeverity": self.counts_by_severity,
            },
            "findings": [f.to_dict(include_secret=include_secret) for f in self.sorted_findings()],
            "errors": [e.to_dict() for e in self.errors],
        }
