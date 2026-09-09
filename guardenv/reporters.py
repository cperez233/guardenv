"""Output formats: human-readable tables, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from typing import Any

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Finding, ScanSummary, Severity
from .rules import RULES_BY_ID, RuleDefinition

__all__ = [
    "SARIF_SCHEMA",
    "github_annotations",
    "render_summary_panel",
    "render_table",
    "to_json",
    "to_sarif",
]

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_URI = "https://github.com/cperez233/guardenv"

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "bright_black",
}


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def to_json(summary: ScanSummary, *, include_secret: bool = False, indent: int | None = 2) -> str:
    """Serialize a scan into GuardEnv's own JSON report schema."""
    return json.dumps(summary.to_dict(include_secret=include_secret), indent=indent, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #


def _sarif_rule(rule: RuleDefinition | None, rule_id: str) -> dict[str, Any]:
    if rule is None:
        # Synthesised rule descriptor for the entropy detector.
        return {
            "id": rule_id,
            "name": "HighEntropyString",
            "shortDescription": {"text": "High entropy string"},
            "fullDescription": {
                "text": "A string whose Shannon entropy exceeds the configured threshold, "
                "which is characteristic of randomly generated credentials."
            },
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "tags": ["security", "entropy", "guardenv"],
                "security-severity": Severity.MEDIUM.sarif_security_severity,
            },
        }
    return {
        "id": rule.id,
        "name": "".join(part.capitalize() for part in rule.id.split("-")),
        "shortDescription": {"text": rule.name},
        "fullDescription": {"text": rule.description},
        "helpUri": f"{TOOL_URI}#rule-{rule.id}",
        "help": {
            "text": f"{rule.description} Rotate the credential and remove it from version control.",
            "markdown": (
                f"**{rule.name}**\n\n{rule.description}\n\n"
                "**Remediation**\n\n"
                "1. Revoke/rotate the credential at the provider.\n"
                "2. Remove it from the working tree and from git history.\n"
                "3. Move it into a secrets manager or CI secret store."
            ),
        },
        "defaultConfiguration": {"level": rule.severity.sarif_level},
        "properties": {
            "tags": ["security", "guardenv", *rule.tags],
            "security-severity": rule.severity.sarif_security_severity,
            "precision": "high" if rule.entropy_min is None else "medium",
        },
    }


def to_sarif(summary: ScanSummary, *, tool_version: str, indent: int | None = 2) -> str:
    """Serialize a scan as SARIF 2.1.0 for GitHub Code Scanning."""
    referenced_ids: list[str] = []
    for finding in summary.sorted_findings():
        if finding.rule_id not in referenced_ids:
            referenced_ids.append(finding.rule_id)

    rule_descriptors = [_sarif_rule(RULES_BY_ID.get(rid), rid) for rid in referenced_ids]
    rule_index = {rid: i for i, rid in enumerate(referenced_ids)}

    results: list[dict[str, Any]] = []
    for finding in summary.sorted_findings():
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": finding.severity.sarif_level,
                "message": {
                    "text": f"{finding.rule_name}: potential credential `{finding.redacted}` "
                    f"detected via {finding.detector.value} analysis."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.path.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.column),
                                "snippet": {"text": finding.line_preview},
                            },
                        }
                    }
                ],
                "partialFingerprints": {"guardenv/v1": finding.id},
                "properties": {
                    "severity": finding.severity.value,
                    "detector": finding.detector.value,
                    "entropy": finding.entropy,
                    "verified": finding.verified,
                    "tags": list(finding.tags),
                },
            }
        )

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GuardEnv",
                        "informationUri": TOOL_URI,
                        "version": tool_version,
                        "semanticVersion": tool_version,
                        "rules": rule_descriptors,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {
                                "level": "warning",
                                "message": {"text": f"{error.path}: {error.reason}"},
                            }
                            for error in summary.errors
                        ],
                    }
                ],
                "results": results,
                "properties": {
                    "filesScanned": summary.files_scanned,
                    "filesSkipped": summary.files_skipped,
                    "durationMs": round(summary.duration_ms, 3),
                },
            }
        ],
    }
    return json.dumps(document, indent=indent, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# GitHub Actions annotations
# --------------------------------------------------------------------------- #


def github_annotations(summary: ScanSummary) -> list[str]:
    """``::error file=...`` workflow commands, for inline PR annotations."""
    lines: list[str] = []
    for finding in summary.sorted_findings():
        level = "error" if finding.severity.rank >= Severity.HIGH.rank else "warning"
        message = f"{finding.rule_name} ({finding.rule_id}): {finding.redacted}"
        lines.append(
            f"::{level} file={finding.path},line={finding.line},col={finding.column},"
            f"title=GuardEnv::{message}"
        )
    return lines


# --------------------------------------------------------------------------- #
# Rich terminal rendering
# --------------------------------------------------------------------------- #


def render_table(findings: Sequence[Finding], *, show_entropy: bool = True) -> Table:
    """Build a ``rich`` table of findings."""
    table = Table(
        show_header=True,
        header_style="bold bright_white",
        border_style="grey30",
        expand=True,
        pad_edge=False,
    )
    table.add_column("SEVERITY", width=10, no_wrap=True)
    table.add_column("RULE", style="bright_cyan", no_wrap=True)
    table.add_column("LOCATION", style="bright_white", overflow="fold")
    table.add_column("SECRET", style="bright_magenta", no_wrap=True)
    if show_entropy:
        table.add_column("H", justify="right", width=5, style="bright_black")

    for finding in findings:
        badge = Text(f" {finding.severity.value} ", style=SEVERITY_STYLE[finding.severity])
        location = f"{finding.path}:{finding.line}:{finding.column}"
        rule_cell = finding.rule_id + (" ✓" if finding.verified else "")
        row: list[Any] = [badge, rule_cell, location, finding.redacted]
        if show_entropy:
            row.append(f"{finding.entropy:.2f}" if finding.entropy is not None else "-")
        table.add_row(*row)
    return table


def render_summary_panel(summary: ScanSummary, *, target: str) -> Panel:
    """Build the closing summary panel shown after the findings table."""
    counts = summary.counts_by_severity
    clean = not summary.findings

    body = Text()
    body.append("Target      ", style="bright_black")
    body.append(f"{target}\n", style="bright_white")
    body.append("Files       ", style="bright_black")
    body.append(
        f"{summary.files_scanned} scanned, {summary.files_skipped} skipped, "
        f"{_human_bytes(summary.bytes_scanned)} read\n",
        style="bright_white",
    )
    body.append("Duration    ", style="bright_black")
    throughput = (
        f" ({_human_bytes(int(summary.bytes_scanned / max(summary.duration_ms / 1000, 1e-6)))}/s)"
        if summary.bytes_scanned
        else ""
    )
    body.append(f"{summary.duration_ms:.1f} ms{throughput}\n", style="bright_white")
    body.append("Findings    ", style="bright_black")

    if clean:
        body.append("0 — no credentials detected", style="bold green")
    else:
        parts = [
            (f"{counts[s.value]} {s.value}", SEVERITY_COLOR[s])
            for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO)
            if counts[s.value]
        ]
        for index, (label, color) in enumerate(parts):
            if index:
                body.append("  ·  ", style="grey35")
            body.append(label, style=f"bold {color}")

    if summary.errors:
        body.append(f"\nWarnings    {len(summary.errors)} file(s) could not be read", style="yellow")

    return Panel(
        body,
        title="[bold]GuardEnv scan report[/bold]",
        border_style="green" if clean else "red",
        padding=(1, 2),
    )


def _human_bytes(count: int) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def iter_report_lines(findings: Iterable[Finding]) -> Iterable[str]:
    """Plain-text rendering used when ``rich`` output is disabled."""
    for finding in findings:
        yield (
            f"{finding.severity.value:<8} {finding.path}:{finding.line}:{finding.column} "
            f"[{finding.rule_id}] {finding.redacted}"
        )
