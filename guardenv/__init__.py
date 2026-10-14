"""GuardEnv - high-speed detection of leaked credentials in source trees.

Public API::

    from guardenv import Scanner, ScanOptions, Severity

    summary = Scanner(ScanOptions()).scan_text(open(".env").read(), ".env")
    for finding in summary.sorted_findings():
        print(finding.rule_id, finding.line, finding.redacted)
"""

from __future__ import annotations

from .entropy import EntropyConfig, EntropyResult, analyze_token, shannon_entropy
from .models import DetectorKind, Finding, ScanError, ScanSummary, Severity
from .rules import RULES, RULES_BY_ID, RuleDefinition, compile_ruleset, default_ruleset
from .scanner import Scanner, ScanOptions

__version__ = "1.1.0"

__all__ = [
    "RULES",
    "RULES_BY_ID",
    "DetectorKind",
    "EntropyConfig",
    "EntropyResult",
    "Finding",
    "RuleDefinition",
    "ScanError",
    "ScanOptions",
    "ScanSummary",
    "Scanner",
    "Severity",
    "__version__",
    "analyze_token",
    "compile_ruleset",
    "default_ruleset",
    "shannon_entropy",
]
