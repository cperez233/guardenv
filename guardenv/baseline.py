"""Baseline support: acknowledge existing findings so CI only fails on new ones."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from .models import Finding, ScanSummary

__all__ = ["Baseline", "BaselineError"]


class BaselineError(RuntimeError):
    """Raised when a baseline file exists but cannot be understood."""


class Baseline:
    """A set of finding fingerprints that should not fail the build."""

    __slots__ = ("_ids",)

    def __init__(self, ids: Iterable[str] = ()) -> None:
        self._ids = set(ids)

    def __len__(self) -> int:
        return len(self._ids)

    def __contains__(self, finding: Finding) -> bool:
        return finding.id in self._ids

    @classmethod
    def load(cls, path: str | Path) -> Baseline:
        target = Path(path)
        if not target.exists():
            return cls()
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BaselineError(f"cannot read baseline {target}: {exc}") from exc

        if isinstance(payload, dict) and "findings" in payload:
            entries = payload["findings"]
        elif isinstance(payload, list):
            entries = payload
        else:
            raise BaselineError(f"baseline {target} has an unexpected shape")

        ids: list[str] = []
        for entry in entries:
            if isinstance(entry, str):
                ids.append(entry)
            elif isinstance(entry, dict) and isinstance(entry.get("id"), str):
                ids.append(entry["id"])
            else:
                raise BaselineError(f"baseline {target} contains an unreadable entry: {entry!r}")
        return cls(ids)

    @classmethod
    def from_summary(cls, summary: ScanSummary) -> Baseline:
        return cls(f.id for f in summary.findings)

    def dump(self, path: str | Path, summary: ScanSummary) -> None:
        """Write a baseline file recording redacted metadata for every finding."""
        document = {
            "schemaVersion": "1.0",
            "tool": "guardenv",
            "findings": [
                {
                    "id": f.id,
                    "ruleId": f.rule_id,
                    "path": f.path,
                    "line": f.line,
                    "redacted": f.redacted,
                }
                for f in summary.sorted_findings()
            ],
        }
        Path(path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    def filter(self, summary: ScanSummary) -> tuple[list[Finding], int]:
        """Split ``summary``'s findings into (new, suppressed_count)."""
        if not self._ids:
            return list(summary.findings), 0
        new = [f for f in summary.findings if f.id not in self._ids]
        return new, len(summary.findings) - len(new)
