"""Encoded-secret pass: credentials hidden inside base64 values.

Kubernetes Secret manifests, Docker auth configs and "obfuscated" constants
carry credentials base64-encoded, where no signature can see them and the
entropy detector can only say "random-looking string". This pass decodes every
plausible base64 run, scans the plaintext with the signature rules and reports
the most severe credential at the position of the *encoded* value.

It mirrors ``web/src/engine/decode.ts`` so the CLI and the playground agree.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator, Sequence

from .entropy import shannon_entropy
from .models import DetectorKind, Finding, redact
from .rules import RuleDefinition, deduplicate_findings, iter_rule_findings

__all__ = ["decode_base64_text", "iter_encoded_findings", "merge_encoded"]

_CANDIDATE = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
_MIN_PLAINTEXT = 12
_MAX_PREVIEW = 160


def decode_base64_text(value: str) -> str | None:
    """Decode standard or URL-safe base64 to text, or ``None`` if it is not text."""
    normalized = value.replace("-", "+").replace("_", "/").rstrip("=")
    if len(normalized) % 4 == 1:
        return None
    padded = normalized + "=" * (-len(normalized) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    if len(text) < _MIN_PLAINTEXT:
        return None
    printable = sum(1 for ch in text if ch in "\t\n\r" or (ord(ch) >= 32 and ord(ch) != 127))
    return text if printable / len(text) >= 0.95 else None


def iter_encoded_findings(text: str, path: str, rules: Sequence[RuleDefinition]) -> Iterator[Finding]:
    """Yield one finding per base64 value whose plaintext carries a credential."""
    for line_no, line in enumerate(text.split("\n"), start=1):
        for match in _CANDIDATE.finditer(line):
            blob = match.group(0)
            plaintext = decode_base64_text(blob)
            if plaintext is None:
                continue
            inner = deduplicate_findings(
                list(iter_rule_findings(plaintext, path, rules, entropy_fn=shannon_entropy))
            )
            if not inner:
                continue
            top = min(inner, key=lambda f: (-f.severity.rank, f.line, f.column))
            masked = redact(blob)
            yield Finding(
                rule_id=top.rule_id,
                rule_name=f"{top.rule_name} (base64)",
                severity=top.severity,
                detector=DetectorKind.REGEX,
                path=path,
                line=line_no,
                column=match.start() + 1,
                match=blob,
                redacted=masked,
                entropy=top.entropy,
                line_preview=line.strip().replace(blob, masked)[:_MAX_PREVIEW],
                description=f"Base64-encoded value that decodes to {top.redacted}. {top.description}",
                tags=(*top.tags, "encoded", "base64"),
                verified=top.verified,
            )


def merge_encoded(findings: Sequence[Finding], encoded: Sequence[Finding]) -> list[Finding]:
    """Fold encoded findings in.

    A decoded credential is more specific than "high entropy string" on the same
    bytes, so it replaces it; a signature that already matched the raw value
    wins over the decoded copy.
    """
    kept = [
        f
        for f in findings
        if f.detector is not DetectorKind.ENTROPY
        or not any(e.line == f.line and f.match in e.match for e in encoded)
    ]
    extra = [
        e
        for e in encoded
        if not any(f.line == e.line and (e.match in f.match or f.match in e.match) for f in kept)
    ]
    return [*kept, *extra]
