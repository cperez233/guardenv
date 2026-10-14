"""Tests for the encoded-secret pass (base64 values carrying credentials)."""

from __future__ import annotations

import base64

from guardenv.decode import decode_base64_text, iter_encoded_findings, merge_encoded
from guardenv.rules import RULES
from guardenv.scanner import Scanner, ScanOptions

# Assembled from parts so the source never holds a complete key-shaped literal.
AWS_KEY_ID = "AKIA" + "Z4KJQ2WB" + "XY7TDNPQ"
STRIPE_KEY = "sk_live_" + "51H8xkLJk2mQqZzRt" + "YuVbNmAsDfGhJkLp"


def b64(value: str) -> str:
    return base64.b64encode(value.encode()).decode()


MANIFEST = f"""apiVersion: v1
kind: Secret
data:
  SERVICE_NAME: {b64("billing-service")}
  AWS_REGION: {b64("eu-west-1")}
  AWS_ACCESS_KEY_ID: {b64(AWS_KEY_ID)}
  STRIPE_SECRET_KEY: {b64(STRIPE_KEY)}
"""


def test_decodes_text_and_rejects_short_or_binary_values() -> None:
    assert decode_base64_text(b64(AWS_KEY_ID)) == AWS_KEY_ID
    assert decode_base64_text(b64("eu-west-1")) is None
    assert decode_base64_text(base64.b64encode(bytes(range(200, 240))).decode()) is None
    assert decode_base64_text("not base64 at all!!") is None


def test_reports_credentials_at_the_encoded_position() -> None:
    found = list(iter_encoded_findings(MANIFEST, "secret.yaml", RULES))
    assert sorted(f.rule_id for f in found) == ["aws-access-key-id", "stripe-secret-key"]
    lines = MANIFEST.split("\n")
    for finding in found:
        assert "encoded" in finding.tags
        assert lines[finding.line - 1][finding.column - 1 :].startswith(finding.match)
        assert AWS_KEY_ID not in finding.line_preview


def test_scanner_finds_encoded_secrets_by_default_and_can_opt_out() -> None:
    on = Scanner().scan_text(MANIFEST, "secret.yaml")
    off = Scanner(ScanOptions(decode_base64=False)).scan_text(MANIFEST, "secret.yaml")
    on_ids = {f.rule_id for f in on.findings}
    assert {"aws-access-key-id", "stripe-secret-key"} <= on_ids
    assert "aws-access-key-id" not in {f.rule_id for f in off.findings}


def test_encoded_finding_replaces_entropy_on_the_same_bytes() -> None:
    summary = Scanner().scan_text(MANIFEST, "secret.yaml")
    lines = [f.line for f in summary.findings]
    assert len(lines) == len(set(lines))
    assert not any(
        f.rule_id == "high-entropy-string" and "encoded" not in f.tags
        for f in summary.findings
        if f.line in (6, 7)
    )


def test_merge_keeps_a_raw_signature_over_its_decoded_copy() -> None:
    raw = list(Scanner().scan_text(f"KEY={AWS_KEY_ID}", "x.env").findings)
    assert merge_encoded(raw, []) == raw
