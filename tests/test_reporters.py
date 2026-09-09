"""Tests for the JSON, SARIF and terminal reporters."""

from __future__ import annotations

import json

import pytest

from guardenv.models import ScanError, ScanSummary, Severity, fingerprint, redact
from guardenv.reporters import (
    SARIF_VERSION,
    github_annotations,
    render_summary_panel,
    render_table,
    to_json,
    to_sarif,
)
from guardenv.scanner import Scanner

FIXTURE = (
    "AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ\n"
    "STRIPE_SECRET_KEY=sk_live_51H8xkLJk2mQqZzRtYuVbNmAsDfGhJkLp\n"
    "SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n"
)


@pytest.fixture
def summary(scanner: Scanner) -> ScanSummary:
    return scanner.scan_text(FIXTURE, "app/.env")


class TestRedaction:
    def test_short_values_keep_only_their_first_character(self) -> None:
        assert redact("abcd") == "a***"
        assert redact("abcdefgh") == "a*******"

    def test_single_character_is_masked(self) -> None:
        assert redact("a") == "*"

    def test_empty_value_stays_empty(self) -> None:
        assert redact("") == ""

    def test_long_values_keep_a_correlatable_prefix_and_suffix(self) -> None:
        masked = redact("AKIAZ4KJQ2WBXY7TDNPQ")
        assert masked.startswith("AKIA")
        assert masked.endswith("DNPQ")
        assert "Z4KJQ2WBXY7T" not in masked

    def test_fingerprints_are_deterministic(self) -> None:
        assert fingerprint("a", 1) == fingerprint("a", 1)
        assert fingerprint("a", 1) != fingerprint("a", 2)


class TestJsonReport:
    def test_document_shape(self, summary: ScanSummary) -> None:
        payload = json.loads(to_json(summary))
        assert payload["tool"] == "guardenv"
        assert payload["schemaVersion"] == "1.0"
        assert set(payload) == {"schemaVersion", "tool", "summary", "findings", "errors"}

    def test_counts_match_the_findings(self, summary: ScanSummary) -> None:
        payload = json.loads(to_json(summary))
        assert payload["summary"]["totalFindings"] == len(payload["findings"])
        assert sum(payload["summary"]["countsBySeverity"].values()) == len(payload["findings"])

    def test_secrets_are_redacted_by_default(self, summary: ScanSummary) -> None:
        raw = to_json(summary)
        assert "AKIAZ4KJQ2WBXY7TDNPQ" not in raw
        assert "sk_live_51H8xkLJk2mQqZzRtYuVbNmAsDfGhJkLp" not in raw
        assert "match" not in json.loads(raw)["findings"][0]

    def test_show_secrets_opts_into_the_raw_value(self, summary: ScanSummary) -> None:
        payload = json.loads(to_json(summary, include_secret=True))
        assert any(f["match"] == "AKIAZ4KJQ2WBXY7TDNPQ" for f in payload["findings"])

    def test_findings_are_sorted_by_descending_severity(self, summary: ScanSummary) -> None:
        ranks = [Severity(f["severity"]).rank for f in json.loads(to_json(summary))["findings"]]
        assert ranks == sorted(ranks, reverse=True)

    def test_empty_scan_serializes(self) -> None:
        payload = json.loads(to_json(ScanSummary()))
        assert payload["findings"] == []
        assert payload["summary"]["totalFindings"] == 0


class TestSarifReport:
    def test_top_level_structure(self, summary: ScanSummary) -> None:
        document = json.loads(to_sarif(summary, tool_version="1.0.0"))
        assert document["version"] == SARIF_VERSION
        assert document["$schema"].endswith("sarif-schema-2.1.0.json")
        assert len(document["runs"]) == 1

    def test_driver_metadata(self, summary: ScanSummary) -> None:
        driver = json.loads(to_sarif(summary, tool_version="9.9.9"))["runs"][0]["tool"]["driver"]
        assert driver["name"] == "GuardEnv"
        assert driver["version"] == "9.9.9"
        assert driver["rules"]

    def test_rule_indexes_resolve(self, summary: ScanSummary) -> None:
        run = json.loads(to_sarif(summary, tool_version="1.0.0"))["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        for result in run["results"]:
            assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    def test_levels_are_valid_sarif_vocabulary(self, summary: ScanSummary) -> None:
        run = json.loads(to_sarif(summary, tool_version="1.0.0"))["runs"][0]
        assert {r["level"] for r in run["results"]} <= {"error", "warning", "note", "none"}

    def test_security_severity_is_present_for_code_scanning(self, summary: ScanSummary) -> None:
        rules = json.loads(to_sarif(summary, tool_version="1.0.0"))["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            assert 0.0 <= float(rule["properties"]["security-severity"]) <= 10.0

    def test_regions_are_one_based(self, summary: ScanSummary) -> None:
        run = json.loads(to_sarif(summary, tool_version="1.0.0"))["runs"][0]
        for result in run["results"]:
            region = result["locations"][0]["physicalLocation"]["region"]
            assert region["startLine"] >= 1
            assert region["startColumn"] >= 1

    def test_partial_fingerprints_enable_alert_tracking(self, summary: ScanSummary) -> None:
        run = json.loads(to_sarif(summary, tool_version="1.0.0"))["runs"][0]
        assert all("guardenv/v1" in r["partialFingerprints"] for r in run["results"])

    def test_snippets_never_leak_the_secret(self, summary: ScanSummary) -> None:
        raw = to_sarif(summary, tool_version="1.0.0")
        assert "AKIAZ4KJQ2WBXY7TDNPQ" not in raw

    def test_entropy_rule_gets_a_synthetic_descriptor(self, entropy_only_scanner: Scanner) -> None:
        entropy_summary = entropy_only_scanner.scan_text(FIXTURE, "app/.env")
        driver = json.loads(to_sarif(entropy_summary, tool_version="1.0.0"))["runs"][0]["tool"]["driver"]
        assert any(rule["id"] == "high-entropy-string" for rule in driver["rules"])

    def test_scan_errors_surface_as_notifications(self) -> None:
        empty = ScanSummary(errors=[ScanError("locked.env", "read failed")])
        run = json.loads(to_sarif(empty, tool_version="1.0.0"))["runs"][0]
        notifications = run["invocations"][0]["toolExecutionNotifications"]
        assert notifications[0]["message"]["text"].startswith("locked.env")


class TestGithubAnnotations:
    def test_workflow_commands_are_emitted(self, summary: ScanSummary) -> None:
        lines = github_annotations(summary)
        assert lines
        assert all(line.startswith(("::error ", "::warning ")) for line in lines)

    def test_annotation_carries_file_and_line(self, summary: ScanSummary) -> None:
        assert "file=app/.env,line=" in github_annotations(summary)[0]

    def test_no_findings_means_no_annotations(self) -> None:
        assert github_annotations(ScanSummary()) == []


class TestTerminalRendering:
    def test_table_has_one_row_per_finding(self, summary: ScanSummary) -> None:
        table = render_table(summary.sorted_findings())
        assert table.row_count == len(summary.findings)

    def test_table_without_the_entropy_column(self, summary: ScanSummary) -> None:
        assert len(render_table(summary.sorted_findings(), show_entropy=False).columns) == 4

    def test_summary_panel_is_green_when_clean(self) -> None:
        assert render_summary_panel(ScanSummary(), target=".").border_style == "green"

    def test_summary_panel_is_red_when_dirty(self, summary: ScanSummary) -> None:
        assert render_summary_panel(summary, target=".").border_style == "red"
