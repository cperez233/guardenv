"""End-to-end tests of the Typer command line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from guardenv import __version__
from guardenv.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, app

runner = CliRunner()

SECRET_ENV = (
    "APP_ENV=production\n"
    "AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ\n"
    "STRIPE_SECRET_KEY=sk_live_51H8xkLJk2mQqZzRtYuVbNmAsDfGhJkLp\n"
)

CLEAN_PY = 'import os\n\nAPI_KEY = os.environ["SERVICE_API_KEY"]\n'


@pytest.fixture
def dirty(tmp_path: Path) -> Path:
    (tmp_path / ".env").write_text(SECRET_ENV)
    return tmp_path


@pytest.fixture
def clean(tmp_path: Path) -> Path:
    (tmp_path / "settings.py").write_text(CLEAN_PY)
    return tmp_path


class TestTopLevel:
    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == EXIT_CLEAN
        assert __version__ in result.stdout

    def test_bare_invocation_prints_help(self) -> None:
        result = runner.invoke(app, [])
        assert result.exit_code == EXIT_CLEAN
        assert "scan" in result.stdout


class TestExitCodes:
    def test_clean_tree_exits_zero(self, clean: Path) -> None:
        assert runner.invoke(app, ["scan", str(clean), "-q"]).exit_code == EXIT_CLEAN

    def test_findings_exit_one(self, dirty: Path) -> None:
        assert runner.invoke(app, ["scan", str(dirty), "-q"]).exit_code == EXIT_FINDINGS

    def test_bad_severity_exits_two(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--fail-on", "SEVERE"])
        assert result.exit_code == EXIT_ERROR

    def test_unknown_rule_id_exits_two(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--rule", "no-such-rule"])
        assert result.exit_code == EXIT_ERROR

    def test_conflicting_output_formats_exit_two(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--json", "--sarif"])
        assert result.exit_code == EXIT_ERROR

    def test_output_without_a_machine_format_exits_two(self, dirty: Path, tmp_path: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "-o", str(tmp_path / "r.json")])
        assert result.exit_code == EXIT_ERROR

    def test_fail_on_critical_ignores_lower_severities(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "-q", "--fail-on", "CRITICAL"])
        assert result.exit_code == EXIT_CLEAN

    def test_fail_on_warning_fails_for_any_finding(self, tmp_path: Path) -> None:
        (tmp_path / ".env").write_text("SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "-q", "--fail-on-warning"])
        assert result.exit_code == EXIT_FINDINGS


class TestOutputFormats:
    def test_json_goes_to_stdout(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--json"])
        payload = json.loads(result.stdout)
        assert payload["tool"] == "guardenv"
        assert payload["summary"]["totalFindings"] >= 2

    def test_sarif_goes_to_stdout(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--sarif"])
        assert json.loads(result.stdout)["version"] == "2.1.0"

    def test_report_can_be_written_to_a_file(self, dirty: Path, tmp_path: Path) -> None:
        target = tmp_path / "reports" / "guardenv.sarif"
        result = runner.invoke(app, ["scan", str(dirty), "--sarif", "-o", str(target)])
        assert result.exit_code == EXIT_FINDINGS
        assert json.loads(target.read_text())["runs"]

    def test_github_annotations(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--github-annotations", "-q"])
        assert "::error file=" in result.stdout

    def test_secrets_are_redacted_unless_requested(self, dirty: Path) -> None:
        redacted = runner.invoke(app, ["scan", str(dirty), "--json"]).stdout
        assert "AKIAZ4KJQ2WBXY7TDNPQ" not in redacted
        exposed = runner.invoke(app, ["scan", str(dirty), "--json", "--show-secrets"]).stdout
        assert "AKIAZ4KJQ2WBXY7TDNPQ" in exposed


class TestStdin:
    def test_scan_from_stdin(self) -> None:
        result = runner.invoke(app, ["scan", "--stdin", "--json"], input=SECRET_ENV)
        payload = json.loads(result.stdout)
        assert payload["findings"][0]["path"] == "<stdin>"

    def test_stdin_name_is_configurable(self) -> None:
        result = runner.invoke(
            app, ["scan", "--stdin", "--stdin-name", "patch.diff", "--json"], input=SECRET_ENV
        )
        assert json.loads(result.stdout)["findings"][0]["path"] == "patch.diff"

    def test_stdin_and_paths_are_mutually_exclusive(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", "--stdin", str(dirty)], input="")
        assert result.exit_code == EXIT_ERROR

    def test_empty_stdin_is_clean(self) -> None:
        result = runner.invoke(app, ["scan", "--stdin", "-q"], input="")
        assert result.exit_code == EXIT_CLEAN


class TestFiltering:
    def test_rule_selection(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--rule", "aws-access-key-id", "--json"])
        rule_ids = {f["ruleId"] for f in json.loads(result.stdout)["findings"]}
        assert rule_ids <= {"aws-access-key-id", "high-entropy-string"}

    def test_rule_exclusion(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--exclude-rule", "aws-access-key-id", "--json"])
        rule_ids = {f["ruleId"] for f in json.loads(result.stdout)["findings"]}
        assert "aws-access-key-id" not in rule_ids

    def test_no_entropy_removes_entropy_findings(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--no-entropy", "--json"])
        detectors = {f["detector"] for f in json.loads(result.stdout)["findings"]}
        assert detectors <= {"regex"}

    def test_entropy_threshold_flag(self, tmp_path: Path) -> None:
        (tmp_path / "notes.txt").write_text("value hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n")
        loose = runner.invoke(app, ["scan", str(tmp_path), "-e", "3.0", "--json"])
        strict = runner.invoke(app, ["scan", str(tmp_path), "-e", "7.9", "--json"])
        assert json.loads(loose.stdout)["summary"]["totalFindings"] >= 1
        assert json.loads(strict.stdout)["summary"]["totalFindings"] == 0

    def test_exclude_dir_flag(self, tmp_path: Path) -> None:
        (tmp_path / "fixtures").mkdir()
        (tmp_path / "fixtures" / ".env").write_text(SECRET_ENV)
        result = runner.invoke(app, ["scan", str(tmp_path), "--exclude-dir", "fixtures", "--json"])
        assert json.loads(result.stdout)["summary"]["totalFindings"] == 0

    def test_min_severity_flag(self, dirty: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--min-severity", "CRITICAL", "--json"])
        severities = {f["severity"] for f in json.loads(result.stdout)["findings"]}
        assert severities <= {"CRITICAL"}


class TestBaselineWorkflow:
    def test_write_then_suppress(self, dirty: Path, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline.json"
        written = runner.invoke(app, ["scan", str(dirty), "--write-baseline", str(baseline)])
        assert written.exit_code == EXIT_CLEAN
        assert json.loads(baseline.read_text())["findings"]

        suppressed = runner.invoke(app, ["scan", str(dirty), "--baseline", str(baseline), "-q"])
        assert suppressed.exit_code == EXIT_CLEAN

    def test_new_secret_still_fails_against_a_baseline(self, dirty: Path, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline.json"
        runner.invoke(app, ["scan", str(dirty), "--write-baseline", str(baseline)])
        (dirty / "new.env").write_text("GITLAB_TOKEN=glpat-A1b2C3d4E5f6G7h8I9j0\n")
        result = runner.invoke(app, ["scan", str(dirty), "--baseline", str(baseline), "-q"])
        assert result.exit_code == EXIT_FINDINGS

    def test_corrupt_baseline_exits_two(self, dirty: Path, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline.json"
        baseline.write_text("{not json")
        result = runner.invoke(app, ["scan", str(dirty), "--baseline", str(baseline)])
        assert result.exit_code == EXIT_ERROR

    def test_missing_baseline_is_treated_as_empty(self, dirty: Path, tmp_path: Path) -> None:
        result = runner.invoke(app, ["scan", str(dirty), "--baseline", str(tmp_path / "absent.json"), "-q"])
        assert result.exit_code == EXIT_FINDINGS


class TestAuxiliaryCommands:
    def test_rules_table(self) -> None:
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == EXIT_CLEAN
        assert "aws-access-key-id" in result.stdout

    def test_rules_json(self) -> None:
        result = runner.invoke(app, ["rules", "--json"])
        payload = json.loads(result.stdout)
        assert {"id", "severity", "pattern"} <= set(payload[0])

    def test_rules_tag_filter(self) -> None:
        result = runner.invoke(app, ["rules", "--json", "--tag", "aws"])
        assert all("aws" in rule["tags"] for rule in json.loads(result.stdout))

    def test_unknown_tag_exits_two(self) -> None:
        assert runner.invoke(app, ["rules", "--tag", "nope"]).exit_code == EXIT_ERROR

    def test_entropy_command_reports_a_verdict(self) -> None:
        result = runner.invoke(app, ["entropy", "hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU"])
        assert result.exit_code == EXIT_CLEAN
        assert "SUSPICIOUS" in result.stdout

    def test_entropy_command_on_a_benign_token(self) -> None:
        result = runner.invoke(app, ["entropy", "FEATURE_FLAG_NEW_CHECKOUT"])
        assert "BENIGN" in result.stdout
