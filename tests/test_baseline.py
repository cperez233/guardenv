"""Tests for baseline loading, filtering and serialization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from guardenv.baseline import Baseline, BaselineError
from guardenv.scanner import Scanner

FIXTURE = "AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ\n"


class TestBaselineLoading:
    def test_absent_file_yields_an_empty_baseline(self, tmp_path: Path) -> None:
        assert len(Baseline.load(tmp_path / "missing.json")) == 0

    def test_accepts_the_native_document(self, tmp_path: Path) -> None:
        path = tmp_path / "b.json"
        path.write_text(json.dumps({"findings": [{"id": "abc123"}, {"id": "def456"}]}))
        assert len(Baseline.load(path)) == 2

    def test_accepts_a_bare_id_list(self, tmp_path: Path) -> None:
        path = tmp_path / "b.json"
        path.write_text(json.dumps(["abc123"]))
        assert len(Baseline.load(path)) == 1

    def test_malformed_json_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "b.json"
        path.write_text("{oops")
        with pytest.raises(BaselineError, match="cannot read baseline"):
            Baseline.load(path)

    def test_unexpected_shape_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "b.json"
        path.write_text(json.dumps({"nope": 1}))
        with pytest.raises(BaselineError, match="unexpected shape"):
            Baseline.load(path)

    def test_unreadable_entry_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "b.json"
        path.write_text(json.dumps([{"no_id": True}]))
        with pytest.raises(BaselineError, match="unreadable entry"):
            Baseline.load(path)


class TestBaselineFiltering:
    def test_empty_baseline_suppresses_nothing(self, scanner: Scanner) -> None:
        summary = scanner.scan_text(FIXTURE, ".env")
        new, suppressed = Baseline().filter(summary)
        assert len(new) == len(summary.findings)
        assert suppressed == 0

    def test_matching_baseline_suppresses_everything(self, scanner: Scanner) -> None:
        summary = scanner.scan_text(FIXTURE, ".env")
        new, suppressed = Baseline.from_summary(summary).filter(summary)
        assert new == []
        assert suppressed == len(summary.findings)

    def test_membership_check(self, scanner: Scanner) -> None:
        summary = scanner.scan_text(FIXTURE, ".env")
        baseline = Baseline.from_summary(summary)
        assert summary.findings[0] in baseline

    def test_moving_a_secret_produces_a_new_fingerprint(self, scanner: Scanner) -> None:
        first = scanner.scan_text(FIXTURE, ".env")
        moved = scanner.scan_text("\n\n" + FIXTURE, ".env")
        new, _ = Baseline.from_summary(first).filter(moved)
        assert new, "a secret on a different line is a different fingerprint"


class TestBaselineDump:
    def test_roundtrip(self, scanner: Scanner, tmp_path: Path) -> None:
        summary = scanner.scan_text(FIXTURE, ".env")
        path = tmp_path / "baseline.json"
        Baseline().dump(path, summary)
        assert len(Baseline.load(path)) == len(summary.findings)

    def test_dump_never_contains_the_raw_secret(self, scanner: Scanner, tmp_path: Path) -> None:
        summary = scanner.scan_text(FIXTURE, ".env")
        path = tmp_path / "baseline.json"
        Baseline().dump(path, summary)
        assert "AKIAZ4KJQ2WBXY7TDNPQ" not in path.read_text()
