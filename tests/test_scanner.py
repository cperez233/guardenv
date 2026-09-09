"""Tests for filesystem traversal, decoding and orchestration."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from guardenv.models import Severity
from guardenv.scanner import (
    DEFAULT_EXCLUDED_DIRS,
    IgnoreSpec,
    Scanner,
    ScanOptions,
    decode_bytes,
    looks_binary,
)

SECRET_LINE = "AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ\n"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text('TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n')
    (tmp_path / ".env").write_text(SECRET_LINE)
    (tmp_path / "README.md").write_text("# Project\n\nNothing secret here.\n")

    for excluded in ("node_modules", ".git", "dist"):
        directory = tmp_path / excluded
        directory.mkdir()
        (directory / "leak.env").write_text(SECRET_LINE)
    return tmp_path


class TestBinarySniffing:
    def test_empty_chunk_is_not_binary(self) -> None:
        assert looks_binary(b"") is False

    def test_plain_text_is_not_binary(self) -> None:
        assert looks_binary(b"hello world\nsecond line\n") is False

    def test_nul_byte_marks_binary(self) -> None:
        assert looks_binary(b"MZ\x90\x00\x03\x00") is True

    def test_utf16_bom_is_treated_as_text(self) -> None:
        assert looks_binary("KEY=value".encode("utf-16")) is False

    def test_control_character_soup_is_binary(self) -> None:
        assert looks_binary(bytes(range(1, 32)) * 4) is True


class TestDecoding:
    def test_utf8_roundtrip(self) -> None:
        text, encoding = decode_bytes("clave=señal\n".encode())
        assert text == "clave=señal\n"
        assert encoding == "utf-8"

    def test_utf8_bom_is_stripped(self) -> None:
        text, encoding = decode_bytes(b"\xef\xbb\xbfKEY=value")
        assert encoding == "utf-8"
        assert "KEY=value" in text

    def test_utf16_is_decoded(self) -> None:
        text, encoding = decode_bytes("KEY=value".encode("utf-16"))
        assert text.strip("﻿") == "KEY=value"
        assert encoding in {"utf-16", "utf-8-sig"}

    def test_latin1_fallback_never_raises(self) -> None:
        text, encoding = decode_bytes(b"clave=se\xf1al")
        assert "clave=se" in text
        assert encoding in {"cp1252", "latin-1", "utf-16", "utf-32"}

    def test_arbitrary_bytes_do_not_raise(self) -> None:
        text, _ = decode_bytes(bytes(range(256)))
        assert isinstance(text, str)


class TestIgnoreSpec:
    def test_comments_and_blanks_are_ignored(self) -> None:
        spec = IgnoreSpec(["# comment", "", "   "])
        assert not spec

    def test_simple_glob(self) -> None:
        spec = IgnoreSpec(["*.log"])
        assert spec.matches("logs/app.log", is_dir=False) is True
        assert spec.matches("logs/app.txt", is_dir=False) is False

    def test_directory_only_pattern(self) -> None:
        spec = IgnoreSpec(["build/"])
        assert spec.matches("build", is_dir=True) is True
        assert spec.matches("build", is_dir=False) is False

    def test_negation_reinstates_a_path(self) -> None:
        spec = IgnoreSpec(["*.env", "!keep.env"])
        assert spec.matches("secrets.env", is_dir=False) is True
        assert spec.matches("keep.env", is_dir=False) is False


class TestScanText:
    def test_detects_a_regex_finding(self, scanner: Scanner) -> None:
        summary = scanner.scan_text(SECRET_LINE, ".env")
        assert [f.rule_id for f in summary.findings] == ["aws-access-key-id"]
        assert summary.files_scanned == 1

    def test_empty_document_is_clean(self, scanner: Scanner) -> None:
        summary = scanner.scan_text("", "empty.txt")
        assert summary.findings == []
        assert summary.highest_severity is None

    def test_duration_is_recorded(self, scanner: Scanner) -> None:
        summary = scanner.scan_text(SECRET_LINE, ".env")
        assert summary.duration_ms >= 0.0

    def test_entropy_detector_can_run_alone(self, entropy_only_scanner: Scanner) -> None:
        summary = entropy_only_scanner.scan_text("SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n", ".env")
        assert [f.rule_id for f in summary.findings] == ["high-entropy-string"]

    def test_regex_detector_can_run_alone(self, rules_only_scanner: Scanner) -> None:
        summary = rules_only_scanner.scan_text(SECRET_LINE, ".env")
        assert all(f.detector.value == "regex" for f in summary.findings)

    def test_min_severity_filters_the_report(self) -> None:
        scanner = Scanner(ScanOptions(min_severity=Severity.CRITICAL))
        summary = scanner.scan_text("SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n" + SECRET_LINE, ".env")
        assert {f.severity for f in summary.findings} == {Severity.CRITICAL}

    def test_minified_bundle_lines_are_skipped(self, entropy_only_scanner: Scanner) -> None:
        bundle = "var a=" + ("kR8fLpQ2mZvX1sTgH9dYw" * 1200) + ";"
        assert entropy_only_scanner.scan_text(bundle, "bundle.min.js").findings == []


class TestScanPaths:
    def test_finds_secrets_across_a_tree(self, scanner: Scanner, repo: Path) -> None:
        summary = scanner.scan_paths([repo])
        paths = {Path(f.path).name for f in summary.findings}
        assert {".env", "app.py"} <= paths

    def test_default_excluded_directories_are_skipped(self, scanner: Scanner, repo: Path) -> None:
        summary = scanner.scan_paths([repo])
        assert not any(part in DEFAULT_EXCLUDED_DIRS for f in summary.findings for part in Path(f.path).parts)

    def test_single_file_target(self, scanner: Scanner, repo: Path) -> None:
        summary = scanner.scan_paths([repo / ".env"])
        assert summary.files_scanned == 1
        assert summary.findings

    def test_missing_path_is_reported_not_raised(self, scanner: Scanner, tmp_path: Path) -> None:
        summary = scanner.scan_paths([tmp_path / "nope"])
        assert summary.findings == []
        assert [e.reason for e in summary.errors] == ["path does not exist"]

    def test_empty_file_is_scanned_without_findings(self, scanner: Scanner, tmp_path: Path) -> None:
        (tmp_path / "empty.env").write_text("")
        summary = scanner.scan_paths([tmp_path])
        assert summary.findings == []

    def test_binary_file_is_skipped(self, scanner: Scanner, tmp_path: Path) -> None:
        (tmp_path / "blob.dat").write_bytes(b"\x00\x01\x02" + SECRET_LINE.encode() * 10)
        summary = scanner.scan_paths([tmp_path])
        assert summary.findings == []
        assert summary.files_skipped >= 1

    def test_oversized_file_is_skipped_with_a_warning(self, tmp_path: Path) -> None:
        (tmp_path / "big.env").write_text(SECRET_LINE * 200)
        scanner = Scanner(ScanOptions(max_file_size=64))
        summary = scanner.scan_paths([tmp_path])
        assert summary.findings == []
        assert any("max-file-size" in e.reason for e in summary.errors)

    def test_excluded_extension_is_skipped(self, scanner: Scanner, tmp_path: Path) -> None:
        (tmp_path / "logo.png").write_text(SECRET_LINE)
        summary = scanner.scan_paths([tmp_path])
        assert summary.findings == []

    def test_lockfiles_are_skipped(self, scanner: Scanner, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text(SECRET_LINE)
        assert scanner.scan_paths([tmp_path]).findings == []

    def test_include_glob_narrows_the_scan(self, tmp_path: Path) -> None:
        (tmp_path / "a.env").write_text(SECRET_LINE)
        (tmp_path / "b.py").write_text(SECRET_LINE)
        scanner = Scanner(ScanOptions(include_globs=("*.env",)))
        summary = scanner.scan_paths([tmp_path])
        assert {Path(f.path).name for f in summary.findings} == {"a.env"}

    def test_exclude_glob_removes_matches(self, tmp_path: Path) -> None:
        (tmp_path / "a.env").write_text(SECRET_LINE)
        (tmp_path / "b.env").write_text(SECRET_LINE)
        scanner = Scanner(ScanOptions(exclude_globs=("b.env",)))
        summary = scanner.scan_paths([tmp_path])
        assert {Path(f.path).name for f in summary.findings} == {"a.env"}

    def test_gitignore_is_respected_by_default(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("secrets/\n")
        (tmp_path / "secrets").mkdir()
        (tmp_path / "secrets" / "prod.env").write_text(SECRET_LINE)
        assert Scanner(ScanOptions()).scan_paths([tmp_path]).findings == []

    def test_gitignore_can_be_disabled(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("secrets/\n")
        (tmp_path / "secrets").mkdir()
        (tmp_path / "secrets" / "prod.env").write_text(SECRET_LINE)
        scanner = Scanner(ScanOptions(respect_gitignore=False))
        assert scanner.scan_paths([tmp_path]).findings

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
    def test_symlinks_are_not_followed_by_default(self, tmp_path: Path) -> None:
        real = tmp_path / "real.env"
        real.write_text(SECRET_LINE)
        (tmp_path / "link.env").symlink_to(real)
        summary = Scanner(ScanOptions()).scan_paths([tmp_path])
        assert [Path(f.path).name for f in summary.findings] == ["real.env"]

    def test_single_worker_matches_concurrent_results(self, repo: Path) -> None:
        concurrent = Scanner(ScanOptions(workers=8)).scan_paths([repo])
        serial = Scanner(ScanOptions(workers=1)).scan_paths([repo])
        assert {f.id for f in concurrent.findings} == {f.id for f in serial.findings}

    def test_non_utf8_file_is_still_scanned(self, scanner: Scanner, tmp_path: Path) -> None:
        (tmp_path / "legacy.env").write_bytes("# se\xf1al\n".encode("latin-1") + SECRET_LINE.encode())
        assert scanner.scan_paths([tmp_path]).findings

    @pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses permission bits")
    def test_unreadable_file_is_reported_not_fatal(self, scanner: Scanner, tmp_path: Path) -> None:
        locked = tmp_path / "locked.env"
        locked.write_text(SECRET_LINE)
        locked.chmod(0o000)
        try:
            summary = scanner.scan_paths([tmp_path])
            assert any("read failed" in e.reason for e in summary.errors)
        finally:
            locked.chmod(0o644)


class TestScanOptions:
    def test_entropy_threshold_override_applies_to_every_charset(self) -> None:
        options = ScanOptions().with_entropy_threshold(5.5)
        assert options.entropy.hex_threshold == 5.5
        assert options.entropy.base64_threshold == 5.5
        assert options.entropy.generic_threshold == 5.5

    def test_none_threshold_leaves_options_untouched(self) -> None:
        options = ScanOptions()
        assert options.with_entropy_threshold(None) is options

    def test_raising_the_threshold_suppresses_entropy_findings(self) -> None:
        text = "SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n"
        loose = Scanner(ScanOptions(enable_rules=False).with_entropy_threshold(3.0))
        strict = Scanner(ScanOptions(enable_rules=False).with_entropy_threshold(7.5))
        assert loose.scan_text(text, ".env").findings
        assert strict.scan_text(text, ".env").findings == []
