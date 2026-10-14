"""Filesystem traversal and orchestration of the detection engines.

The scanner is deliberately defensive: a repository is an adversarial input for
a file walker. Broken symlinks, permission errors, 4 GB minified bundles,
UTF-16 configs, latin-1 legacy files and genuinely binary blobs must all be
handled without aborting the run or emitting garbage findings.
"""

from __future__ import annotations

import fnmatch
import os
import time
from collections.abc import Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from pathlib import Path

from .decode import iter_encoded_findings, merge_encoded
from .entropy import (
    DEFAULT_ENTROPY_CONFIG,
    EntropyConfig,
    scan_line_for_entropy,
    shannon_entropy,
)
from .models import DetectorKind, Finding, ScanError, ScanSummary, Severity, redact
from .rules import RuleDefinition, deduplicate_findings, default_ruleset, iter_rule_findings

__all__ = [
    "DEFAULT_EXCLUDED_DIRS",
    "DEFAULT_EXCLUDED_EXTENSIONS",
    "ScanOptions",
    "Scanner",
    "decode_bytes",
    "looks_binary",
]


DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        "__pycache__",
        "node_modules",
        "bower_components",
        "vendor",
        "dist",
        "build",
        "out",
        "target",
        "coverage",
        "htmlcov",
        ".venv",
        "venv",
        "env",
        ".env.d",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".turbo",
        ".parcel-cache",
        ".gradle",
        ".terraform",
        "site-packages",
        ".cache",
        ".DS_Store",
    }
)

DEFAULT_EXCLUDED_EXTENSIONS: frozenset[str] = frozenset(
    {
        # images / media
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".tiff",
        ".svg",
        ".mp3",
        ".mp4",
        ".avi",
        ".mov",
        ".mkv",
        ".wav",
        ".flac",
        ".ogg",
        ".webm",
        # fonts
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        # archives / binaries
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".jar",
        ".war",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".bin",
        ".o",
        ".a",
        ".class",
        ".pyc",
        ".pyo",
        ".wasm",
        ".node",
        # documents / data blobs
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".mdb",
        ".parquet",
        ".avro",
        # lockfiles: enormous, hash-dense, and never hold real credentials
        ".lock",
    }
)

#: Files whose name alone is enough to skip them.
DEFAULT_EXCLUDED_FILENAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "Cargo.lock",
        "composer.lock",
        "go.sum",
    }
)

#: Encodings tried in order when a file is not valid UTF-8.
_FALLBACK_ENCODINGS: tuple[str, ...] = ("utf-8-sig", "utf-16", "utf-32", "cp1252", "latin-1")

_NULL_BYTE = b"\x00"
#: Printable ASCII, the usual whitespace/control escapes, and everything above
#: 0x7F (which is legitimate UTF-8 continuation data, not evidence of binary).
_TEXTISH_BYTES = bytes(range(0x20, 0x7F)) + b"\n\r\t\f\b\x1b" + bytes(range(0x80, 0x100))
_BINARY_SNIFF_BYTES = 8192


# --------------------------------------------------------------------------- #
# Byte handling
# --------------------------------------------------------------------------- #


def looks_binary(chunk: bytes) -> bool:
    """Heuristic binary sniff, mirroring what git itself does.

    A NUL byte in the first 8 KiB, or a high proportion of non-text control
    characters, means we refuse to treat the file as source code.
    """
    if not chunk:
        return False
    # UTF-16/32 text legitimately contains NUL bytes, so the BOM check has to
    # run *before* the NUL check or every wide-encoded config looks binary.
    if chunk[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff") or chunk[:2] in (
        b"\xff\xfe",
        b"\xfe\xff",
    ):
        return False
    if _NULL_BYTE in chunk:
        return True
    # `translate` deletes the allowed bytes in C; iterating an 8 KiB chunk byte
    # by byte in Python cost ~6% of total scan time.
    non_text = len(chunk.translate(None, _TEXTISH_BYTES))
    return non_text / len(chunk) > 0.30


def decode_bytes(data: bytes) -> tuple[str, str]:
    """Decode ``data`` to text, returning ``(text, encoding_used)``.

    Raises ``UnicodeDecodeError`` only if every candidate encoding fails, which
    in practice means the input is binary.
    """
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    for encoding in _FALLBACK_ENCODINGS:
        try:
            return data.decode(encoding), encoding
        except (UnicodeDecodeError, UnicodeError):
            continue
    # latin-1 never fails, so reaching here means the earlier attempts were all
    # rejected for structural reasons; decode lossily as a last resort.
    return data.decode("utf-8", errors="replace"), "utf-8/replace"


# --------------------------------------------------------------------------- #
# Ignore handling
# --------------------------------------------------------------------------- #


class IgnoreSpec:
    """A pragmatic subset of ``.gitignore`` semantics.

    Supported: comments, blank lines, negation (``!``), directory-only patterns
    (trailing ``/``), anchored patterns (leading ``/``) and shell globs.
    Not supported: ``**`` spanning multiple path segments with anchoring
    subtleties, and character-class edge cases. Anything unsupported simply
    fails to match, so the scanner errs towards scanning more, never less.
    """

    __slots__ = ("_rules",)

    def __init__(self, patterns: Iterable[str]) -> None:
        self._rules: list[tuple[str, bool, bool]] = []
        for raw in patterns:
            line = raw.rstrip("\n").strip()
            if not line or line.startswith("#"):
                continue
            negated = line.startswith("!")
            if negated:
                line = line[1:]
            dir_only = line.endswith("/")
            line = line.strip("/")
            if line:
                self._rules.append((line, negated, dir_only))

    def __bool__(self) -> bool:
        return bool(self._rules)

    @classmethod
    def from_file(cls, path: Path) -> IgnoreSpec:
        try:
            return cls(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            return cls(())

    def matches(self, relative_path: str, *, is_dir: bool) -> bool:
        result = False
        segments = relative_path.split("/")
        for pattern, negated, dir_only in self._rules:
            if dir_only and not is_dir:
                continue
            hit = fnmatch.fnmatch(relative_path, pattern) or any(
                fnmatch.fnmatch(segment, pattern) for segment in segments
            )
            if not hit and "/" in pattern:
                hit = fnmatch.fnmatch(relative_path, f"*/{pattern}")
            if hit:
                result = not negated
        return result


# --------------------------------------------------------------------------- #
# Options
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ScanOptions:
    """Everything that shapes a scan run."""

    rules: tuple[RuleDefinition, ...] = field(default_factory=default_ruleset)
    entropy: EntropyConfig = DEFAULT_ENTROPY_CONFIG
    enable_entropy: bool = True
    enable_rules: bool = True
    #: Decode base64 values and scan the plaintext with the signature rules.
    decode_base64: bool = True
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS
    excluded_extensions: frozenset[str] = DEFAULT_EXCLUDED_EXTENSIONS
    excluded_filenames: frozenset[str] = DEFAULT_EXCLUDED_FILENAMES
    include_globs: tuple[str, ...] = ()
    exclude_globs: tuple[str, ...] = ()
    max_file_size: int = 5 * 1024 * 1024
    follow_symlinks: bool = False
    #: Detection is CPU-bound Python that holds the GIL, so extra threads buy
    #: nothing on a warm page cache - measured at 521 files/s serial versus
    #: 448 files/s with four threads. Threads only pay off when reads
    #: dominate (cold cache, network mounts); raise this with `--workers` there.
    workers: int = 1
    respect_gitignore: bool = True
    ignore_file: str = ".gitignore"
    min_severity: Severity = Severity.INFO
    #: Entropy findings are informative but noisier; they get their own floor.
    entropy_severity: Severity = Severity.MEDIUM

    def with_entropy_threshold(self, threshold: float | None) -> ScanOptions:
        """Return a copy whose entropy detector uses an absolute threshold."""
        if threshold is None:
            return self
        config = EntropyConfig(
            min_length=self.entropy.min_length,
            max_length=self.entropy.max_length,
            hex_threshold=threshold,
            base64_threshold=threshold,
            generic_threshold=threshold,
            min_unique_ratio=self.entropy.min_unique_ratio,
            use_heuristics=self.entropy.use_heuristics,
        )
        return replace(self, entropy=config)


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


class Scanner:
    """Runs the regex and entropy detectors across files or in-memory text."""

    def __init__(self, options: ScanOptions | None = None) -> None:
        self.options = options or ScanOptions()

    # ---------------------------- public surface ---------------------------- #

    def scan_paths(self, paths: Sequence[str | os.PathLike[str]]) -> ScanSummary:
        """Scan every file reachable from ``paths`` and return a summary."""
        started = time.perf_counter()
        summary = ScanSummary()

        targets = list(self._collect_targets(paths, summary))
        if not targets:
            summary.duration_ms = (time.perf_counter() - started) * 1000
            return summary

        workers = max(1, min(self.options.workers, len(targets)))
        if workers == 1:
            for target, display in targets:
                self._consume(self._scan_one(target, display), summary)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(self._scan_one, target, display): display for target, display in targets
                }
                for future in as_completed(futures):
                    try:
                        self._consume(future.result(), summary)
                    except Exception as exc:  # pragma: no cover - safety net
                        summary.errors.append(ScanError(futures[future], f"{type(exc).__name__}: {exc}"))
                        summary.files_skipped += 1

        summary.findings = deduplicate_findings(summary.findings)
        summary.findings = [f for f in summary.findings if f.severity.rank >= self.options.min_severity.rank]
        summary.duration_ms = (time.perf_counter() - started) * 1000
        return summary

    def scan_text(self, text: str, path: str = "<stdin>") -> ScanSummary:
        """Scan an in-memory document (used for ``--stdin`` and for tests)."""
        started = time.perf_counter()
        summary = ScanSummary()
        findings = list(self._detect(text, path))
        summary.files_scanned = 1
        summary.bytes_scanned = len(text.encode("utf-8", errors="replace"))
        summary.findings = [
            f for f in deduplicate_findings(findings) if f.severity.rank >= self.options.min_severity.rank
        ]
        summary.duration_ms = (time.perf_counter() - started) * 1000
        return summary

    # ------------------------------ traversal ------------------------------- #

    def _collect_targets(
        self, paths: Sequence[str | os.PathLike[str]], summary: ScanSummary
    ) -> Iterator[tuple[Path, str]]:
        for raw in paths:
            root = Path(raw)
            if not root.exists():
                summary.errors.append(ScanError(str(root), "path does not exist"))
                continue
            if root.is_file():
                if self._should_scan_file(root, root.name):
                    yield root, str(root)
                else:
                    summary.files_skipped += 1
                continue
            yield from self._walk(root, summary)

    def _walk(self, root: Path, summary: ScanSummary) -> Iterator[tuple[Path, str]]:
        options = self.options
        ignore = IgnoreSpec(())
        if options.respect_gitignore:
            ignore = IgnoreSpec.from_file(root / options.ignore_file)

        for dirpath, dirnames, filenames in os.walk(
            root,
            topdown=True,
            followlinks=options.follow_symlinks,
            onerror=lambda e: summary.errors.append(
                ScanError(getattr(e, "filename", str(root)), f"{type(e).__name__}: {e}")
            ),
        ):
            current = Path(dirpath)
            kept_dirs: list[str] = []
            for name in dirnames:
                if name in options.excluded_dirs:
                    continue
                rel = self._relative(current / name, root)
                if ignore and ignore.matches(rel, is_dir=True):
                    continue
                kept_dirs.append(name)
            dirnames[:] = kept_dirs

            for name in filenames:
                candidate = current / name
                rel = self._relative(candidate, root)
                if ignore and ignore.matches(rel, is_dir=False):
                    summary.files_skipped += 1
                    continue
                if self._should_scan_file(candidate, rel):
                    yield candidate, str(candidate)
                else:
                    summary.files_skipped += 1

    @staticmethod
    def _relative(path: Path, root: Path) -> str:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:  # pragma: no cover - path outside root
            return path.as_posix()

    def _should_scan_file(self, path: Path, relative: str) -> bool:
        options = self.options
        name = path.name
        if name in options.excluded_filenames:
            return False
        # `.env` and friends have no suffix worth excluding; check the real one.
        suffix = path.suffix.lower()
        if suffix and suffix in options.excluded_extensions:
            return False
        if options.exclude_globs and any(
            fnmatch.fnmatch(relative, g) or fnmatch.fnmatch(name, g) for g in options.exclude_globs
        ):
            return False
        if options.include_globs and not any(
            fnmatch.fnmatch(relative, g) or fnmatch.fnmatch(name, g) for g in options.include_globs
        ):
            return False
        return not (not options.follow_symlinks and path.is_symlink())

    # ------------------------------ file work ------------------------------- #

    def _scan_one(self, path: Path, display: str) -> _FileResult:
        options = self.options
        try:
            size = path.stat().st_size
        except OSError as exc:
            return _FileResult(
                display, [], ScanError(display, f"stat failed: {exc.strerror or exc}"), 0, skipped=True
            )

        if size == 0:
            return _FileResult(display, [], None, 0)
        if size > options.max_file_size:
            return _FileResult(
                display,
                [],
                ScanError(display, f"skipped: {size} bytes exceeds max-file-size ({options.max_file_size})"),
                0,
                skipped=True,
            )

        try:
            data = path.read_bytes()
        except (OSError, MemoryError) as exc:
            return _FileResult(display, [], ScanError(display, f"read failed: {exc}"), 0, skipped=True)

        if looks_binary(data[:_BINARY_SNIFF_BYTES]):
            return _FileResult(display, [], None, 0, skipped=True)

        try:
            text, _encoding = decode_bytes(data)
        except (UnicodeDecodeError, LookupError) as exc:  # pragma: no cover - decode_bytes is total
            return _FileResult(display, [], ScanError(display, f"decode failed: {exc}"), 0, skipped=True)

        try:
            findings = list(self._detect(text, display))
        except Exception as exc:  # pragma: no cover - a rule must never kill the run
            return _FileResult(
                display, [], ScanError(display, f"{type(exc).__name__}: {exc}"), len(data), skipped=True
            )

        return _FileResult(display, findings, None, len(data))

    def _detect(self, text: str, path: str) -> Iterator[Finding]:
        options = self.options
        findings: list[Finding] = []
        if options.enable_rules and options.rules:
            findings.extend(iter_rule_findings(text, path, options.rules, entropy_fn=shannon_entropy))
        if options.enable_entropy:
            findings.extend(self._entropy_findings(text, path))
        if options.enable_rules and options.rules and options.decode_base64:
            encoded = list(iter_encoded_findings(text, path, options.rules))
            if encoded:
                findings = merge_encoded(deduplicate_findings(findings), encoded)
        yield from findings

    def _entropy_findings(self, text: str, path: str) -> Iterator[Finding]:
        options = self.options
        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(line) > 20_000:
                # Minified bundles: analysing them line-by-line is pathological
                # and produces nothing but noise.
                continue
            for result, offset in scan_line_for_entropy(line, options.entropy):
                preview = line.strip()[:200]
                token = result.token
                yield Finding(
                    rule_id="high-entropy-string",
                    rule_name="High Entropy String",
                    severity=options.entropy_severity,
                    detector=DetectorKind.ENTROPY,
                    path=path,
                    line=line_no,
                    column=offset + 1,
                    match=token,
                    redacted=redact(token),
                    entropy=result.entropy,
                    line_preview=preview.replace(token, redact(token)) if token in preview else preview,
                    description=(
                        f"{result.charset} string with {result.entropy:.2f} bits/char of entropy "
                        f"(threshold {result.threshold:.2f})."
                    ),
                    tags=("entropy", result.charset),
                )

    @staticmethod
    def _consume(result: _FileResult, summary: ScanSummary) -> None:
        if result.error is not None:
            summary.errors.append(result.error)
        if result.skipped:
            summary.files_skipped += 1
        else:
            summary.files_scanned += 1
            summary.bytes_scanned += result.size
        summary.findings.extend(result.findings)


@dataclass(slots=True)
class _FileResult:
    path: str
    findings: list[Finding]
    error: ScanError | None
    size: int
    skipped: bool = False
