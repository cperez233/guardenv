"""Shannon entropy analysis with false-positive suppression heuristics.

Raw entropy alone is a famously noisy secret detector: minified JavaScript,
lockfile hashes, base64-encoded images and UUIDs all score highly. This module
pairs a fast entropy kernel with a set of cheap structural heuristics that
discard the well-known benign shapes *before* the threshold comparison happens.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from functools import lru_cache
from itertools import pairwise

__all__ = [
    "Charset",
    "EntropyConfig",
    "EntropyResult",
    "analyze_token",
    "classify_charset",
    "is_benign_token",
    "iter_candidates",
    "normalized_entropy",
    "scan_line_for_entropy",
    "shannon_entropy",
]


class Charset(str):
    """Symbolic charset names (kept as plain strings for cheap serialization)."""

    HEX = "hex"
    BASE64 = "base64"
    BASE64URL = "base64url"
    ALPHANUMERIC = "alphanumeric"
    MIXED = "mixed"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class EntropyConfig:
    """Tunable knobs for the entropy detector.

    Thresholds are expressed in *bits per character*. Different alphabets have
    different theoretical maxima (hex tops out at 4.0 bits/char, base64 at 6.0),
    so each charset carries its own threshold instead of a single global number.
    """

    min_length: int = 20
    max_length: int = 512
    hex_threshold: float = 3.0
    base64_threshold: float = 4.5
    generic_threshold: float = 4.0
    #: Minimum ratio of distinct characters to total length. Filters out
    #: padding, repeated runs and "aaaaaaaaaaaaaaaaaaaa"-style placeholders.
    min_unique_ratio: float = 0.30
    #: When True, apply the structural benign-shape heuristics.
    use_heuristics: bool = True

    def threshold_for(self, charset: str) -> float:
        if charset == Charset.HEX:
            return self.hex_threshold
        if charset in (Charset.BASE64, Charset.BASE64URL):
            return self.base64_threshold
        return self.generic_threshold

    def with_scale(self, scale: float) -> EntropyConfig:
        """Return a copy with every threshold shifted by ``scale`` bits.

        Used by the ``--entropy-threshold`` CLI flag and by the web playground's
        slider, which both express sensitivity as a single number.
        """
        return EntropyConfig(
            min_length=self.min_length,
            max_length=self.max_length,
            hex_threshold=max(0.0, self.hex_threshold + scale),
            base64_threshold=max(0.0, self.base64_threshold + scale),
            generic_threshold=max(0.0, self.generic_threshold + scale),
            min_unique_ratio=self.min_unique_ratio,
            use_heuristics=self.use_heuristics,
        )


DEFAULT_ENTROPY_CONFIG = EntropyConfig()


@dataclass(frozen=True, slots=True)
class EntropyResult:
    """Outcome of analysing a single token."""

    token: str
    entropy: float
    normalized: float
    charset: str
    threshold: float
    suspicious: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "token": self.token,
            "entropy": round(self.entropy, 4),
            "normalized": round(self.normalized, 4),
            "charset": self.charset,
            "threshold": self.threshold,
            "suspicious": self.suspicious,
            "reason": self.reason,
        }


# --------------------------------------------------------------------------- #
# Entropy kernel
# --------------------------------------------------------------------------- #


def _entropy_uncached(value: str) -> float:
    if not value:
        return 0.0
    length = len(value)
    # Counter is implemented in C and beats a manual dict loop for the string
    # sizes we care about (20-512 chars).
    counts = Counter(value)
    inv_len = 1.0 / length
    total = 0.0
    for count in counts.values():
        p = count * inv_len
        total -= p * math.log2(p)
    return total


@lru_cache(maxsize=8192)
def _entropy_cached(value: str) -> float:
    return _entropy_uncached(value)


def shannon_entropy(value: str) -> float:
    """Shannon entropy of ``value`` in bits per character.

    Results for tokens of a reasonable size are memoized; very long strings
    bypass the cache so that scanning a minified bundle cannot blow up memory.
    """
    if not value:
        return 0.0
    if len(value) > 1024:
        return _entropy_uncached(value)
    return _entropy_cached(value)


def normalized_entropy(value: str) -> float:
    """Entropy scaled to ``[0, 1]`` against the token's own alphabet size.

    A 32-char hex string with perfect distribution scores 1.0 here even though
    its absolute entropy is only 4.0 bits/char. Useful for comparing tokens
    drawn from different alphabets on the same axis (the playground scatter
    plot uses the absolute value; ranking uses this one).
    """
    if len(value) < 2:
        return 0.0
    alphabet = len(set(value))
    if alphabet < 2:
        return 0.0
    ceiling = math.log2(min(alphabet, len(value)))
    if ceiling <= 0:
        return 0.0
    return min(1.0, shannon_entropy(value) / ceiling)


# --------------------------------------------------------------------------- #
# Charset classification
# --------------------------------------------------------------------------- #

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_ALNUM_RE = re.compile(r"^[A-Za-z0-9]+$")


def classify_charset(token: str) -> str:
    """Bucket ``token`` into the alphabet family that best describes it."""
    if _HEX_RE.match(token):
        return Charset.HEX
    if _ALNUM_RE.match(token):
        return Charset.ALPHANUMERIC
    if _BASE64_RE.match(token):
        return Charset.BASE64
    if _BASE64URL_RE.match(token):
        return Charset.BASE64URL
    return Charset.MIXED


# --------------------------------------------------------------------------- #
# Benign-shape heuristics
# --------------------------------------------------------------------------- #

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z?)?$")
_SEMVER_RE = re.compile(r"^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$")
_PATH_RE = re.compile(r"^(?:[./~]|[A-Za-z]:\\)|[/\\]{2,}")
_NUMERIC_RE = re.compile(r"^[0-9._,-]+$")
_CSS_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{3,8}$")
# snake_case / SCREAMING_SNAKE_CASE / kebab-case: alphabetic segments joined
# by a single separator. Variable names, not credentials.
_WORDY_RE = re.compile(r"^[A-Za-z]+(?:[_-][A-Za-z]+)+$")
# Reverse-DNS identifiers and hostnames: com.example.app, api.eu.internal
_DOTTED_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+\.?$")
#: Splits a dotted/underscored/slashed identifier into its word segments.
_SEGMENT_SPLIT_RE = re.compile(r"[._\-/]+")
_MIME_DATA_RE = re.compile(r"^data:[a-z]+/", re.IGNORECASE)
_INTEGRITY_RE = re.compile(r"^sha(?:256|384|512)-", re.IGNORECASE)

#: Tokens that appear verbatim in documentation, templates and .env.example
#: files. Matching is case-insensitive and substring-based.
PLACEHOLDER_MARKERS: frozenset[str] = frozenset(
    {
        "changeme",
        "your_",
        "yourapi",
        "yourkey",
        "example",
        "placeholder",
        "dummy",
        "sample",
        "insert",
        "replace",
        "todo",
        "fixme",
        "xxxxxx",
        "000000",
        "111111",
        "abcdef0123",
        "notarealkey",
        "fake",
        "test_key",
        "dummykey",
        "lorem",
        "foobar",
        "<your",
        "${",
        "{{",
        "%s",
    }
)


def _looks_like_english(token: str) -> bool:
    """Detect snake_case / kebab-case / camelCase identifiers.

    These carry high per-character entropy when long, but are structurally
    words, not random bytes.
    """
    if _WORDY_RE.match(token):
        return True
    # camelCase with no digits is almost never a secret: real tokens in this
    # length range essentially always carry digits.
    humps = sum(1 for i, c in enumerate(token) if c.isupper() and i > 0)
    return humps >= 2 and not any(c.isdigit() for c in token) and token[0].islower()


def _has_sequential_run(token: str, length: int = 8) -> bool:
    """True when ``token`` contains a long ascending character run.

    Alphabet constants (``0123456789abcdef...``) score maximum entropy while
    carrying no information at all.
    """
    run = 1
    for previous, current in pairwise(token):
        run = run + 1 if ord(current) - ord(previous) == 1 else 1
        if run >= length:
            return True
    return False


def is_benign_token(token: str, config: EntropyConfig = DEFAULT_ENTROPY_CONFIG) -> tuple[bool, str]:
    """Return ``(is_benign, reason)`` for a candidate token.

    Every rule here is O(len(token)) and runs before the entropy comparison, so
    the common case (ordinary source code) stays cheap.
    """
    if not config.use_heuristics:
        return False, ""

    lowered = token.lower()

    if _UUID_RE.match(token):
        return True, "uuid"
    if _ISO_DATE_RE.match(token):
        return True, "iso-8601-timestamp"
    if _SEMVER_RE.match(token):
        return True, "semantic-version"
    if _NUMERIC_RE.match(token):
        return True, "numeric-literal"
    if _CSS_COLOR_RE.match(token):
        return True, "css-color"
    if _PATH_RE.search(token):
        return True, "filesystem-path"
    if _MIME_DATA_RE.match(token):
        return True, "data-uri"
    if _INTEGRITY_RE.match(token):
        return True, "subresource-integrity-hash"
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True, "documentation-placeholder"
    if _looks_like_english(token):
        return True, "word-like-identifier"
    if _DOTTED_RE.match(token):
        return True, "hostname-or-dotted-identifier"
    if _has_sequential_run(token):
        return True, "sequential-character-run"

    # A dotted/underscored/slashed identifier - `entropy_config.hex_threshold`,
    # `github/codeql-action/upload-sarif`. Long as a whole, but every segment is
    # a short word: no single part of it is long enough to be a credential.
    segments = _SEGMENT_SPLIT_RE.split(token)
    if len(segments) >= 2 and max(len(segment) for segment in segments) < config.min_length:
        return True, "structured-identifier"

    unique_ratio = len(set(token)) / len(token)
    if unique_ratio < config.min_unique_ratio:
        return True, "low-character-variety"

    # A run of the same character covering a third of the token means padding.
    longest_run = 1
    run = 1
    for prev, cur in pairwise(token):
        run = run + 1 if prev == cur else 1
        longest_run = max(longest_run, run)
    if longest_run >= max(4, len(token) // 3):
        return True, "repeated-character-run"

    return False, ""


# --------------------------------------------------------------------------- #
# Token extraction and analysis
# --------------------------------------------------------------------------- #

#: Candidate secrets are runs of "secret-shaped" characters.
#:
#: ``=`` is deliberately *not* part of the interior class: it is the assignment
#: operator in every config format we care about, so allowing it would fuse
#: ``API_KEY=<value>`` into a single token and score the variable name as part
#: of the secret. It is re-admitted only as trailing base64 padding. ``:`` and
#: ``@`` are excluded for the same reason (``host:port``, ``user@host``), while
#: ``.`` stays in because JWTs and dotted keys need it.
_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_\-.~]{16,}={0,2}")


def iter_candidates(text: str, config: EntropyConfig = DEFAULT_ENTROPY_CONFIG) -> Iterator[tuple[str, int]]:
    """Yield ``(token, offset)`` pairs worth running entropy analysis on."""
    for match in _CANDIDATE_RE.finditer(text):
        token = match.group(0).strip("._-~")
        if not token:
            continue
        offset = match.start() + match.group(0).index(token)
        if config.min_length <= len(token) <= config.max_length:
            yield token, offset
        elif len(token) > config.max_length:
            # Very long blobs (base64 images, minified bundles) are analysed on
            # a representative window instead of being dropped outright.
            window = token[: config.max_length]
            yield window, offset


def analyze_token(token: str, config: EntropyConfig = DEFAULT_ENTROPY_CONFIG) -> EntropyResult:
    """Score a single token against the configured thresholds."""
    charset = classify_charset(token)
    threshold = config.threshold_for(charset)
    entropy = shannon_entropy(token)
    normalized = normalized_entropy(token)

    if len(token) < config.min_length:
        return EntropyResult(token, entropy, normalized, charset, threshold, False, "too-short")

    benign, reason = is_benign_token(token, config)
    if benign:
        return EntropyResult(token, entropy, normalized, charset, threshold, False, reason)

    suspicious = entropy >= threshold
    return EntropyResult(
        token,
        entropy,
        normalized,
        charset,
        threshold,
        suspicious,
        "above-threshold" if suspicious else "below-threshold",
    )


def scan_line_for_entropy(
    line: str, config: EntropyConfig = DEFAULT_ENTROPY_CONFIG
) -> list[tuple[EntropyResult, int]]:
    """Analyse every candidate in ``line``; return the suspicious ones."""
    results: list[tuple[EntropyResult, int]] = []
    for token, offset in iter_candidates(line, config):
        result = analyze_token(token, config)
        if result.suspicious:
            results.append((result, offset))
    return results
