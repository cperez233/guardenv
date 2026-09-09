"""Tests for the Shannon entropy engine and its suppression heuristics."""

from __future__ import annotations

import math

import pytest

from guardenv.entropy import (
    Charset,
    EntropyConfig,
    analyze_token,
    classify_charset,
    is_benign_token,
    iter_candidates,
    normalized_entropy,
    scan_line_for_entropy,
    shannon_entropy,
)


class TestShannonEntropy:
    def test_empty_string_has_zero_entropy(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_repeated_character_has_zero_entropy(self) -> None:
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_uniform_binary_alphabet_is_one_bit(self) -> None:
        assert shannon_entropy("abababab") == pytest.approx(1.0)

    def test_uniform_four_symbol_alphabet_is_two_bits(self) -> None:
        assert shannon_entropy("abcdabcdabcd") == pytest.approx(2.0)

    def test_matches_the_textbook_formula(self) -> None:
        value = "aaabbc"
        expected = -sum((count / len(value)) * math.log2(count / len(value)) for count in (3, 2, 1))
        assert shannon_entropy(value) == pytest.approx(expected)

    def test_long_strings_bypass_the_cache_but_agree_with_it(self) -> None:
        token = ("abcdefgh" * 200)[:1600]
        assert shannon_entropy(token) == pytest.approx(3.0)

    def test_random_base64_scores_higher_than_prose(self) -> None:
        prose = "the quick brown fox jumps over the lazy dog"
        secret = "kR8fLpQ2mZvX1sTgH9dYw3EbN0uJc7AiOe5Rt2K"
        assert shannon_entropy(secret) > shannon_entropy(prose)


class TestNormalizedEntropy:
    def test_short_strings_are_zero(self) -> None:
        assert normalized_entropy("a") == 0.0

    def test_uniform_distribution_reaches_one(self) -> None:
        assert normalized_entropy("abcd") == pytest.approx(1.0)

    def test_result_is_bounded(self) -> None:
        for token in ("abcdefgh", "aaaa", "kR8fLpQ2mZvX1sTgH9dYw3EbN0uJc7Ai"):
            assert 0.0 <= normalized_entropy(token) <= 1.0


class TestCharsetClassification:
    @pytest.mark.parametrize(
        ("token", "expected"),
        [
            ("deadbeef0123456789abcdef", Charset.HEX),
            ("AKIAZ4KJQ2WBXY7TDNPQ", Charset.ALPHANUMERIC),
            ("kR8fLpQ2mZv+X1sTgH9dYw3EbN0uJc7A=", Charset.BASE64),
            ("kR8fLpQ2mZv-X1sTgH9dYw3EbN0uJc7A", Charset.BASE64URL),
            ("some/path:with@symbols!", Charset.MIXED),
        ],
    )
    def test_classification(self, token: str, expected: str) -> None:
        assert classify_charset(token) == expected

    def test_hex_wins_over_alphanumeric_for_pure_hex(self) -> None:
        assert classify_charset("abcdef123456") == Charset.HEX


class TestBenignHeuristics:
    @pytest.mark.parametrize(
        ("token", "reason"),
        [
            ("550e8400-e29b-41d4-a716-446655440000", "uuid"),
            ("2026-09-08T12:30:00Z", "iso-8601-timestamp"),
            ("v1.24.3-beta.1", "semantic-version"),
            ("1234567890.123456", "numeric-literal"),
            ("./src/components/Button.tsx", "filesystem-path"),
            ("FEATURE_FLAG_NEW_CHECKOUT", "word-like-identifier"),
            ("api.eu-west-1.internal.acme-corp.io", "hostname-or-dotted-identifier"),
            ("aaaaaaaaaaaaaaaaaaaaaaaa", "low-character-variety"),
            ("YOUR_API_KEY_GOES_HERE_XXXX", "documentation-placeholder"),
            ("sha256-QLbLFhGmv1PHMvpZDU5ZaSMlwPtqoRvsHW0S5nkzZAw=", "subresource-integrity-hash"),
            ("0123456789abcdefghijklmnopqrstuvwxyz", "sequential-character-run"),
            ("entropy_config.hex_threshold", "structured-identifier"),
            ("github/codeql-action/upload-sarif", "structured-identifier"),
            ("verbatimModuleSyntax", "word-like-identifier"),
        ],
    )
    def test_known_benign_shapes_are_suppressed(self, token: str, reason: str) -> None:
        benign, actual = is_benign_token(token)
        assert benign is True
        assert actual == reason

    def test_genuine_secret_is_not_suppressed(self) -> None:
        benign, _ = is_benign_token("kR8fLpQ2mZvX1sTgH9dYw3EbN0uJc7AiOe5Rt2K")
        assert benign is False

    def test_separators_do_not_shield_a_long_segment(self) -> None:
        # The structured-identifier rule must not swallow real tokens that
        # happen to carry a prefix: one segment is still credential-length.
        benign, _ = is_benign_token("glpat-A1b2C3d4E5f6G7h8I9j0")
        assert benign is False

    def test_short_ascending_runs_are_not_suppressed(self) -> None:
        benign, _ = is_benign_token("hV3q9ZxT2LmR8NfPwabcdKdA1sGjB4cXeU")
        assert benign is False

    def test_heuristics_can_be_disabled(self) -> None:
        config = EntropyConfig(use_heuristics=False)
        benign, reason = is_benign_token("550e8400-e29b-41d4-a716-446655440000", config)
        assert benign is False
        assert reason == ""


class TestAnalyzeToken:
    def test_short_tokens_are_rejected_before_scoring(self) -> None:
        result = analyze_token("abc123")
        assert result.suspicious is False
        assert result.reason == "too-short"

    def test_high_entropy_secret_is_flagged(self) -> None:
        result = analyze_token("hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU")
        assert result.suspicious is True
        assert result.reason == "above-threshold"

    def test_hex_uses_its_own_lower_threshold(self) -> None:
        token = "d41d8cd98f00b204e9800998ecf8427e"
        result = analyze_token(token)
        assert result.charset == Charset.HEX
        assert result.threshold == pytest.approx(3.0)
        assert result.suspicious is True

    def test_threshold_scaling_moves_the_verdict(self) -> None:
        token = "hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU"
        assert analyze_token(token, EntropyConfig()).suspicious is True
        strict = EntropyConfig().with_scale(+2.0)
        assert analyze_token(token, strict).suspicious is False

    def test_result_serializes_cleanly(self) -> None:
        payload = analyze_token("hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU").to_dict()
        assert set(payload) == {
            "token",
            "entropy",
            "normalized",
            "charset",
            "threshold",
            "suspicious",
            "reason",
        }


class TestCandidateExtraction:
    def test_assignment_operator_splits_key_from_value(self) -> None:
        line = "SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU"
        tokens = [token for token, _ in iter_candidates(line)]
        assert "hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU" in tokens
        assert not any("SESSION_SECRET=" in token for token in tokens)

    def test_offsets_point_at_the_token(self) -> None:
        line = "SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU"
        for token, offset in iter_candidates(line):
            assert line[offset : offset + len(token)] == token

    def test_oversized_blobs_are_windowed_not_dropped(self) -> None:
        config = EntropyConfig(max_length=64)
        blob = "kR8fLpQ2mZvX1sTgH9dYw" * 20
        tokens = [token for token, _ in iter_candidates(blob, config)]
        assert tokens and all(len(token) <= 64 for token in tokens)

    def test_line_scan_returns_only_suspicious_tokens(self) -> None:
        line = "url = 'https://example.com/docs' ; key = 'hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU'"
        results = scan_line_for_entropy(line)
        assert [r.token for r, _ in results] == ["hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU"]

    def test_empty_input_yields_nothing(self) -> None:
        assert scan_line_for_entropy("") == []
