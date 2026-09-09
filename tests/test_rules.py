"""Tests for the deterministic signature engine."""

from __future__ import annotations

import pytest

from guardenv.models import DetectorKind, Finding, Severity, redact
from guardenv.rules import (
    RULES,
    RULES_BY_ID,
    RuleIndex,
    build_index,
    compile_ruleset,
    deduplicate_findings,
    github_checksum_valid,
    iter_rule_findings,
)

from .conftest import make_github_token


def findings_for(text: str, path: str = "fixture.txt"):
    return list(iter_rule_findings(text, path, RULES))


def rule_ids_for(text: str) -> set[str]:
    return {f.rule_id for f in findings_for(text)}


class TestRulesetIntegrity:
    def test_rule_ids_are_unique(self) -> None:
        ids = [rule.id for rule in RULES]
        assert len(ids) == len(set(ids))

    def test_every_rule_exposes_a_secret_group(self) -> None:
        for rule in RULES:
            assert "secret" in rule.pattern.groupindex, f"{rule.id} lacks a `secret` group"

    def test_every_rule_has_a_description_and_tags(self) -> None:
        for rule in RULES:
            assert rule.description.strip()
            assert rule.tags, f"{rule.id} has no tags"

    def test_keywords_are_lowercased_for_the_prefilter(self) -> None:
        for rule in RULES:
            assert all(keyword == keyword.lower() for keyword in rule.keywords)

    def test_rules_by_id_is_consistent(self) -> None:
        assert set(RULES_BY_ID) == {rule.id for rule in RULES}


class TestCloudProviderRules:
    def test_aws_access_key_id(self) -> None:
        assert "aws-access-key-id" in rule_ids_for("AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ")

    def test_aws_temporary_credential_prefix(self) -> None:
        assert "aws-access-key-id" in rule_ids_for("key: ASIAZ4KJQ2WBXY7TDNPQ")

    def test_aws_secret_access_key_requires_context(self) -> None:
        with_context = 'aws_secret_access_key = "kR8fLpQ2mZv+X1sTgH9dYw3EbN0uJc7AiOe5Rt2K"'
        assert "aws-secret-access-key" in rule_ids_for(with_context)

    def test_aws_documentation_sample_is_allowlisted(self) -> None:
        assert "aws-access-key-id" not in rule_ids_for("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")

    def test_google_api_key(self) -> None:
        assert "gcp-api-key" in rule_ids_for("key = 'AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY'")

    def test_google_oauth_client_secret(self) -> None:
        assert "gcp-oauth-client-secret" in rule_ids_for("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")

    def test_azure_storage_connection_string(self) -> None:
        # Azure account keys are base64 of 64 bytes: 86 characters plus "==".
        account_key = ("kR8fLpQ2mZvX1sTgH9dYw3EbN0uJc7AiOe5Rt2Kp" * 3)[:86] + "=="
        blob = f"DefaultEndpointsProtocol=https;AccountName=prod;AccountKey={account_key};"
        assert "azure-storage-connection-string" in rule_ids_for(blob)


class TestGitForgeRules:
    def test_classic_pat_is_detected(self) -> None:
        assert "github-pat-classic" in rule_ids_for(f"token = '{make_github_token()}'")

    def test_valid_checksum_marks_the_finding_verified(self) -> None:
        token = make_github_token()
        finding = next(f for f in findings_for(token) if f.rule_id == "github-pat-classic")
        assert finding.verified is True

    def test_invalid_checksum_still_reports_but_unverified(self) -> None:
        token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
        finding = next(f for f in findings_for(token) if f.rule_id == "github-pat-classic")
        assert finding.verified is False

    def test_checksum_validator_rejects_malformed_input(self) -> None:
        assert github_checksum_valid("ghp_short") is False
        assert github_checksum_valid("no-underscore") is False
        assert github_checksum_valid("ghp_" + "!" * 36) is False

    def test_fine_grained_pat(self) -> None:
        token = "github_pat_11ABCDEFG0aBcDeFgHiJkL_" + "A" * 59
        assert "github-pat-fine-grained" in rule_ids_for(token)

    def test_oauth_and_server_tokens(self) -> None:
        for prefix in ("gho", "ghu", "ghs", "ghr"):
            assert "github-oauth-token" in rule_ids_for(make_github_token(prefix))

    def test_gitlab_pat(self) -> None:
        assert "gitlab-pat" in rule_ids_for("glpat-A1b2C3d4E5f6G7h8I9j0")


class TestPaymentAndAiRules:
    def test_stripe_live_secret_key(self) -> None:
        assert "stripe-secret-key" in rule_ids_for("sk_live_51H8xkLJk2mQqZzRtYuVbNmAsDfGhJkLp")

    def test_stripe_publishable_key_is_informational(self) -> None:
        finding = next(
            f
            for f in findings_for("pk_live_51H8xkLJk2mQqZzRtYuVbNmAsDfGhJkLp")
            if f.rule_id == "stripe-publishable-key"
        )
        assert finding.severity is Severity.INFO

    def test_openai_project_key(self) -> None:
        key = "sk-proj-9dK2mQxV7bLpR4tNwZ0aT3BlbkFJq8Xc1vY6uHnM2sEr5GdW7pKz"
        assert "openai-api-key" in rule_ids_for(key)

    def test_anthropic_key(self) -> None:
        key = "sk-ant-api03-" + "A1b2C3d4E5" * 9
        assert "anthropic-api-key" in rule_ids_for(key)


class TestKeyMaterialRules:
    @pytest.mark.parametrize("kind", ["RSA ", "EC ", "DSA ", "OPENSSH ", ""])
    def test_pem_private_key_headers(self, kind: str) -> None:
        block = f"-----BEGIN {kind}PRIVATE KEY-----\nMIIEow==\n-----END {kind}PRIVATE KEY-----"
        assert "private-key-block" in rule_ids_for(block)

    def test_public_key_header_is_not_a_finding(self) -> None:
        assert "private-key-block" not in rule_ids_for("-----BEGIN PUBLIC KEY-----")

    def test_jwt_is_detected(self) -> None:
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        assert "json-web-token" in rule_ids_for(jwt)


class TestConnectionStringRules:
    @pytest.mark.parametrize(
        ("uri", "rule_id"),
        [
            ("postgresql://svc:Tr0ub4dor3xK@db.internal:5432/billing", "postgres-connection-string"),
            ("mysql://root:Hunter2Hunter2@10.0.0.4:3306/app", "mysql-connection-string"),
            ("mongodb+srv://admin:S3cretPass@cluster0.mongo.net/db", "mongodb-connection-string"),
            ("redis://:qN7vWx2LmR9tYbA4@cache:6379/0", "redis-connection-string"),
            ("amqps://user:R4bb1tMQpass@broker:5671/vhost", "amqp-connection-string"),
        ],
    )
    def test_credentials_in_uris(self, uri: str, rule_id: str) -> None:
        assert rule_id in rule_ids_for(uri)

    def test_placeholder_password_is_allowlisted(self) -> None:
        assert "postgres-connection-string" not in rule_ids_for(
            "postgresql://user:password@localhost:5432/db"
        )

    def test_uri_without_credentials_is_ignored(self) -> None:
        assert "postgres-connection-string" not in rule_ids_for("postgresql://localhost:5432/db")


class TestGenericRules:
    def test_dotenv_assignment(self) -> None:
        assert "dotenv-secret-assignment" in rule_ids_for("SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU")

    def test_dotenv_export_prefix_is_supported(self) -> None:
        assert "dotenv-secret-assignment" in rule_ids_for("export API_TOKEN=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU")

    def test_environment_indirection_is_not_a_finding(self) -> None:
        assert "generic-secret-assignment" not in rule_ids_for('api_key = os.environ["SERVICE_API_KEY"]')

    def test_boolean_and_numeric_values_are_allowlisted(self) -> None:
        assert rule_ids_for("DEBUG=true\nTOKEN_TTL=3600\n") == set()

    def test_low_entropy_value_does_not_trip_the_generic_rule(self) -> None:
        assert "generic-secret-assignment" not in rule_ids_for('password = "aaaaaaaaaaaaaa"')


class TestLocationReporting:
    def test_line_numbers_are_one_based_and_accurate(self) -> None:
        text = "\n\n\nAWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ\n"
        finding = next(f for f in findings_for(text) if f.rule_id == "aws-access-key-id")
        assert finding.line == 4

    def test_document_scoped_rules_report_the_right_line(self) -> None:
        text = "a=1\nb=2\nSESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n"
        finding = next(f for f in findings_for(text) if f.rule_id == "dotenv-secret-assignment")
        assert finding.line == 3

    def test_column_points_inside_the_line(self) -> None:
        line = "token = 'AKIAZ4KJQ2WBXY7TDNPQ'"
        finding = next(f for f in findings_for(line) if f.rule_id == "aws-access-key-id")
        assert line[finding.column - 1 :].startswith("AKIA")

    def test_preview_never_contains_the_raw_secret(self) -> None:
        for finding in findings_for("AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ"):
            assert finding.match not in finding.line_preview

    def test_empty_input_produces_nothing(self) -> None:
        assert findings_for("") == []


class TestDeduplication:
    def test_specific_rule_beats_generic_rule(self) -> None:
        text = "AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ"
        kept = {f.rule_id for f in deduplicate_findings(findings_for(text))}
        assert kept == {"aws-access-key-id"}

    def test_entropy_finding_yields_to_a_regex_finding(self) -> None:
        secret = "AKIAZ4KJQ2WBXY7TDNPQ"
        regex_finding = next(f for f in findings_for(secret) if f.rule_id == "aws-access-key-id")
        entropy_finding = Finding(
            rule_id="high-entropy-string",
            rule_name="High Entropy String",
            severity=Severity.MEDIUM,
            detector=DetectorKind.ENTROPY,
            path="fixture.txt",
            line=regex_finding.line,
            column=regex_finding.column,
            match=secret,
            redacted=redact(secret),
        )
        kept = deduplicate_findings([entropy_finding, regex_finding])
        assert [f.detector for f in kept] == [DetectorKind.REGEX]

    def test_distinct_secrets_on_one_line_are_both_kept(self) -> None:
        text = "a=AKIAZ4KJQ2WBXY7TDNPQ b=glpat-A1b2C3d4E5f6G7h8I9j0"
        kept = {f.rule_id for f in deduplicate_findings(findings_for(text))}
        assert {"aws-access-key-id", "gitlab-pat"} <= kept


class TestRulesetCompilation:
    def test_include_filter(self) -> None:
        selected = compile_ruleset(include=["aws-access-key-id"])
        assert [rule.id for rule in selected] == ["aws-access-key-id"]

    def test_exclude_filter(self) -> None:
        selected = compile_ruleset(exclude=["aws-access-key-id"])
        assert "aws-access-key-id" not in {rule.id for rule in selected}

    def test_severity_floor(self) -> None:
        selected = compile_ruleset(min_severity=Severity.CRITICAL)
        assert all(rule.severity is Severity.CRITICAL for rule in selected)

    def test_unknown_rule_id_raises(self) -> None:
        with pytest.raises(KeyError, match="no-such-rule"):
            compile_ruleset(include=["no-such-rule"])


class TestRuleIndex:
    """The keyword prefilter must never cost recall, only time."""

    def test_partitions_line_and_document_rules(self) -> None:
        index = RuleIndex(RULES)
        assert set(index.line_rules) | set(index.document_rules) == set(RULES)
        assert not set(index.line_rules) & set(index.document_rules)

    def test_selects_rules_whose_keyword_is_present(self) -> None:
        index = RuleIndex(RULES)
        ids = {rule.id for rule in index.candidates("token = ghp_something")}
        assert "github-pat-classic" in ids

    def test_rejects_rules_whose_keyword_is_absent(self) -> None:
        index = RuleIndex(RULES)
        ids = {rule.id for rule in index.candidates("x = 1")}
        assert "github-pat-classic" not in ids
        assert "stripe-secret-key" not in ids

    def test_finds_keywords_that_overlap_a_longer_one(self) -> None:
        # `ac` (Twilio) starts inside `accountkey` (Azure). A prefilter that
        # consumed the longer match would silently drop the Twilio rule.
        index = RuleIndex(RULES)
        ids = {rule.id for rule in index.candidates("accountkey=abc")}
        assert {"azure-storage-connection-string", "twilio-account-sid"} <= ids

    def test_result_preserves_ruleset_order(self) -> None:
        index = RuleIndex(RULES)
        selected = index.candidates("key secret token ghp_ akia sk_live_ postgres://")
        order = {rule.id: i for i, rule in enumerate(index.line_rules)}
        positions = [order[rule.id] for rule in selected]
        assert positions == sorted(positions)

    def test_is_a_superset_of_what_actually_matches(self) -> None:
        # The property that matters: anything the full ruleset would report must
        # survive the prefilter. Check it against every rule's own fixture line.
        index = RuleIndex(RULES)
        samples = [
            "AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ",
            "token = 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'",
            "sk_live_51H8xkLJk2mQqZzRtYuVbNmAsDfGhJkLp",
            "postgresql://svc:Tr0ub4dor3xK@db.internal:5432/billing",
            "-----BEGIN RSA PRIVATE KEY-----",
            "glpat-A1b2C3d4E5f6G7h8I9j0",
        ]
        for sample in samples:
            expected = {f.rule_id for f in findings_for(sample)}
            available = {r.id for r in index.candidates(sample.lower())} | {
                r.id for r in index.document_rules
            }
            assert expected <= available, sample

    def test_build_index_is_memoized(self) -> None:
        assert build_index(tuple(RULES)) is build_index(tuple(RULES))

    def test_empty_ruleset_yields_nothing(self) -> None:
        index = RuleIndex(())
        assert index.candidates("AKIAZ4KJQ2WBXY7TDNPQ") == ()
