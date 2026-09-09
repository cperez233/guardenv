"""Deterministic signatures for credential detection.

Design notes
------------
* Every pattern exposes a named ``secret`` group so reporters can redact the
  credential without guessing which capture holds it.
* Each rule declares ``keywords``: a cheap ``substring in line`` pre-filter that
  runs before the regex engine. On real repositories this skips >95% of
  rule/line pairs and is the single biggest reason the scanner stays fast.
* ``allowlist`` patterns kill the documentation examples that vendors publish
  (``AKIAIOSFODNN7EXAMPLE`` and friends) before they ever reach a report.
* Some rules carry a ``validator`` that can *upgrade* a finding to
  ``verified=True`` (e.g. GitHub's CRC32 checksum). A failed validation never
  suppresses a finding - it only withholds the confidence boost.
"""

from __future__ import annotations

import re
import zlib
from bisect import bisect_right
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from itertools import accumulate
from re import Pattern

from .entropy import shannon_entropy
from .models import DetectorKind, Finding, Severity, redact

__all__ = [
    "RULES",
    "RULES_BY_ID",
    "RuleDefinition",
    "compile_ruleset",
    "deduplicate_findings",
    "default_ruleset",
    "iter_rule_findings",
]

Validator = Callable[[str], bool]


# --------------------------------------------------------------------------- #
# Validators
# --------------------------------------------------------------------------- #

_BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _base62_decode(value: str) -> int:
    total = 0
    for char in value:
        index = _BASE62.find(char)
        if index < 0:
            raise ValueError(f"non-base62 character {char!r}")
        total = total * 62 + index
    return total


def github_checksum_valid(token: str) -> bool:
    """Verify the CRC32 checksum GitHub embeds in its ``gh*_`` tokens.

    Layout: ``<prefix>_<30 chars of entropy><6 chars of base62 CRC32>``.
    Returns ``False`` (never raises) for anything that does not fit the layout.
    """
    _, _, body = token.partition("_")
    if len(body) < 12:
        return False
    payload, checksum = body[:-6], body[-6:]
    try:
        expected = _base62_decode(checksum)
    except ValueError:
        return False
    return zlib.crc32(payload.encode("ascii")) == expected


# --------------------------------------------------------------------------- #
# Rule definition
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """A single detection signature."""

    id: str
    name: str
    description: str
    severity: Severity
    pattern: Pattern[str]
    keywords: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    allowlist: tuple[Pattern[str], ...] = ()
    #: Minimum Shannon entropy the captured secret must reach. ``None`` disables
    #: the check (used by rules whose shape is already unambiguous).
    entropy_min: float | None = None
    validator: Validator | None = None
    #: Rules that legitimately span several lines (PEM blocks).
    multiline: bool = False

    def is_allowlisted(self, secret: str) -> bool:
        return any(pattern.search(secret) for pattern in self.allowlist)

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "tags": list(self.tags),
            "entropyMin": self.entropy_min,
            "multiline": self.multiline,
            "pattern": self.pattern.pattern,
        }


def _rule(
    id: str,
    name: str,
    description: str,
    severity: Severity,
    pattern: str,
    *,
    keywords: Sequence[str] = (),
    tags: Sequence[str] = (),
    allowlist: Sequence[str] = (),
    entropy_min: float | None = None,
    validator: Validator | None = None,
    flags: int = 0,
    multiline: bool = False,
) -> RuleDefinition:
    return RuleDefinition(
        id=id,
        name=name,
        description=description,
        severity=severity,
        pattern=re.compile(pattern, flags),
        keywords=tuple(k.lower() for k in keywords),
        tags=tuple(tags),
        allowlist=tuple(re.compile(a, re.IGNORECASE) for a in allowlist),
        entropy_min=entropy_min,
        validator=validator,
        multiline=multiline,
    )


# Shared allowlist fragments: vendor documentation samples and obvious stubs.
_DOC_SAMPLES = (
    r"EXAMPLE",
    r"^(?:x{6,}|X{6,}|0{6,}|1{6,}|a{6,}|A{6,})",
    r"(?:your|my|the)[-_]?(?:api|secret|access|private)?[-_]?key",
    r"REPLACE[-_]?ME|CHANGE[-_]?ME|PLACEHOLDER|DUMMY|SAMPLE|NOT[-_]?REAL",
    r"^\$\{|^\{\{|^<[a-z]",
)


# --------------------------------------------------------------------------- #
# The ruleset
# --------------------------------------------------------------------------- #

RULES: tuple[RuleDefinition, ...] = (
    # ---------------------------- Cloud providers ---------------------------- #
    _rule(
        "aws-access-key-id",
        "AWS Access Key ID",
        "Long-lived AWS access key identifier (AKIA) or temporary credential prefix.",
        Severity.CRITICAL,
        r"\b(?P<secret>(?:AKIA|ASIA|ABIA|ACCA|AIDA|AGPA|AROA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b",
        keywords=("akia", "asia", "abia", "acca", "aida", "agpa", "aroa", "anpa", "anva", "a3t"),
        tags=("aws", "cloud", "iam"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "aws-secret-access-key",
        "AWS Secret Access Key",
        "40-character AWS secret assigned to an access key ID.",
        Severity.CRITICAL,
        r"(?i)aws[-_ ]?(?:secret|private)[-_ ]?(?:access[-_ ]?)?key\w*\s*[:=]\s*"
        r"[\"']?(?P<secret>[A-Za-z0-9/+=]{40})[\"']?",
        keywords=("aws",),
        tags=("aws", "cloud", "iam"),
        allowlist=_DOC_SAMPLES,
        entropy_min=3.5,
    ),
    _rule(
        "aws-session-token",
        "AWS Session Token",
        "Short-lived STS session token; still grants full API access until expiry.",
        Severity.HIGH,
        r"(?i)aws[-_ ]?session[-_ ]?token\w*\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9/+=]{100,})[\"']?",
        keywords=("aws_session_token", "aws-session-token", "aws session token"),
        tags=("aws", "cloud", "sts"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "gcp-api-key",
        "Google Cloud API Key",
        "Google/Firebase API key (AIza prefix).",
        Severity.HIGH,
        r"\b(?P<secret>AIza[0-9A-Za-z_\-]{35})\b",
        keywords=("aiza",),
        tags=("gcp", "google", "firebase"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "gcp-oauth-client-secret",
        "Google OAuth Client Secret",
        "Google OAuth 2.0 client secret (GOCSPX prefix).",
        Severity.CRITICAL,
        r"\b(?P<secret>GOCSPX-[A-Za-z0-9_\-]{28})\b",
        keywords=("gocspx",),
        tags=("gcp", "google", "oauth"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "gcp-service-account",
        "GCP Service Account Key File",
        "Service-account JSON containing an embedded private key.",
        Severity.CRITICAL,
        r"[\"']type[\"']\s*:\s*[\"'](?P<secret>service_account)[\"']",
        keywords=("service_account",),
        tags=("gcp", "google", "iam"),
    ),
    _rule(
        "azure-storage-connection-string",
        "Azure Storage Connection String",
        "Azure Storage account key embedded in a connection string.",
        Severity.CRITICAL,
        r"AccountKey\s*=\s*(?P<secret>[A-Za-z0-9+/=]{86,88})",
        keywords=("accountkey",),
        tags=("azure", "cloud", "storage"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "azure-ad-client-secret",
        "Azure AD Client Secret",
        "Entra ID / Azure AD application client secret.",
        Severity.CRITICAL,
        r"\b(?P<secret>[A-Za-z0-9_~.\-]{3}8Q~[A-Za-z0-9_~.\-]{34})\b",
        keywords=("8q~",),
        tags=("azure", "entra", "oauth"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "digitalocean-token",
        "DigitalOcean Personal Access Token",
        "DigitalOcean API token (dop_v1 prefix).",
        Severity.CRITICAL,
        r"\b(?P<secret>dop_v1_[a-f0-9]{64})\b",
        keywords=("dop_v1_",),
        tags=("digitalocean", "cloud"),
    ),
    # ------------------------------- Git forges ------------------------------ #
    _rule(
        "github-pat-classic",
        "GitHub Personal Access Token (classic)",
        "Classic GitHub PAT; grants the scopes selected at creation time.",
        Severity.CRITICAL,
        r"\b(?P<secret>ghp_[A-Za-z0-9]{36})\b",
        keywords=("ghp_",),
        tags=("github", "vcs", "scm"),
        allowlist=_DOC_SAMPLES,
        validator=github_checksum_valid,
    ),
    _rule(
        "github-pat-fine-grained",
        "GitHub Fine-grained Personal Access Token",
        "Fine-grained GitHub PAT scoped to specific repositories.",
        Severity.CRITICAL,
        r"\b(?P<secret>github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b",
        keywords=("github_pat_",),
        tags=("github", "vcs", "scm"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "github-oauth-token",
        "GitHub OAuth / App Token",
        "GitHub OAuth access (gho_), user-to-server (ghu_), server (ghs_) or refresh (ghr_) token.",
        Severity.CRITICAL,
        r"\b(?P<secret>gh[ousr]_[A-Za-z0-9]{36})\b",
        keywords=("gho_", "ghu_", "ghs_", "ghr_"),
        tags=("github", "vcs", "oauth"),
        allowlist=_DOC_SAMPLES,
        validator=github_checksum_valid,
    ),
    _rule(
        "gitlab-pat",
        "GitLab Personal Access Token",
        "GitLab PAT (glpat prefix).",
        Severity.CRITICAL,
        r"\b(?P<secret>glpat-[A-Za-z0-9_\-]{20})\b",
        keywords=("glpat-",),
        tags=("gitlab", "vcs", "scm"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "gitlab-runner-token",
        "GitLab Runner Registration Token",
        "Token allowing registration of a CI runner against a GitLab project.",
        Severity.HIGH,
        r"\b(?P<secret>glrt-[A-Za-z0-9_\-]{20})\b",
        keywords=("glrt-",),
        tags=("gitlab", "ci"),
    ),
    # ------------------------------- Payments -------------------------------- #
    _rule(
        "stripe-secret-key",
        "Stripe Secret Key",
        "Stripe live/test secret or restricted key; can move money.",
        Severity.CRITICAL,
        r"\b(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,247})\b",
        keywords=("sk_live_", "sk_test_", "rk_live_", "rk_test_"),
        tags=("stripe", "payments", "pci"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "stripe-publishable-key",
        "Stripe Publishable Key",
        "Client-side Stripe key. Not secret, but flags the environment in use.",
        Severity.INFO,
        r"\b(?P<secret>pk_(?:live|test)_[A-Za-z0-9]{24,247})\b",
        keywords=("pk_live_", "pk_test_"),
        tags=("stripe", "payments", "informational"),
    ),
    _rule(
        "square-access-token",
        "Square Access Token",
        "Square OAuth or personal access token.",
        Severity.CRITICAL,
        r"\b(?P<secret>sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,43})\b",
        keywords=("sq0atp-", "sq0csp-"),
        tags=("square", "payments"),
    ),
    _rule(
        "paypal-braintree-token",
        "Braintree Access Token",
        "Braintree/PayPal production access token.",
        Severity.CRITICAL,
        r"\b(?P<secret>access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})\b",
        keywords=("access_token$production$",),
        tags=("paypal", "braintree", "payments"),
    ),
    # --------------------------------- AI/ML --------------------------------- #
    _rule(
        "openai-api-key",
        "OpenAI API Key",
        "OpenAI secret key (legacy, project or service-account form).",
        Severity.CRITICAL,
        r"\b(?P<secret>sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}T3BlbkFJ[A-Za-z0-9_\-]{16,})\b",
        keywords=("sk-", "t3blbkfj"),
        tags=("openai", "ai", "llm"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "openai-api-key-legacy",
        "OpenAI API Key (legacy format)",
        "Pre-2023 OpenAI key: sk- followed by 48 base62 characters.",
        Severity.CRITICAL,
        r"\b(?P<secret>sk-[A-Za-z0-9]{48})\b",
        keywords=("sk-",),
        tags=("openai", "ai", "llm"),
        allowlist=_DOC_SAMPLES,
        entropy_min=4.0,
    ),
    _rule(
        "anthropic-api-key",
        "Anthropic API Key",
        "Anthropic Claude API key (sk-ant prefix).",
        Severity.CRITICAL,
        r"\b(?P<secret>sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_\-]{80,120})\b",
        keywords=("sk-ant-",),
        tags=("anthropic", "ai", "llm"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "huggingface-token",
        "Hugging Face Access Token",
        "Hugging Face user or organization access token.",
        Severity.HIGH,
        r"\b(?P<secret>hf_[A-Za-z0-9]{34,40})\b",
        keywords=("hf_",),
        tags=("huggingface", "ai", "ml"),
        allowlist=_DOC_SAMPLES,
    ),
    # ------------------------------ Comms / SaaS ----------------------------- #
    _rule(
        "slack-token",
        "Slack API Token",
        "Slack bot, user, app or legacy workspace token.",
        Severity.CRITICAL,
        r"\b(?P<secret>xox[baprse]-(?:[0-9a-zA-Z]{10,48}-){1,4}[0-9a-zA-Z]{10,48})\b",
        keywords=("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe-"),
        tags=("slack", "saas", "chat"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "slack-webhook",
        "Slack Incoming Webhook",
        "Slack webhook URL; allows posting messages into a workspace channel.",
        Severity.HIGH,
        r"(?P<secret>https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9+/]{6,}"
        r"/[A-Za-z0-9+/]{6,}/[A-Za-z0-9+/]{12,})",
        keywords=("hooks.slack.com",),
        tags=("slack", "webhook"),
    ),
    _rule(
        "discord-bot-token",
        "Discord Bot Token",
        "Discord bot token; full control of the bot account.",
        Severity.HIGH,
        r"\b(?P<secret>[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,38})\b",
        keywords=("discord", "bot "),
        tags=("discord", "chat", "bot"),
    ),
    _rule(
        "telegram-bot-token",
        "Telegram Bot Token",
        "Telegram Bot API token (numeric id + secret).",
        Severity.HIGH,
        r"\b(?P<secret>\d{8,10}:AA[A-Za-z0-9_\-]{33})\b",
        keywords=(":aa",),
        tags=("telegram", "chat", "bot"),
    ),
    _rule(
        "twilio-api-key",
        "Twilio API Key SID",
        "Twilio API key SID; pairs with a secret to authenticate REST calls.",
        Severity.HIGH,
        r"\b(?P<secret>SK[0-9a-fA-F]{32})\b",
        keywords=("sk",),
        tags=("twilio", "sms", "voice"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "twilio-account-sid",
        "Twilio Account SID",
        "Twilio account identifier; sensitive when paired with an auth token.",
        Severity.MEDIUM,
        r"\b(?P<secret>AC[0-9a-fA-F]{32})\b",
        keywords=("ac",),
        tags=("twilio", "sms"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "sendgrid-api-key",
        "SendGrid API Key",
        "SendGrid API key; allows sending mail as the account.",
        Severity.CRITICAL,
        r"\b(?P<secret>SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b",
        keywords=("sg.",),
        tags=("sendgrid", "email"),
    ),
    _rule(
        "mailgun-api-key",
        "Mailgun API Key",
        "Mailgun private API key.",
        Severity.HIGH,
        r"\b(?P<secret>key-[0-9a-zA-Z]{32})\b",
        keywords=("key-",),
        tags=("mailgun", "email"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "shopify-token",
        "Shopify Access Token",
        "Shopify private app, custom app or partner token.",
        Severity.CRITICAL,
        r"\b(?P<secret>shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b",
        keywords=("shpat_", "shpca_", "shppa_", "shpss_"),
        tags=("shopify", "ecommerce"),
    ),
    _rule(
        "npm-access-token",
        "npm Access Token",
        "npm automation or publish token.",
        Severity.CRITICAL,
        r"\b(?P<secret>npm_[A-Za-z0-9]{36})\b",
        keywords=("npm_",),
        tags=("npm", "registry", "supply-chain"),
        allowlist=_DOC_SAMPLES,
    ),
    _rule(
        "pypi-upload-token",
        "PyPI Upload Token",
        "PyPI API token; permits publishing packages under the account.",
        Severity.CRITICAL,
        r"\b(?P<secret>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b",
        keywords=("pypi-",),
        tags=("pypi", "registry", "supply-chain"),
    ),
    _rule(
        "hashicorp-vault-token",
        "HashiCorp Vault Token",
        "Vault service or batch token.",
        Severity.CRITICAL,
        r"\b(?P<secret>hv[sb]\.[A-Za-z0-9_\-]{24,})\b",
        keywords=("hvs.", "hvb."),
        tags=("vault", "hashicorp", "secrets-manager"),
    ),
    _rule(
        "terraform-cloud-token",
        "Terraform Cloud API Token",
        "HCP Terraform / Terraform Cloud user or team token.",
        Severity.CRITICAL,
        r"\b(?P<secret>[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,})\b",
        keywords=(".atlasv1.",),
        tags=("terraform", "hashicorp", "iac"),
    ),
    _rule(
        "datadog-api-key",
        "Datadog API Key",
        "Datadog API key declared next to a Datadog-specific variable name.",
        Severity.HIGH,
        r"(?i)\bdd[-_ ]?(?:api|app)[-_ ]?key\w*\s*[:=]\s*[\"']?(?P<secret>[a-f0-9]{32,40})[\"']?",
        keywords=("dd_api_key", "dd-api-key", "datadog"),
        tags=("datadog", "observability"),
        allowlist=_DOC_SAMPLES,
    ),
    # ------------------------------ Key material ----------------------------- #
    _rule(
        "private-key-block",
        "Cryptographic Private Key",
        "PEM-encoded private key (RSA, EC, DSA, OpenSSH or PGP).",
        Severity.CRITICAL,
        r"(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)",
        keywords=("-----begin",),
        tags=("crypto", "pki", "ssh"),
    ),
    _rule(
        "putty-private-key",
        "PuTTY Private Key",
        "PuTTY PPK private key header.",
        Severity.CRITICAL,
        r"(?P<secret>PuTTY-User-Key-File-[23]:)",
        keywords=("putty-user-key-file",),
        tags=("crypto", "ssh"),
    ),
    _rule(
        "json-web-token",
        "JSON Web Token",
        "Signed JWT. Often a session or service credential.",
        Severity.MEDIUM,
        r"\b(?P<secret>eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b",
        keywords=("eyj",),
        tags=("jwt", "session", "auth"),
    ),
    # --------------------------- Connection strings -------------------------- #
    _rule(
        "postgres-connection-string",
        "PostgreSQL Connection String",
        "PostgreSQL URI with inline credentials.",
        Severity.CRITICAL,
        r"(?i)(?P<secret>postgres(?:ql)?://[^:/\s@\"']+:[^@/\s\"']{3,}@[^\s/\"']+)",
        keywords=("postgres://", "postgresql://"),
        tags=("database", "postgres", "connection-string"),
        allowlist=(*_DOC_SAMPLES, r":(?:password|pass|pwd|secret|\*+)@"),
    ),
    _rule(
        "mysql-connection-string",
        "MySQL Connection String",
        "MySQL/MariaDB URI with inline credentials.",
        Severity.CRITICAL,
        r"(?i)(?P<secret>mysql(?:x)?://[^:/\s@\"']+:[^@/\s\"']{3,}@[^\s/\"']+)",
        keywords=("mysql://", "mysqlx://"),
        tags=("database", "mysql", "connection-string"),
        allowlist=(*_DOC_SAMPLES, r":(?:password|pass|pwd|secret|\*+)@"),
    ),
    _rule(
        "mongodb-connection-string",
        "MongoDB Connection String",
        "MongoDB URI with inline credentials.",
        Severity.CRITICAL,
        r"(?i)(?P<secret>mongodb(?:\+srv)?://[^:/\s@\"']+:[^@/\s\"']{3,}@[^\s/\"']+)",
        keywords=("mongodb://", "mongodb+srv://"),
        tags=("database", "mongodb", "connection-string"),
        allowlist=(*_DOC_SAMPLES, r":(?:password|pass|pwd|secret|\*+)@"),
    ),
    _rule(
        "redis-connection-string",
        "Redis Connection String",
        "Redis URI carrying an inline password.",
        Severity.HIGH,
        r"(?i)(?P<secret>rediss?://[^:/\s@\"']*:[^@/\s\"']{3,}@[^\s/\"']+)",
        keywords=("redis://", "rediss://"),
        tags=("database", "redis", "connection-string"),
        allowlist=(*_DOC_SAMPLES, r":(?:password|pass|pwd|secret|\*+)@"),
    ),
    _rule(
        "amqp-connection-string",
        "AMQP Connection String",
        "RabbitMQ/AMQP URI carrying inline credentials.",
        Severity.HIGH,
        r"(?i)(?P<secret>amqps?://[^:/\s@\"']+:[^@/\s\"']{3,}@[^\s/\"']+)",
        keywords=("amqp://", "amqps://"),
        tags=("queue", "rabbitmq", "connection-string"),
        allowlist=(*_DOC_SAMPLES, r":(?:password|pass|pwd|secret|\*+)@"),
    ),
    _rule(
        "basic-auth-url",
        "Credentials Embedded in URL",
        "HTTP(S) URL with user:password basic-auth credentials.",
        Severity.HIGH,
        r"(?i)(?P<secret>https?://[^:/\s@\"']+:[^@/\s\"']{3,}@[^\s/\"']+)",
        keywords=("http://", "https://"),
        tags=("http", "basic-auth", "connection-string"),
        allowlist=(*_DOC_SAMPLES, r":(?:password|pass|pwd|secret|token|\*+)@"),
    ),
    _rule(
        "npmrc-auth-token",
        "npmrc Auth Token",
        "Registry auth token stored in .npmrc / CI configuration.",
        Severity.CRITICAL,
        r"(?i)_auth(?:Token)?\s*=\s*(?P<secret>[A-Za-z0-9+/=_\-]{16,})",
        keywords=("_auth",),
        tags=("npm", "registry", "supply-chain"),
        allowlist=_DOC_SAMPLES,
    ),
    # ------------------------------- Generic --------------------------------- #
    _rule(
        "generic-secret-assignment",
        "Generic Secret Assignment",
        "A secret-shaped value assigned to a variable whose name implies a credential.",
        Severity.MEDIUM,
        r"(?i)\b(?P<key>[A-Za-z0-9_\-.]*(?:api[-_]?key|secret|passwd|password|token|"
        r"auth|credential|private[-_]?key|access[-_]?key|client[-_]?secret)[A-Za-z0-9_\-.]*)\b"
        r"\s*[:=]{1,2}\s*[\"'](?P<secret>[^\"'\n]{12,120})[\"']",
        keywords=(
            "key",
            "secret",
            "passwd",
            "password",
            "token",
            "auth",
            "credential",
        ),
        tags=("generic", "heuristic"),
        allowlist=(
            *_DOC_SAMPLES,
            r"^(?:true|false|null|none|undefined|localhost)$",
            r"^[a-z]+(?:[-_][a-z]+)*$",
            r"^\d+$",
            r"^(?:process\.env|os\.environ|env\[|config\.|settings\.)",
        ),
        entropy_min=3.2,
    ),
    _rule(
        "dotenv-secret-assignment",
        "Dotenv Secret Assignment",
        "KEY=value line in a .env-style file where the key name implies a credential. "
        "Matched case-sensitively: an uppercase key is what distinguishes a dotenv "
        "entry from an ordinary lowercase keyword argument in source code.",
        Severity.HIGH,
        r"(?m)^[ \t]*(?:export[ \t]+)?(?P<key>[A-Z0-9_]*(?:API[-_]?KEY|SECRET|PASSWD|PASSWORD|TOKEN|"
        r"AUTH|CREDENTIAL|PRIVATE[-_]?KEY|ACCESS[-_]?KEY|CLIENT[-_]?SECRET)[A-Z0-9_]*)[ \t]*=[ \t]*"
        r"[\"']?(?P<secret>[^\s\"'#]{8,200})[\"']?[ \t]*(?:#.*)?$",
        keywords=("key", "secret", "passwd", "password", "token", "auth", "credential"),
        tags=("dotenv", "generic", "heuristic"),
        allowlist=(
            *_DOC_SAMPLES,
            r"^(?:true|false|null|none|undefined|localhost)$",
            r"^\$\{?[A-Z_]+\}?$",
            r"^\d+$",
        ),
        entropy_min=2.8,
    ),
)

RULES_BY_ID: dict[str, RuleDefinition] = {rule.id: rule for rule in RULES}


def default_ruleset() -> tuple[RuleDefinition, ...]:
    """Return the built-in ruleset."""
    return RULES


def compile_ruleset(
    *,
    include: Sequence[str] | None = None,
    exclude: Sequence[str] | None = None,
    min_severity: Severity | None = None,
) -> tuple[RuleDefinition, ...]:
    """Filter the built-in ruleset by id and/or severity floor.

    Raises ``KeyError`` when an unknown rule id is referenced so that typos in
    CI configuration fail loudly instead of silently disabling coverage.
    """
    unknown = {rid for rid in (*(include or ()), *(exclude or ())) if rid not in RULES_BY_ID}
    if unknown:
        raise KeyError(f"Unknown rule id(s): {', '.join(sorted(unknown))}")

    selected = RULES
    if include:
        wanted = set(include)
        selected = tuple(r for r in selected if r.id in wanted)
    if exclude:
        unwanted = set(exclude)
        selected = tuple(r for r in selected if r.id not in unwanted)
    if min_severity is not None:
        selected = tuple(r for r in selected if r.severity.rank >= min_severity.rank)
    return selected


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class _LineIndex:
    """Maps absolute offsets in a document back to (line, column) pairs."""

    starts: list[int] = field(default_factory=list)

    @classmethod
    def build(cls, lines: Sequence[str]) -> _LineIndex:
        # `accumulate` runs the running sum in C; iterating the document
        # character by character in Python cost ~12% of total scan time.
        return cls([0, *accumulate(len(line) + 1 for line in lines)])

    def locate(self, offset: int) -> tuple[int, int]:
        line = bisect_right(self.starts, offset) - 1
        return line + 1, offset - self.starts[line] + 1


class RuleIndex:
    """An aggregated keyword prefilter for a ruleset.

    Checking each rule's keywords separately costs a Python-level ``any()`` call
    per rule per line. With ~50 rules that dominates the runtime - in a profile
    the regex engine itself barely registers. This class inverts the loop: it
    tests each *unique* keyword once against the whole document, then maps the
    keywords that were present back onto the rules that asked for them.

    ``str.__contains__`` is exact and runs a two-way search in C, so the result
    is precisely "every rule with at least one keyword in this document" - a
    superset of the rules that can match any individual line, never a subset.
    Measured against a compiled alternation over the same keywords, this is
    roughly 5x faster (308 us vs 1,550 us on a 4.7 KB document).
    """

    __slots__ = ("_always", "_by_keyword", "_keywords", "_order", "document_rules", "line_rules")

    def __init__(self, rules: Sequence[RuleDefinition]) -> None:
        self.document_rules: tuple[RuleDefinition, ...] = tuple(r for r in rules if _needs_document_scope(r))
        self.line_rules: tuple[RuleDefinition, ...] = tuple(r for r in rules if not _needs_document_scope(r))
        self._order: dict[str, int] = {r.id: i for i, r in enumerate(self.line_rules)}
        self._always: tuple[RuleDefinition, ...] = tuple(r for r in self.line_rules if not r.keywords)

        by_keyword: dict[str, list[RuleDefinition]] = {}
        for rule in self.line_rules:
            for keyword in rule.keywords:
                by_keyword.setdefault(keyword, []).append(rule)
        self._by_keyword: dict[str, tuple[RuleDefinition, ...]] = {
            keyword: tuple(rules_for) for keyword, rules_for in by_keyword.items()
        }
        # Longest first: the most selective keywords reject soonest.
        self._keywords: tuple[str, ...] = tuple(sorted(self._by_keyword, key=len, reverse=True))

    def candidates(self, lowered_text: str) -> tuple[RuleDefinition, ...]:
        """Rules with at least one keyword somewhere in ``lowered_text``.

        Callers pass the whole (lowercased) document. Resolving the candidate
        set once per file rather than once per line is what keeps the scanner's
        Python overhead proportional to files instead of lines.
        """
        selected: dict[str, RuleDefinition] = {r.id: r for r in self._always}
        for keyword in self._keywords:
            if keyword in lowered_text:
                for rule in self._by_keyword[keyword]:
                    selected[rule.id] = rule
        if len(selected) == len(self._always):
            return self._always
        return tuple(sorted(selected.values(), key=lambda r: self._order[r.id]))


@lru_cache(maxsize=32)
def build_index(rules: tuple[RuleDefinition, ...]) -> RuleIndex:
    """Memoized :class:`RuleIndex` construction, keyed by the ruleset itself."""
    return RuleIndex(rules)


def iter_rule_findings(
    text: str,
    path: str,
    rules: Sequence[RuleDefinition],
    *,
    entropy_fn: Callable[[str], float] | None = None,
    max_preview: int = 200,
) -> Iterator[Finding]:
    """Yield a :class:`Finding` for every rule match in ``text``.

    ``entropy_fn`` is injected so the scanner can share one memoized entropy
    kernel across all files rather than each rule recomputing it.
    """
    if not text:
        return

    entropy_of = entropy_fn or shannon_entropy
    lines = text.splitlines()
    seen: set[tuple[str, int, str]] = set()

    # Rules whose pattern is anchored with ^/$ under re.MULTILINE (or that are
    # explicitly declared multiline) must see the whole document; everything
    # else is matched line by line, which keeps the regex input tiny.
    ruleset = build_index(tuple(rules))
    document_rules = ruleset.document_rules

    # Two-stage prefilter.
    #
    # Stage 1 runs the aggregated keyword scan once over the whole document.
    # Resolving the candidate set is Python-level work (set unions, ordering)
    # and doing it per line was the single largest cost in the scanner.
    #
    # Stage 2 re-checks each survivor per line. That matters because stage 1 is
    # coarse: one `CACHE_KEY` anywhere in a file would otherwise arm the generic
    # rules on every one of its lines. Looping over ~5 survivors per line is
    # cheap; looping over all ~50 rules was not.
    candidate_rules = ruleset.candidates(text.lower())
    if not candidate_rules and not document_rules:
        return

    # Hoisting the keyword tuples out of the loop lets the per-line check be a
    # plain for/else, avoiding one `any()` call plus a generator frame per rule
    # per line - which was measurably the largest remaining overhead.
    staged = tuple((rule, rule.keywords) for rule in candidate_rules)

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        preview = stripped[:max_preview]
        lowered = line.lower()
        for rule, keywords in staged:
            if keywords:
                for keyword in keywords:
                    if keyword in lowered:
                        break
                else:
                    continue
            for match in rule.pattern.finditer(line):
                secret = _extract_secret(match)
                if not secret or rule.is_allowlisted(secret):
                    continue
                entropy_value = entropy_of(secret)
                if rule.entropy_min is not None and entropy_value < rule.entropy_min:
                    continue
                key = (rule.id, line_no, secret)
                if key in seen:
                    continue
                seen.add(key)
                yield _build_finding(rule, secret, path, line_no, match.start() + 1, preview, entropy_value)

    index: _LineIndex | None = None
    for rule in document_rules:
        for match in rule.pattern.finditer(text):
            secret = _extract_secret(match)
            if not secret or rule.is_allowlisted(secret):
                continue
            entropy_value = entropy_of(secret)
            if rule.entropy_min is not None and entropy_value < rule.entropy_min:
                continue
            if index is None:
                index = _LineIndex.build(lines)
            line_no, column = index.locate(match.start())
            key = (rule.id, line_no, secret)
            if key in seen:
                continue
            seen.add(key)
            preview = lines[line_no - 1].strip()[:max_preview] if line_no <= len(lines) else ""
            yield _build_finding(rule, secret, path, line_no, column, preview, entropy_value)


def _needs_document_scope(rule: RuleDefinition) -> bool:
    """True when a rule must be matched against the whole file at once."""
    return bool(rule.multiline or rule.pattern.flags & re.MULTILINE)


def _extract_secret(match: re.Match[str]) -> str:
    """Prefer the named ``secret`` group, falling back to the full match."""
    try:
        value = match.group("secret")
    except IndexError:  # pattern without a `secret` group
        value = match.group(0)
    return (value or "").strip()


def _build_finding(
    rule: RuleDefinition,
    secret: str,
    path: str,
    line: int,
    column: int,
    preview: str,
    entropy_value: float,
) -> Finding:
    verified = bool(rule.validator and rule.validator(secret))
    return Finding(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        detector=DetectorKind.REGEX,
        path=path,
        line=line,
        column=column,
        match=secret,
        redacted=redact(secret),
        entropy=entropy_value,
        line_preview=_mask_preview(preview, secret),
        description=rule.description,
        tags=rule.tags,
        verified=verified,
    )


def _mask_preview(preview: str, secret: str) -> str:
    """Never let the raw credential escape through the preview field."""
    if secret and secret in preview:
        return preview.replace(secret, redact(secret))
    return preview


# --------------------------------------------------------------------------- #
# Deduplication
# --------------------------------------------------------------------------- #

#: Rules that fire on *shape* rather than on a vendor-specific signature. When a
#: specific rule already covers the same bytes, the generic one is redundant.
GENERIC_RULE_IDS: frozenset[str] = frozenset({"generic-secret-assignment", "dotenv-secret-assignment"})


def _specificity(finding: Finding) -> tuple[int, int, int]:
    """Sort key for deduplication; higher is kept.

    Three tiers, because a vendor signature tells the reader far more than
    "this looks random":

    2. a named vendor rule (``stripe-secret-key``)
    1. a generic shape rule (``dotenv-secret-assignment``)
    0. the entropy detector

    Severity and checksum verification break ties inside a tier.
    """
    if finding.detector is DetectorKind.ENTROPY:
        tier = 0
    elif finding.rule_id in GENERIC_RULE_IDS:
        tier = 1
    else:
        tier = 2
    return (tier, finding.severity.rank, 1 if finding.verified else 0)


def deduplicate_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Collapse overlapping detections of the same credential.

    Three kinds of overlap are resolved, in order:

    1. Identical ``(path, line, secret)`` triples reported by several rules -
       the most specific/severe one wins.
    2. A generic rule matching a superset or subset of a specific rule's secret
       on the same line - the specific one wins.
    3. Entropy findings whose token is contained in a regex finding on the same
       line - the regex finding wins, because it names the credential type.
    """
    ordered = sorted(findings, key=_specificity, reverse=True)
    kept: list[Finding] = []
    kept_by_line: dict[tuple[str, int], list[Finding]] = {}

    for finding in ordered:
        line_key = (finding.path, finding.line)
        neighbours = kept_by_line.setdefault(line_key, [])
        redundant = False
        for other in neighbours:
            if finding.match == other.match:
                redundant = True
                break
            overlapping = finding.match in other.match or other.match in finding.match
            if not overlapping:
                continue
            if _specificity(finding)[0] < _specificity(other)[0]:
                redundant = True
                break
        if redundant:
            continue
        neighbours.append(finding)
        kept.append(finding)

    return kept
