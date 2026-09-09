/**
 * Deterministic signatures - a TypeScript port of `guardenv/rules.py`.
 *
 * Rule ids, severities and tags are identical to the Python ruleset so a report
 * exported from the playground can be diffed against a CI run without a
 * translation layer.
 */

import type { RuleDefinition } from "./types";

// --------------------------------------------------------------------------
// Validators
// --------------------------------------------------------------------------

const BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

const CRC32_TABLE: Int32Array = (() => {
  const table = new Int32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let value = i;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[i] = value;
  }
  return table;
})();

/** CRC32 of an ASCII string, returned as an unsigned 32-bit integer. */
export function crc32(value: string): number {
  let crc = -1;
  for (let i = 0; i < value.length; i += 1) {
    const index = (crc ^ value.charCodeAt(i)) & 0xff;
    crc = (crc >>> 8) ^ (CRC32_TABLE[index] ?? 0);
  }
  return (crc ^ -1) >>> 0;
}

function base62Decode(value: string): number | null {
  let total = 0;
  for (const char of value) {
    const index = BASE62.indexOf(char);
    if (index < 0) return null;
    total = total * 62 + index;
  }
  return total;
}

/**
 * Verify the CRC32 checksum GitHub embeds in its `gh*_` tokens:
 * `<prefix>_<30 chars of entropy><6 chars of base62 CRC32>`.
 * Returns false for anything that does not fit the layout - a failed check
 * never suppresses a finding, it only withholds the "verified" badge.
 */
export function githubChecksumValid(token: string): boolean {
  const separator = token.indexOf("_");
  if (separator < 0) return false;
  const body = token.slice(separator + 1);
  if (body.length < 12) return false;
  const payload = body.slice(0, -6);
  const checksum = base62Decode(body.slice(-6));
  if (checksum === null) return false;
  return crc32(payload) === checksum;
}

// --------------------------------------------------------------------------
// Shared allowlist fragments
// --------------------------------------------------------------------------

const DOC_SAMPLES: readonly RegExp[] = [
  /EXAMPLE/i,
  /^(?:x{6,}|0{6,}|1{6,}|a{6,})/i,
  /(?:your|my|the)[-_]?(?:api|secret|access|private)?[-_]?key/i,
  /REPLACE[-_]?ME|CHANGE[-_]?ME|PLACEHOLDER|DUMMY|SAMPLE|NOT[-_]?REAL/i,
  /^\$\{|^\{\{|^<[a-z]/i,
];

const WEAK_PASSWORD_PLACEHOLDER = /:(?:password|pass|pwd|secret|token|\*+)@/i;

// --------------------------------------------------------------------------
// The ruleset
// --------------------------------------------------------------------------

export const RULES: readonly RuleDefinition[] = [
  // ------------------------------ Cloud ------------------------------------
  {
    id: "aws-access-key-id",
    name: "AWS Access Key ID",
    description: "Long-lived AWS access key identifier (AKIA) or temporary credential prefix.",
    severity: "CRITICAL",
    pattern:
      /\b(?<secret>(?:AKIA|ASIA|ABIA|ACCA|AIDA|AGPA|AROA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b/g,
    keywords: ["akia", "asia", "abia", "acca", "aida", "agpa", "aroa", "anpa", "anva", "a3t"],
    tags: ["aws", "cloud", "iam"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "aws-secret-access-key",
    name: "AWS Secret Access Key",
    description: "40-character AWS secret assigned to an access key ID.",
    severity: "CRITICAL",
    pattern:
      /aws[-_ ]?(?:secret|private)[-_ ]?(?:access[-_ ]?)?key\w*\s*[:=]\s*["']?(?<secret>[A-Za-z0-9/+=]{40})["']?/gi,
    keywords: ["aws"],
    tags: ["aws", "cloud", "iam"],
    allowlist: DOC_SAMPLES,
    entropyMin: 3.5,
  },
  {
    id: "aws-session-token",
    name: "AWS Session Token",
    description: "Short-lived STS session token; grants full API access until it expires.",
    severity: "HIGH",
    pattern: /aws[-_ ]?session[-_ ]?token\w*\s*[:=]\s*["']?(?<secret>[A-Za-z0-9/+=]{100,})["']?/gi,
    keywords: ["aws_session_token", "aws-session-token", "aws session token"],
    tags: ["aws", "cloud", "sts"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "gcp-api-key",
    name: "Google Cloud API Key",
    description: "Google or Firebase API key (AIza prefix).",
    severity: "HIGH",
    pattern: /\b(?<secret>AIza[0-9A-Za-z_-]{35})\b/g,
    keywords: ["aiza"],
    tags: ["gcp", "google", "firebase"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "gcp-oauth-client-secret",
    name: "Google OAuth Client Secret",
    description: "Google OAuth 2.0 client secret (GOCSPX prefix).",
    severity: "CRITICAL",
    pattern: /\b(?<secret>GOCSPX-[A-Za-z0-9_-]{28})\b/g,
    keywords: ["gocspx"],
    tags: ["gcp", "google", "oauth"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "gcp-service-account",
    name: "GCP Service Account Key File",
    description: "Service-account JSON containing an embedded private key.",
    severity: "CRITICAL",
    pattern: /["']type["']\s*:\s*["'](?<secret>service_account)["']/g,
    keywords: ["service_account"],
    tags: ["gcp", "google", "iam"],
  },
  {
    id: "azure-storage-connection-string",
    name: "Azure Storage Connection String",
    description: "Azure Storage account key embedded in a connection string.",
    severity: "CRITICAL",
    pattern: /AccountKey\s*=\s*(?<secret>[A-Za-z0-9+/=]{86,88})/g,
    keywords: ["accountkey"],
    tags: ["azure", "cloud", "storage"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "digitalocean-token",
    name: "DigitalOcean Personal Access Token",
    description: "DigitalOcean API token (dop_v1 prefix).",
    severity: "CRITICAL",
    pattern: /\b(?<secret>dop_v1_[a-f0-9]{64})\b/g,
    keywords: ["dop_v1_"],
    tags: ["digitalocean", "cloud"],
  },
  // ---------------------------- Git forges ---------------------------------
  {
    id: "github-pat-classic",
    name: "GitHub Personal Access Token (classic)",
    description: "Classic GitHub PAT; grants the scopes selected at creation time.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>ghp_[A-Za-z0-9]{36})\b/g,
    keywords: ["ghp_"],
    tags: ["github", "vcs", "scm"],
    allowlist: DOC_SAMPLES,
    validate: githubChecksumValid,
  },
  {
    id: "github-pat-fine-grained",
    name: "GitHub Fine-grained Personal Access Token",
    description: "Fine-grained GitHub PAT scoped to specific repositories.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b/g,
    keywords: ["github_pat_"],
    tags: ["github", "vcs", "scm"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "github-oauth-token",
    name: "GitHub OAuth / App Token",
    description: "GitHub OAuth (gho_), user-to-server (ghu_), server (ghs_) or refresh (ghr_) token.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>gh[ousr]_[A-Za-z0-9]{36})\b/g,
    keywords: ["gho_", "ghu_", "ghs_", "ghr_"],
    tags: ["github", "vcs", "oauth"],
    allowlist: DOC_SAMPLES,
    validate: githubChecksumValid,
  },
  {
    id: "gitlab-pat",
    name: "GitLab Personal Access Token",
    description: "GitLab personal access token (glpat prefix).",
    severity: "CRITICAL",
    pattern: /\b(?<secret>glpat-[A-Za-z0-9_-]{20})\b/g,
    keywords: ["glpat-"],
    tags: ["gitlab", "vcs", "scm"],
    allowlist: DOC_SAMPLES,
  },
  // ----------------------------- Payments ----------------------------------
  {
    id: "stripe-secret-key",
    name: "Stripe Secret Key",
    description: "Stripe live/test secret or restricted key; can move money.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,247})\b/g,
    keywords: ["sk_live_", "sk_test_", "rk_live_", "rk_test_"],
    tags: ["stripe", "payments", "pci"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "stripe-publishable-key",
    name: "Stripe Publishable Key",
    description: "Client-side Stripe key. Not secret, but reveals the environment in use.",
    severity: "INFO",
    pattern: /\b(?<secret>pk_(?:live|test)_[A-Za-z0-9]{24,247})\b/g,
    keywords: ["pk_live_", "pk_test_"],
    tags: ["stripe", "payments", "informational"],
  },
  {
    id: "square-access-token",
    name: "Square Access Token",
    description: "Square OAuth or personal access token.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43})\b/g,
    keywords: ["sq0atp-", "sq0csp-"],
    tags: ["square", "payments"],
  },
  // ------------------------------- AI/ML -----------------------------------
  {
    id: "openai-api-key",
    name: "OpenAI API Key",
    description: "OpenAI secret key (legacy, project or service-account form).",
    severity: "CRITICAL",
    pattern:
      /\b(?<secret>sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,})\b/g,
    keywords: ["sk-", "t3blbkfj"],
    tags: ["openai", "ai", "llm"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "openai-api-key-legacy",
    name: "OpenAI API Key (legacy format)",
    description: "Pre-2023 OpenAI key: sk- followed by 48 base62 characters.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>sk-[A-Za-z0-9]{48})\b/g,
    keywords: ["sk-"],
    tags: ["openai", "ai", "llm"],
    allowlist: DOC_SAMPLES,
    entropyMin: 4.0,
  },
  {
    id: "anthropic-api-key",
    name: "Anthropic API Key",
    description: "Anthropic Claude API key (sk-ant prefix).",
    severity: "CRITICAL",
    pattern: /\b(?<secret>sk-ant-(?:api|admin)[0-9]{2}-[A-Za-z0-9_-]{80,120})\b/g,
    keywords: ["sk-ant-"],
    tags: ["anthropic", "ai", "llm"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "huggingface-token",
    name: "Hugging Face Access Token",
    description: "Hugging Face user or organization access token.",
    severity: "HIGH",
    pattern: /\b(?<secret>hf_[A-Za-z0-9]{34,40})\b/g,
    keywords: ["hf_"],
    tags: ["huggingface", "ai", "ml"],
    allowlist: DOC_SAMPLES,
  },
  // --------------------------- Comms / SaaS --------------------------------
  {
    id: "slack-token",
    name: "Slack API Token",
    description: "Slack bot, user, app or legacy workspace token.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>xox[baprse]-(?:[0-9a-zA-Z]{10,48}-){1,4}[0-9a-zA-Z]{10,48})\b/g,
    keywords: ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-", "xoxe-"],
    tags: ["slack", "saas", "chat"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "slack-webhook",
    name: "Slack Incoming Webhook",
    description: "Slack webhook URL; allows posting messages into a workspace channel.",
    severity: "HIGH",
    pattern:
      /(?<secret>https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9+/]{6,}\/[A-Za-z0-9+/]{6,}\/[A-Za-z0-9+/]{12,})/g,
    keywords: ["hooks.slack.com"],
    tags: ["slack", "webhook"],
  },
  {
    id: "telegram-bot-token",
    name: "Telegram Bot Token",
    description: "Telegram Bot API token (numeric id plus secret).",
    severity: "HIGH",
    pattern: /\b(?<secret>\d{8,10}:AA[A-Za-z0-9_-]{33})\b/g,
    keywords: [":aa"],
    tags: ["telegram", "chat", "bot"],
  },
  {
    id: "sendgrid-api-key",
    name: "SendGrid API Key",
    description: "SendGrid API key; allows sending mail as the account.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
    keywords: ["sg."],
    tags: ["sendgrid", "email"],
  },
  {
    id: "mailgun-api-key",
    name: "Mailgun API Key",
    description: "Mailgun private API key.",
    severity: "HIGH",
    pattern: /\b(?<secret>key-[0-9a-zA-Z]{32})\b/g,
    keywords: ["key-"],
    tags: ["mailgun", "email"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "shopify-token",
    name: "Shopify Access Token",
    description: "Shopify private app, custom app or partner token.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/g,
    keywords: ["shpat_", "shpca_", "shppa_", "shpss_"],
    tags: ["shopify", "ecommerce"],
  },
  {
    id: "npm-access-token",
    name: "npm Access Token",
    description: "npm automation or publish token.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>npm_[A-Za-z0-9]{36})\b/g,
    keywords: ["npm_"],
    tags: ["npm", "registry", "supply-chain"],
    allowlist: DOC_SAMPLES,
  },
  {
    id: "hashicorp-vault-token",
    name: "HashiCorp Vault Token",
    description: "Vault service or batch token.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>hv[sb]\.[A-Za-z0-9_-]{24,})\b/g,
    keywords: ["hvs.", "hvb."],
    tags: ["vault", "hashicorp", "secrets-manager"],
  },
  {
    id: "terraform-cloud-token",
    name: "Terraform Cloud API Token",
    description: "HCP Terraform / Terraform Cloud user or team token.",
    severity: "CRITICAL",
    pattern: /\b(?<secret>[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})\b/g,
    keywords: [".atlasv1."],
    tags: ["terraform", "hashicorp", "iac"],
  },
  // ---------------------------- Key material -------------------------------
  {
    id: "private-key-block",
    name: "Cryptographic Private Key",
    description: "PEM-encoded private key (RSA, EC, DSA, OpenSSH or PGP).",
    severity: "CRITICAL",
    pattern:
      /(?<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)/g,
    keywords: ["-----begin"],
    tags: ["crypto", "pki", "ssh"],
  },
  {
    id: "putty-private-key",
    name: "PuTTY Private Key",
    description: "PuTTY PPK private key header.",
    severity: "CRITICAL",
    pattern: /(?<secret>PuTTY-User-Key-File-[23]:)/g,
    keywords: ["putty-user-key-file"],
    tags: ["crypto", "ssh"],
  },
  {
    id: "json-web-token",
    name: "JSON Web Token",
    description: "Signed JWT. Often a session or service credential.",
    severity: "MEDIUM",
    pattern: /\b(?<secret>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g,
    keywords: ["eyj"],
    tags: ["jwt", "session", "auth"],
  },
  // ------------------------- Connection strings ----------------------------
  {
    id: "postgres-connection-string",
    name: "PostgreSQL Connection String",
    description: "PostgreSQL URI with inline credentials.",
    severity: "CRITICAL",
    pattern: /(?<secret>postgres(?:ql)?:\/\/[^:/\s@"']+:[^@/\s"']{3,}@[^\s/"']+)/gi,
    keywords: ["postgres://", "postgresql://"],
    tags: ["database", "postgres", "connection-string"],
    allowlist: [...DOC_SAMPLES, WEAK_PASSWORD_PLACEHOLDER],
  },
  {
    id: "mysql-connection-string",
    name: "MySQL Connection String",
    description: "MySQL/MariaDB URI with inline credentials.",
    severity: "CRITICAL",
    pattern: /(?<secret>mysqlx?:\/\/[^:/\s@"']+:[^@/\s"']{3,}@[^\s/"']+)/gi,
    keywords: ["mysql://", "mysqlx://"],
    tags: ["database", "mysql", "connection-string"],
    allowlist: [...DOC_SAMPLES, WEAK_PASSWORD_PLACEHOLDER],
  },
  {
    id: "mongodb-connection-string",
    name: "MongoDB Connection String",
    description: "MongoDB URI with inline credentials.",
    severity: "CRITICAL",
    pattern: /(?<secret>mongodb(?:\+srv)?:\/\/[^:/\s@"']+:[^@/\s"']{3,}@[^\s/"']+)/gi,
    keywords: ["mongodb://", "mongodb+srv://"],
    tags: ["database", "mongodb", "connection-string"],
    allowlist: [...DOC_SAMPLES, WEAK_PASSWORD_PLACEHOLDER],
  },
  {
    id: "redis-connection-string",
    name: "Redis Connection String",
    description: "Redis URI carrying an inline password.",
    severity: "HIGH",
    pattern: /(?<secret>rediss?:\/\/[^:/\s@"']*:[^@/\s"']{3,}@[^\s/"']+)/gi,
    keywords: ["redis://", "rediss://"],
    tags: ["database", "redis", "connection-string"],
    allowlist: [...DOC_SAMPLES, WEAK_PASSWORD_PLACEHOLDER],
  },
  {
    id: "amqp-connection-string",
    name: "AMQP Connection String",
    description: "RabbitMQ/AMQP URI carrying inline credentials.",
    severity: "HIGH",
    pattern: /(?<secret>amqps?:\/\/[^:/\s@"']+:[^@/\s"']{3,}@[^\s/"']+)/gi,
    keywords: ["amqp://", "amqps://"],
    tags: ["queue", "rabbitmq", "connection-string"],
    allowlist: [...DOC_SAMPLES, WEAK_PASSWORD_PLACEHOLDER],
  },
  {
    id: "basic-auth-url",
    name: "Credentials Embedded in URL",
    description: "HTTP(S) URL carrying user:password basic-auth credentials.",
    severity: "HIGH",
    pattern: /(?<secret>https?:\/\/[^:/\s@"']+:[^@/\s"']{3,}@[^\s/"']+)/gi,
    keywords: ["http://", "https://"],
    tags: ["http", "basic-auth", "connection-string"],
    allowlist: [...DOC_SAMPLES, WEAK_PASSWORD_PLACEHOLDER],
  },
  {
    id: "npmrc-auth-token",
    name: "npmrc Auth Token",
    description: "Registry auth token stored in .npmrc or CI configuration.",
    severity: "CRITICAL",
    pattern: /_auth(?:Token)?\s*=\s*(?<secret>[A-Za-z0-9+/=_-]{16,})/gi,
    keywords: ["_auth"],
    tags: ["npm", "registry", "supply-chain"],
    allowlist: DOC_SAMPLES,
  },
  // ------------------------------ Generic ----------------------------------
  {
    id: "generic-secret-assignment",
    name: "Generic Secret Assignment",
    description: "A secret-shaped value assigned to a variable whose name implies a credential.",
    severity: "MEDIUM",
    pattern:
      /\b[A-Za-z0-9_.-]*(?:api[-_]?key|secret|passwd|password|token|auth|credential|private[-_]?key|access[-_]?key|client[-_]?secret)[A-Za-z0-9_.-]*\b\s*[:=]{1,2}\s*["'](?<secret>[^"'\n]{12,120})["']/gi,
    keywords: ["key", "secret", "passwd", "password", "token", "auth", "credential"],
    tags: ["generic", "heuristic"],
    allowlist: [
      ...DOC_SAMPLES,
      /^(?:true|false|null|none|undefined|localhost)$/i,
      /^[a-z]+(?:[-_][a-z]+)*$/,
      /^\d+$/,
      /^(?:process\.env|os\.environ|env\[|config\.|settings\.)/i,
    ],
    entropyMin: 3.2,
  },
  {
    id: "dotenv-secret-assignment",
    name: "Dotenv Secret Assignment",
    description:
      "KEY=value line in a .env-style file where the key name implies a credential. " +
      "Matched case-sensitively: an uppercase key is what distinguishes a dotenv entry " +
      "from an ordinary lowercase keyword argument in source code.",
    severity: "HIGH",
    pattern:
      /^[ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:API[-_]?KEY|SECRET|PASSWD|PASSWORD|TOKEN|AUTH|CREDENTIAL|PRIVATE[-_]?KEY|ACCESS[-_]?KEY|CLIENT[-_]?SECRET)[A-Z0-9_]*[ \t]*=[ \t]*["']?(?<secret>[^\s"'#]{8,200})["']?[ \t]*(?:#.*)?$/gm,
    keywords: ["key", "secret", "passwd", "password", "token", "auth", "credential"],
    tags: ["dotenv", "generic", "heuristic"],
    documentScoped: true,
    allowlist: [
      ...DOC_SAMPLES,
      /^(?:true|false|null|none|undefined|localhost)$/i,
      /^\$\{?[A-Z_]+\}?$/,
      /^\d+$/,
    ],
    entropyMin: 2.8,
  },
];

export const RULES_BY_ID: ReadonlyMap<string, RuleDefinition> = new Map(
  RULES.map((rule) => [rule.id, rule]),
);

/** Rules that fire on shape rather than on a vendor signature. */
export const GENERIC_RULE_IDS: ReadonlySet<string> = new Set([
  "generic-secret-assignment",
  "dotenv-secret-assignment",
]);

export const ALL_TAGS: readonly string[] = Array.from(
  new Set(RULES.flatMap((rule) => rule.tags)),
).sort();
