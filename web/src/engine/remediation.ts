/**
 * What to do about a finding. The first step is provider-specific (where to
 * revoke), the rest is the same discipline for every leaked credential.
 */

import type { ScanFinding } from "./types";

export interface Remediation {
  readonly revoke: string;
  readonly console?: { readonly label: string; readonly href: string };
  readonly steps: readonly string[];
}

interface Playbook {
  readonly match: (finding: ScanFinding) => boolean;
  readonly revoke: string;
  readonly console?: { readonly label: string; readonly href: string };
}

const has = (finding: ScanFinding, tag: string): boolean => finding.tags.includes(tag);

const PLAYBOOKS: readonly Playbook[] = [
  {
    match: (f) => has(f, "aws"),
    revoke: "Deactivate the access key in IAM, create a new one, then delete the old key once nothing uses it.",
    console: { label: "AWS IAM credentials", href: "https://console.aws.amazon.com/iam/home#/security_credentials" },
  },
  {
    match: (f) => has(f, "gcp"),
    revoke: "Delete or regenerate the key in Google Cloud; for a service account, disable the key and issue a new one.",
    console: { label: "Google Cloud credentials", href: "https://console.cloud.google.com/apis/credentials" },
  },
  {
    match: (f) => has(f, "azure"),
    revoke: "Rotate the storage account access key (key1/key2) and move clients to the regenerated one.",
  },
  {
    match: (f) => has(f, "github"),
    revoke: "Delete the token in GitHub developer settings and issue a fine-grained token with the least scope it needs.",
    console: { label: "GitHub tokens", href: "https://github.com/settings/tokens" },
  },
  {
    match: (f) => has(f, "gitlab"),
    revoke: "Revoke the personal access token in GitLab and create a replacement with a short expiry.",
    console: { label: "GitLab access tokens", href: "https://gitlab.com/-/user_settings/personal_access_tokens" },
  },
  {
    match: (f) => has(f, "stripe"),
    revoke: "Roll the key in the Stripe dashboard; a restricted key with only the permissions you use is safer.",
    console: { label: "Stripe API keys", href: "https://dashboard.stripe.com/apikeys" },
  },
  {
    match: (f) => has(f, "openai"),
    revoke: "Revoke the key in the OpenAI platform and create a new project-scoped key.",
    console: { label: "OpenAI API keys", href: "https://platform.openai.com/api-keys" },
  },
  {
    match: (f) => has(f, "anthropic"),
    revoke: "Delete the key in the Anthropic Console and create a new one.",
    console: { label: "Anthropic API keys", href: "https://console.anthropic.com/settings/keys" },
  },
  {
    match: (f) => has(f, "huggingface"),
    revoke: "Invalidate the token in Hugging Face settings and create a new one with read-only access if possible.",
    console: { label: "Hugging Face tokens", href: "https://huggingface.co/settings/tokens" },
  },
  {
    match: (f) => has(f, "slack"),
    revoke: "Regenerate the token or webhook URL from the Slack app's configuration page.",
    console: { label: "Slack apps", href: "https://api.slack.com/apps" },
  },
  {
    match: (f) => has(f, "sendgrid"),
    revoke: "Delete the API key in SendGrid settings and create a new one with restricted access.",
    console: { label: "SendGrid API keys", href: "https://app.sendgrid.com/settings/api_keys" },
  },
  {
    match: (f) => has(f, "digitalocean"),
    revoke: "Delete the personal access token in DigitalOcean and generate a new one.",
    console: { label: "DigitalOcean tokens", href: "https://cloud.digitalocean.com/account/api/tokens" },
  },
  {
    match: (f) => has(f, "telegram"),
    revoke: "Send /revoke to @BotFather for this bot to invalidate the token and get a new one.",
  },
  {
    match: (f) => has(f, "npm"),
    revoke: "Revoke the token in your npm account's access tokens page and publish with a granular token.",
  },
  {
    match: (f) => has(f, "database") || has(f, "queue") || has(f, "basic-auth"),
    revoke: "Change the password for this user on the server, update the connection string where it is configured, and check the server's logs for unknown clients.",
  },
  {
    match: (f) => has(f, "crypto"),
    revoke: "Generate a new key pair, replace the public key wherever it is trusted (authorized_keys, CA, deploy keys) and remove the old one.",
  },
  {
    match: (f) => has(f, "jwt"),
    revoke: "If this token is live, rotate the signing secret so every issued token becomes invalid, then let clients sign in again.",
  },
  {
    match: (f) => has(f, "vault") || has(f, "terraform"),
    revoke: "Revoke the token (vault token revoke, or the Terraform Cloud user settings) and issue one with a short TTL.",
  },
];

const GENERIC =
  "Treat it as compromised: rotate it with whoever issued it, even if the repository is private.";

export function remediationFor(finding: ScanFinding): Remediation {
  const playbook = PLAYBOOKS.find((entry) => entry.match(finding));
  const steps = [
    "Load it from the environment or a secret manager instead of the file.",
    "If it was ever committed, rewriting history (git filter-repo) hides it but does not un-leak it: rotate first.",
    "Check the provider's audit log for use you don't recognise since the leak.",
  ];
  if (finding.tags.includes("encoded")) {
    steps.unshift("Base64 is an encoding, not encryption: anyone with the file can read this value.");
  }
  if (finding.tags.includes("informational")) {
    return {
      revoke: "Publishable keys are meant for clients, so this is not a leak by itself.",
      steps: ["Confirm it is the publishable key and not a secret or restricted key."],
    };
  }
  return playbook?.console !== undefined
    ? { revoke: playbook.revoke, console: playbook.console, steps }
    : { revoke: playbook?.revoke ?? GENERIC, steps };
}
