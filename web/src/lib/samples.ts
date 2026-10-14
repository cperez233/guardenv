/**
 * Demo documents for the playground.
 *
 * Every credential below is synthetic and non-functional. They exist so a first
 * time visitor sees a populated report instead of an empty state.
 */

export interface SampleDocument {
  readonly id: string;
  readonly label: string;
  readonly filename: string;
  readonly description: string;
  readonly content: string;
}

const LEAKY_ENV = `# Production environment - DO NOT COMMIT
APP_ENV=production
DEBUG=false
PORT=8080

AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ
AWS_SECRET_ACCESS_KEY=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
AWS_DEFAULT_REGION=us-east-1

DATABASE_URL=postgresql://svc_billing:Tr0ub4dor3xK@db-prod.internal:5432/billing
REDIS_URL=redis://:qN7vWx2LmR9tYbA4@cache-prod.internal:6379/0

STRIPE_SECRET_KEY=sk_live_51H8xkLJk2mQqZzRtYuVbNmAsDfGhJkLp
OPENAI_API_KEY=sk-proj-9dK2mQxV7bLpR4tNwZ0aT3BlbkFJq8Xc1vY6uHnM2sEr5GdW7pKz
SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU

SUPPORT_EMAIL=security@acme-corp.io
FEATURE_FLAG_NEW_CHECKOUT=true
`;

const LEAKY_SOURCE = `import os
import httpx

GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"
SLACK_WEBHOOK = "https://hooks.slack.com/services/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"

# Correct pattern: read from the environment, never inline.
SENTRY_DSN = os.environ["SENTRY_DSN"]


def notify(message: str) -> None:
    httpx.post(SLACK_WEBHOOK, json={"text": message}, timeout=5.0)


def open_pull_request(repo: str, title: str) -> httpx.Response:
    return httpx.post(
        f"https://api.github.com/repos/{repo}/pulls",
        headers={"Authorization": f"Bearer {GITHUB_TOKEN}"},
        json={"title": title, "head": "feature", "base": "main"},
        timeout=10.0,
    )
`;

const CLEAN_SOURCE = `import { z } from "zod";

/**
 * Everything sensitive comes from the environment at boot time. Nothing in this
 * file is a credential, so GuardEnv should report it clean.
 */
const EnvSchema = z.object({
  DATABASE_URL: z.string().url(),
  SERVICE_API_KEY: z.string().min(32),
  AWS_REGION: z.string().default("eu-west-1"),
  FEATURE_FLAG_NEW_CHECKOUT: z.coerce.boolean().default(false),
});

export type Env = z.infer<typeof EnvSchema>;

export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = EnvSchema.safeParse(source);
  if (!parsed.success) {
    throw new Error(\`Invalid environment: \${parsed.error.message}\`);
  }
  return parsed.data;
}

export const BUILD_ID = "2026-09-08T12:30:00Z";
export const RELEASE = "v1.24.3-beta.1";
export const TRACE_ID = "550e8400-e29b-41d4-a716-446655440000";
`;

const MIXED_CONFIG = `{
  "name": "billing-service",
  "version": "2.4.1",
  "infrastructure": {
    "region": "eu-west-1",
    "queue": "amqps://worker:R4bb1tMQpass@broker.internal:5671/vhost"
  },
  "integrations": {
    "sendgrid": "SG.aBcDeFgHiJkLmNoPqRsTuV.9dK2mQxV7bLpR4tNwZ0aQ8Xc1vY6uHnM2sEr5Gd",
    "shopify": "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",
    "stripePublishable": "pk_live_51H8xkLJk2mQqZzRtYuVbNmAsDfGhJkLp"
  },
  "auth": {
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
  },
  "integrity": "sha384-QLbLFhGmv1PHMvpZDU5ZaSMlwPtqoRvsHW0S5nkzZAwQLbLFhGmv1PHMvpZDU5Za",
  "buildId": "550e8400-e29b-41d4-a716-446655440000"
}
`;

/**
 * The values are encoded at load time from the synthetic credentials above, so
 * no encoded copy of a key-shaped string ever sits in the source tree (GitHub
 * push protection decodes base64 too).
 */
const b64 = (value: string): string => btoa(value);

const K8S_SECRET = `# Kubernetes Secret: base64 is an encoding, not encryption.
apiVersion: v1
kind: Secret
metadata:
  name: billing-service
  namespace: payments
type: Opaque
data:
  SERVICE_NAME: ${b64("billing-service")}
  AWS_REGION: ${b64("eu-west-1")}
  AWS_ACCESS_KEY_ID: ${b64(LEAKY_ENV.match(/AKIA[0-9A-Z]{16}/)?.[0] ?? "")}
  STRIPE_SECRET_KEY: ${b64(LEAKY_ENV.match(/sk_live_[0-9A-Za-z]+/)?.[0] ?? "")}
  DATABASE_URL: ${b64(LEAKY_ENV.match(/postgresql:\/\/\S+/)?.[0] ?? "")}
`;

const DIFF_PATCH = `diff --git a/config/settings.py b/config/settings.py
index 3b18e51..a9c4f02 100644
--- a/config/settings.py
+++ b/config/settings.py
@@ -1,7 +1,7 @@
 import os

-STRIPE_SECRET_KEY = "${LEAKY_ENV.match(/sk_live_[0-9A-Za-z]+/)?.[0] ?? ""}"
+STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
 DEBUG = False
-DATABASE_URL = "${LEAKY_ENV.match(/postgresql:\/\/\S+/)?.[0] ?? ""}"
+DATABASE_URL = os.environ["DATABASE_URL"]
diff --git a/.env.production b/.env.production
new file mode 100644
index 0000000..5f1d2c3
--- /dev/null
+++ b/.env.production
@@ -0,0 +1,3 @@
+APP_ENV=production
+AWS_ACCESS_KEY_ID=${LEAKY_ENV.match(/AKIA[0-9A-Z]{16}/)?.[0] ?? ""}
+SESSION_SECRET=${LEAKY_ENV.match(/SESSION_SECRET=(\S+)/)?.[1] ?? ""}
`;

export const SAMPLE_DOCUMENTS: readonly SampleDocument[] = [
  {
    id: "env",
    label: ".env",
    filename: "production.env",
    description: "A production dotenv file with cloud, database and vendor credentials.",
    content: LEAKY_ENV,
  },
  {
    id: "source",
    label: "service.py",
    filename: "service.py",
    description: "Application code with tokens hardcoded by mistake.",
    content: LEAKY_SOURCE,
  },
  {
    id: "config",
    label: "config.json",
    filename: "config.json",
    description: "A JSON config mixing real credentials with benign hashes and UUIDs.",
    content: MIXED_CONFIG,
  },
  {
    id: "k8s",
    label: "secret.yaml",
    filename: "secret.yaml",
    description: "A Kubernetes Secret whose credentials are only base64-encoded.",
    content: K8S_SECRET,
  },
  {
    id: "diff",
    label: "fix.diff",
    filename: "fix.diff",
    description: "A git diff that moves secrets to the environment and adds a .env.production by mistake.",
    content: DIFF_PATCH,
  },
  {
    id: "clean",
    label: "env.ts",
    filename: "env.ts",
    description: "Correctly written config that reads every secret from the environment.",
    content: CLEAN_SOURCE,
  },
];

export const DEFAULT_SAMPLE = SAMPLE_DOCUMENTS[0] as SampleDocument;
