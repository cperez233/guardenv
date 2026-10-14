/**
 * Contract tests for the client-side engine.
 *
 * The expectations here are deliberately the same ones the Python suite pins
 * (`tests/test_entropy.py`, `tests/test_rules.py`), because the playground and
 * the CLI must not disagree about what counts as a secret.
 */

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  analyzeToken,
  classifyCharset,
  extractCandidates,
  isBenignToken,
  normalizedEntropy,
  profileDocument,
  shannonEntropy,
  configWithThreshold,
} from "./entropy";
import { toJsonReport, toMarkdownReport, toSarifReport } from "./export";
import { RULES, RULES_BY_ID, crc32, githubChecksumValid } from "./rules";
import { deduplicate, redact, scanText } from "./scanner";
import { SEVERITY_RANK } from "./types";

const BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/** Build a GitHub token whose embedded CRC32 checksum is genuinely correct. */
function makeGithubToken(prefix = "ghp", payload = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5"): string {
  let value = crc32(payload);
  let digits = "";
  while (value > 0) {
    digits = (BASE62[value % 62] ?? "0") + digits;
    value = Math.floor(value / 62);
  }
  return `${prefix}_${payload}${digits.padStart(6, "0")}`;
}

const LEAKY_ENV = [
  "APP_ENV=production",
  "AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ",
  'AWS_SECRET_ACCESS_KEY="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"',
  "DATABASE_URL=postgresql://svc:Tr0ub4dor3xK@db.internal:5432/billing",
  "DEBUG=false",
  "",
].join("\n");

describe("shannonEntropy", () => {
  it("returns zero for an empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns zero when every character is identical", () => {
    expect(shannonEntropy("aaaaaaaaaa")).toBe(0);
  });

  it("returns one bit for a uniform binary alphabet", () => {
    expect(shannonEntropy("abababab")).toBeCloseTo(1, 10);
  });

  it("returns two bits for a uniform four-symbol alphabet", () => {
    expect(shannonEntropy("abcdabcdabcd")).toBeCloseTo(2, 10);
  });

  it("matches the textbook formula", () => {
    const expected = -[3, 2, 1].reduce((acc, count) => {
      const p = count / 6;
      return acc + p * Math.log2(p);
    }, 0);
    expect(shannonEntropy("aaabbc")).toBeCloseTo(expected, 10);
  });

  it("scores a random secret above prose", () => {
    expect(shannonEntropy("kR8fLpQ2mZvX1sTgH9dYw3EbN0uJc7AiOe5Rt2K")).toBeGreaterThan(
      shannonEntropy("the quick brown fox jumps over the lazy dog"),
    );
  });

  it("agrees with the uncached path for long inputs", () => {
    expect(shannonEntropy("abcdefgh".repeat(200))).toBeCloseTo(3, 10);
  });
});

describe("normalizedEntropy", () => {
  it("is zero for single characters", () => {
    expect(normalizedEntropy("a")).toBe(0);
  });

  it("reaches one for a uniform distribution", () => {
    expect(normalizedEntropy("abcd")).toBeCloseTo(1, 10);
  });

  it("stays within [0, 1]", () => {
    for (const token of ["abcdefgh", "aaaa", "kR8fLpQ2mZvX1sTgH9dYw3EbN0uJc7Ai"]) {
      const value = normalizedEntropy(token);
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThanOrEqual(1);
    }
  });
});

describe("classifyCharset", () => {
  it.each([
    ["deadbeef0123456789abcdef", "hex"],
    ["AKIAZ4KJQ2WBXY7TDNPQ", "alphanumeric"],
    ["kR8fLpQ2mZv+X1sTgH9dYw3EbN0uJc7A=", "base64"],
    ["kR8fLpQ2mZv-X1sTgH9dYw3EbN0uJc7A", "base64url"],
    ["some/path:with@symbols!", "mixed"],
  ])("classifies %s", (token, expected) => {
    expect(classifyCharset(token)).toBe(expected);
  });
});

describe("isBenignToken", () => {
  it.each([
    ["550e8400-e29b-41d4-a716-446655440000", "uuid"],
    ["2026-09-08T12:30:00Z", "iso-8601-timestamp"],
    ["v1.24.3-beta.1", "semantic-version"],
    ["1234567890.123456", "numeric-literal"],
    ["./src/components/Button.tsx", "filesystem-path"],
    ["FEATURE_FLAG_NEW_CHECKOUT", "word-like-identifier"],
    ["api.eu-west-1.internal.acme-corp.io", "hostname-or-dotted-identifier"],
    ["aaaaaaaaaaaaaaaaaaaaaaaa", "low-character-variety"],
    ["YOUR_API_KEY_GOES_HERE_XXXX", "documentation-placeholder"],
    ["sha256-QLbLFhGmv1PHMvpZDU5ZaSMlwPtqoRvsHW0S5nkzZAw=", "subresource-integrity-hash"],
    ["0123456789abcdefghijklmnopqrstuvwxyz", "sequential-character-run"],
    ["entropy_config.hex_threshold", "structured-identifier"],
    ["github/codeql-action/upload-sarif", "structured-identifier"],
    ["verbatimModuleSyntax", "word-like-identifier"],
  ])("suppresses %s", (token, reason) => {
    const verdict = isBenignToken(token);
    expect(verdict.benign).toBe(true);
    expect(verdict.reason).toBe(reason);
  });

  it("does not suppress a genuine secret", () => {
    expect(isBenignToken("kR8fLpQ2mZvX1sTgH9dYw3EbN0uJc7AiOe5Rt2K").benign).toBe(false);
  });

  it("does not let a separator shield a credential-length segment", () => {
    expect(isBenignToken("glpat-A1b2C3d4E5f6G7h8I9j0").benign).toBe(false);
  });

  it("does not suppress a short ascending run", () => {
    expect(isBenignToken("hV3q9ZxT2LmR8NfPwabcdKdA1sGjB4cXeU").benign).toBe(false);
  });

  it("can be disabled", () => {
    const config = configWithThreshold(4.5, false);
    expect(isBenignToken("550e8400-e29b-41d4-a716-446655440000", config).benign).toBe(false);
  });
});

describe("analyzeToken", () => {
  it("rejects short tokens before scoring", () => {
    const result = analyzeToken("abc123", 1, 1);
    expect(result.suspicious).toBe(false);
    expect(result.reason).toBe("too-short");
  });

  it("flags a high entropy secret", () => {
    expect(analyzeToken("hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU", 1, 1).suspicious).toBe(true);
  });

  it("applies the lower hex threshold", () => {
    const result = analyzeToken("d41d8cd98f00b204e9800998ecf8427e", 1, 1);
    expect(result.charset).toBe("hex");
    expect(result.threshold).toBeCloseTo(3.0, 10);
    expect(result.suspicious).toBe(true);
  });

  it("respects the configured threshold", () => {
    const token = "hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU";
    expect(analyzeToken(token, 1, 1, configWithThreshold(3.0)).suspicious).toBe(true);
    expect(analyzeToken(token, 1, 1, configWithThreshold(7.5)).suspicious).toBe(false);
  });
});

describe("extractCandidates", () => {
  it("splits the key from the value at the assignment operator", () => {
    const tokens = extractCandidates("SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU").map(
      (candidate) => candidate.token,
    );
    expect(tokens).toContain("hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU");
    expect(tokens.some((token) => token.includes("SESSION_SECRET="))).toBe(false);
  });

  it("reports offsets that point at the token", () => {
    const line = "SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU";
    for (const { token, offset } of extractCandidates(line)) {
      expect(line.slice(offset, offset + token.length)).toBe(token);
    }
  });

  it("windows oversized blobs instead of dropping them", () => {
    const config = { ...configWithThreshold(4.5), maxLength: 64 };
    const tokens = extractCandidates("kR8fLpQ2mZvX1sTgH9dYw".repeat(20), config);
    expect(tokens.length).toBeGreaterThan(0);
    expect(tokens.every((candidate) => candidate.token.length <= 64)).toBe(true);
  });

  it("reports 1-based line and column positions", () => {
    const profile = profileDocument("a=1\nSECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n");
    const hit = profile.find((entry) => entry.suspicious);
    expect(hit?.line).toBe(2);
    expect(hit?.column).toBeGreaterThan(1);
  });
});

describe("ruleset integrity", () => {
  it("has unique ids", () => {
    const ids = RULES.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("exposes a `secret` capture group on every rule", () => {
    for (const rule of RULES) {
      expect(rule.pattern.source, rule.id).toContain("(?<secret>");
    }
  });

  it("compiles every pattern with the global flag so exec() can iterate", () => {
    for (const rule of RULES) {
      expect(rule.pattern.flags, rule.id).toContain("g");
    }
  });

  it("keeps keywords lowercase for the prefilter", () => {
    for (const rule of RULES) {
      for (const keyword of rule.keywords) {
        expect(keyword).toBe(keyword.toLowerCase());
      }
    }
  });

  it("indexes every rule by id", () => {
    expect(RULES_BY_ID.size).toBe(RULES.length);
  });
});

describe("githubChecksumValid", () => {
  it("accepts a correctly checksummed token", () => {
    expect(githubChecksumValid(makeGithubToken())).toBe(true);
  });

  it("rejects malformed input without throwing", () => {
    expect(githubChecksumValid("ghp_short")).toBe(false);
    expect(githubChecksumValid("no-underscore")).toBe(false);
    expect(githubChecksumValid(`ghp_${"!".repeat(36)}`)).toBe(false);
  });

  it("matches the known CRC32 of a reference string", () => {
    expect(crc32("123456789")).toBe(0xcbf43926);
  });
});

describe("scanText", () => {
  it("detects the credentials in a leaky dotenv file", () => {
    const summary = scanText(LEAKY_ENV, { path: ".env" });
    const ids = summary.findings.map((finding) => finding.ruleId);
    expect(ids).toContain("aws-access-key-id");
    expect(ids).toContain("aws-secret-access-key");
    expect(ids).toContain("postgres-connection-string");
  });

  it("returns an empty summary for empty input", () => {
    const summary = scanText("");
    expect(summary.totalFindings).toBe(0);
    expect(summary.highestSeverity).toBeNull();
  });

  it("reports accurate one-based line numbers", () => {
    const summary = scanText("\n\n\nAWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ\n", { path: ".env" });
    const finding = summary.findings.find((entry) => entry.ruleId === "aws-access-key-id");
    expect(finding?.line).toBe(4);
  });

  it("points the column at the secret", () => {
    const line = "token = 'AKIAZ4KJQ2WBXY7TDNPQ'";
    const summary = scanText(line, { path: "app.py" });
    const finding = summary.findings.find((entry) => entry.ruleId === "aws-access-key-id");
    expect(line.slice((finding?.column ?? 1) - 1)).toMatch(/^AKIA/);
  });

  it("never leaks the raw secret into the preview", () => {
    for (const finding of scanText(LEAKY_ENV, { path: ".env" }).findings) {
      expect(finding.linePreview).not.toContain(finding.match);
    }
  });

  it("allowlists vendor documentation samples", () => {
    const summary = scanText("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
    expect(summary.findings.map((finding) => finding.ruleId)).not.toContain("aws-access-key-id");
  });

  it("marks a valid GitHub checksum as verified", () => {
    const summary = scanText(`token = "${makeGithubToken()}"`, { path: "app.py" });
    const finding = summary.findings.find((entry) => entry.ruleId === "github-pat-classic");
    expect(finding?.verified).toBe(true);
  });

  it("still reports a token whose checksum fails", () => {
    const summary = scanText('token = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"');
    const finding = summary.findings.find((entry) => entry.ruleId === "github-pat-classic");
    expect(finding).toBeDefined();
    expect(finding?.verified).toBe(false);
  });

  it("ignores environment indirection", () => {
    const summary = scanText('api_key = os.environ["SERVICE_API_KEY"]');
    expect(summary.findings.map((finding) => finding.ruleId)).not.toContain(
      "generic-secret-assignment",
    );
  });

  it("ignores booleans and numeric values", () => {
    expect(scanText("DEBUG=true\nTOKEN_TTL=3600\n").totalFindings).toBe(0);
  });

  it("honours the analysis mode toggles", () => {
    const rulesOnly = scanText(LEAKY_ENV, { enableEntropy: false });
    expect(rulesOnly.findings.every((finding) => finding.detector === "regex")).toBe(true);

    const entropyOnly = scanText(LEAKY_ENV, { enableRules: false });
    expect(entropyOnly.findings.every((finding) => finding.detector === "entropy")).toBe(true);
  });

  it("keeps the entropy profile even when the entropy detector is off", () => {
    const summary = scanText(LEAKY_ENV, { enableEntropy: false });
    expect(summary.entropyProfile.length).toBeGreaterThan(0);
  });

  it("applies the severity floor", () => {
    const summary = scanText(LEAKY_ENV, { minSeverity: "CRITICAL" });
    expect(summary.findings.every((finding) => finding.severity === "CRITICAL")).toBe(true);
  });

  it("sorts findings by descending severity", () => {
    const ranks = scanText(LEAKY_ENV).findings.map((finding) => SEVERITY_RANK[finding.severity]);
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
  });

  it("raising the threshold suppresses entropy findings", () => {
    const text = "SESSION_SECRET=hV3q9ZxT2LmR8NfPwY6KdA1sGjB4cXeU\n";
    expect(scanText(text, { enableRules: false, entropyThreshold: 3.0 }).totalFindings).toBe(1);
    expect(scanText(text, { enableRules: false, entropyThreshold: 7.9 }).totalFindings).toBe(0);
  });

  it("produces stable fingerprints across runs", () => {
    const first = scanText(LEAKY_ENV, { path: ".env" }).findings.map((f) => f.id);
    const second = scanText(LEAKY_ENV, { path: ".env" }).findings.map((f) => f.id);
    expect(first).toEqual(second);
  });
});

describe("deduplicate", () => {
  it("prefers a vendor rule over the generic shape rule", () => {
    const summary = scanText("AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ", { path: ".env" });
    expect(summary.findings.map((finding) => finding.ruleId)).toEqual(["aws-access-key-id"]);
  });

  it("prefers a regex finding over an entropy finding on the same bytes", () => {
    const summary = scanText("AWS_ACCESS_KEY_ID=AKIAZ4KJQ2WBXY7TDNPQ", { path: ".env" });
    expect(summary.findings.every((finding) => finding.detector === "regex")).toBe(true);
  });

  it("keeps distinct secrets on the same line", () => {
    const summary = scanText("a=AKIAZ4KJQ2WBXY7TDNPQ b=glpat-A1b2C3d4E5f6G7h8I9j0");
    const ids = new Set(summary.findings.map((finding) => finding.ruleId));
    expect(ids.has("aws-access-key-id")).toBe(true);
    expect(ids.has("gitlab-pat")).toBe(true);
  });

  it("is a no-op on an empty list", () => {
    expect(deduplicate([])).toEqual([]);
  });
});

describe("redact", () => {
  it("returns an empty string unchanged", () => {
    expect(redact("")).toBe("");
  });

  it("fully masks a single character", () => {
    expect(redact("a")).toBe("*");
  });

  it("keeps only the first character of a short value", () => {
    expect(redact("abcd")).toBe("a***");
  });

  it("keeps a correlatable prefix and suffix on a long value", () => {
    const masked = redact("AKIAZ4KJQ2WBXY7TDNPQ");
    expect(masked.startsWith("AKIA")).toBe(true);
    expect(masked.endsWith("DNPQ")).toBe(true);
    expect(masked).not.toContain("Z4KJQ2WBXY7T");
  });
});

describe("exporters", () => {
  const summary = scanText(LEAKY_ENV, { path: "app/.env" });

  it("emits the GuardEnv JSON schema", () => {
    const payload: unknown = JSON.parse(toJsonReport(summary));
    expect(payload).toMatchObject({ tool: "guardenv", schemaVersion: "1.0" });
  });

  it("redacts secrets in JSON by default", () => {
    expect(toJsonReport(summary)).not.toContain("AKIAZ4KJQ2WBXY7TDNPQ");
  });

  it("can opt into raw values", () => {
    expect(toJsonReport(summary, true)).toContain("AKIAZ4KJQ2WBXY7TDNPQ");
  });

  it("emits SARIF 2.1.0 with resolvable rule indexes", () => {
    const document = JSON.parse(toSarifReport(summary)) as {
      version: string;
      runs: { tool: { driver: { rules: { id: string }[] } }; results: { ruleId: string; ruleIndex: number }[] }[];
    };
    expect(document.version).toBe("2.1.0");
    const run = document.runs[0];
    expect(run).toBeDefined();
    for (const result of run?.results ?? []) {
      expect(run?.tool.driver.rules[result.ruleIndex]?.id).toBe(result.ruleId);
    }
  });

  it("keeps SARIF levels inside the spec vocabulary", () => {
    const document = JSON.parse(toSarifReport(summary)) as {
      runs: { results: { level: string }[] }[];
    };
    for (const result of document.runs[0]?.results ?? []) {
      expect(["error", "warning", "note", "none"]).toContain(result.level);
    }
  });

  it("never leaks a secret through SARIF", () => {
    expect(toSarifReport(summary)).not.toContain("AKIAZ4KJQ2WBXY7TDNPQ");
  });

  it("renders a Markdown table when there are findings", () => {
    expect(toMarkdownReport(summary)).toContain("| Severity | Rule | Location |");
  });

  it("renders a clean Markdown report when there are none", () => {
    expect(toMarkdownReport(scanText("DEBUG=true\n"))).toContain("No credentials detected");
  });
});

// Assembled from parts so no complete provider token sits in the source.
const NEW_PROVIDER_CASES: Readonly<Record<string, string>> = {
  "supabase-access-token": "SUPABASE_ACCESS_TOKEN=" + "sbp_" + "3f9a".repeat(10),
  "cloudflare-api-token": "CLOUDFLARE_API_TOKEN=" + "Zx7Kq2Lm9Pv4Rt8W" + "n3Yb6Hc1Jd5Fg0Ss2Aa9Ee4Q",
  "vercel-token": "VERCEL_TOKEN=" + "Ab3dE5fG7hJ9" + "kL1mN2pQ4rS6",
  "discord-webhook": "https://discord.com/api/webhooks/" + "112233445566778899/" + "Ab1_".repeat(16),
  "discord-bot-token":
    "DISCORD_BOT_TOKEN=" + "M" + "Tk4NzY1NDMyMTA5ODc2NTQz" + ".Gh7Kp2." + "Xy9Wv8Uu7Tt6Ss5Rr4Qq3Pp2Oo1",
  "azure-ad-client-secret": "AZURE_CLIENT_SECRET=" + "abc8Q~" + "Zx7Kq2Lm9Pv4Rt8Wn3Yb6Hc1Jd5Fg0Ss2A",
  "gitlab-runner-token": "token: " + "glrt-" + "Ab3dE5fG7hJ9kL1mN2pQ",
  "paypal-braintree-token":
    "BT=" + "access_token$production$" + "x9k2m4p6r8t0v1w3$" + "0123456789abcdef".repeat(2),
  "twilio-api-key": "TWILIO_KEY=" + "SK" + "0123456789abcdef".repeat(2),
  "twilio-account-sid": "TWILIO_SID=" + "AC" + "fedcba9876543210".repeat(2),
  "pypi-upload-token": "password = " + "pypi-AgEIcHlwaS5vcmc" + "Ab3dE5fG7hJ9kL1mN2pQ".repeat(3),
  "datadog-api-key": "DD_API_KEY=" + "0123456789abcdef" + "fedcba9876543210",
};

describe("provider rules shared with the CLI", () => {
  for (const [ruleId, line] of Object.entries(NEW_PROVIDER_CASES)) {
    it(`detects ${ruleId}`, () => {
      const ids = scanText(line).findings.map((finding) => finding.ruleId);
      expect(ids).toContain(ruleId);
    });
  }

  it("carries exactly the rule ids of guardenv/rules.py", () => {
    const python = readFileSync(new URL("../../../guardenv/rules.py", import.meta.url), "utf8");
    const ids = [...python.matchAll(/_rule\(\s*"([a-z0-9-]+)",/g)].map((match) => match[1]);
    expect(ids.length).toBeGreaterThan(40);
    expect(RULES.map((rule) => rule.id).sort()).toEqual([...ids].sort());
  });
});
