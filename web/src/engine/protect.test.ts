import { describe, expect, it } from "vitest";

import { SAMPLE_DOCUMENTS } from "@/lib/samples";
import { buildBaseline, cliFingerprint } from "./baseline";
import { decodeBase64Text, findEncodedSecrets, mergeEncoded } from "./decode";
import { envExampleFor, gitignoreFor } from "./protect";
import { remediationFor } from "./remediation";
import { riskScore } from "./risk";
import { scanText } from "./scanner";
import { withFindings } from "./summary";

const sample = (id: string): (typeof SAMPLE_DOCUMENTS)[number] => {
  const found = SAMPLE_DOCUMENTS.find((doc) => doc.id === id);
  if (found === undefined) throw new Error(`missing sample ${id}`);
  return found;
};

describe("encoded secrets", () => {
  it("decodes text and rejects binary or short values", () => {
    expect(decodeBase64Text("QUtJQVo0S0pRMldCWFk3VEROUFE=")).toBe("AKIAZ4KJQ2WBXY7TDNPQ");
    expect(decodeBase64Text("ZXUtd2VzdC0x")).toBeNull();
    expect(decodeBase64Text("////////////////////")).toBeNull();
  });

  it("finds the credentials inside a Kubernetes Secret and only those", () => {
    const doc = sample("k8s");
    const encoded = findEncodedSecrets(doc.content, doc.filename);
    expect(encoded.map((f) => f.ruleId).sort()).toEqual(
      ["aws-access-key-id", "postgres-connection-string", "stripe-secret-key"].sort(),
    );
    for (const finding of encoded) {
      expect(finding.tags).toContain("encoded");
      expect(doc.content.split("\n")[finding.line - 1]?.slice(finding.column - 1)).toContain(finding.match);
    }
  });

  it("replaces an entropy finding on the same bytes instead of duplicating it", () => {
    const doc = sample("k8s");
    const plain = scanText(doc.content, { path: doc.filename });
    const merged = mergeEncoded(plain.findings, findEncodedSecrets(doc.content, doc.filename));
    const lines = merged.map((f) => f.line);
    expect(new Set(lines).size).toBe(lines.length);
    expect(merged.some((f) => f.detector === "entropy" && f.line === 11)).toBe(false);
  });
});

describe("risk grade", () => {
  it("is A for a clean document and capped at D with any critical finding", () => {
    expect(riskScore(scanText(sample("clean").content)).grade).toBe("A");
    const leaky = scanText(sample("env").content);
    expect(leaky.countsBySeverity.CRITICAL).toBeGreaterThan(0);
    expect(["D", "F"]).toContain(riskScore(leaky).grade);
  });

  it("recomputes aggregates when findings are filtered", () => {
    const leaky = scanText(sample("env").content);
    const kept = leaky.findings.filter((f) => f.severity !== "CRITICAL");
    const view = withFindings(leaky, kept);
    expect(view.totalFindings).toBe(kept.length);
    expect(view.countsBySeverity.CRITICAL).toBe(0);
  });
});

describe("protection snippets", () => {
  it("empties secret values in a .env.example and keeps harmless defaults", () => {
    const doc = sample("env");
    const example = envExampleFor(doc.content, scanText(doc.content).findings);
    expect(example).not.toBeNull();
    expect(example).toContain("\nAWS_ACCESS_KEY_ID=\n");
    expect(example).toContain("\nPORT=8080\n");
    expect(example).not.toContain("sk_live_");
    expect(envExampleFor(sample("source").content, [])).toBeNull();
    expect(envExampleFor(sample("k8s").content, [])).toBeNull();
  });

  it("ignores the file itself when it is not an env or key file", () => {
    expect(gitignoreFor("config.json")).toContain("\nconfig.json\n");
    expect(gitignoreFor("production.env")).not.toContain("\nproduction.env\n");
  });

  it("gives provider-specific revocation steps", () => {
    const finding = scanText(sample("env").content).findings.find((f) => f.ruleId === "stripe-secret-key");
    expect(finding).toBeDefined();
    if (finding !== undefined) expect(remediationFor(finding).console?.href).toContain("stripe.com");
  });
});

describe("baseline", () => {
  it("fingerprints exactly like guardenv/models.py", async () => {
    const finding = scanText(sample("env").content, { path: "production.env" }).findings.find(
      (f) => f.ruleId === "aws-access-key-id",
    );
    expect(finding).toBeDefined();
    if (finding === undefined) return;
    // sha256("production.env\x1faws-access-key-id\x1f6\x1fAKIAZ4KJQ2WBXY7TDNPQ")[:16], computed in Python.
    expect(await cliFingerprint(finding)).toBe("ccad288c2538b539");
    const doc = JSON.parse(await buildBaseline([finding])) as { findings: { id: string }[] };
    expect(doc.findings[0]?.id).toBe("ccad288c2538b539");
  });
});
